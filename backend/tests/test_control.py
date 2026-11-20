"""キャプチャ停止/開始・リセット・WebSocketコマンドのテスト (test_control.py)

実NIC/Npcapを使わないよう、スニファの起動/停止だけを差し替えて状態遷移を検証します。
"""

import asyncio
import json
import os
import tempfile
import unittest
from typing import Any, Dict, List

import websockets

from backend.main import IGMPFlowApp
from backend.websocket_server import WebSocketServer


class FakeSniffApp(IGMPFlowApp):
    """スニファの実起動を行わず、状態フラグだけを切り替えるテスト用サブクラス。"""

    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.start_calls = 0
        self.stop_calls = 0
        self.broadcasts: List[Dict[str, Any]] = []
        self.ws_server.broadcast = lambda data: self.broadcasts.append(data)  # type: ignore[method-assign]

    def _start_sniffing_unlocked(self) -> None:
        self._sniff_running = True
        self.start_calls += 1

    def _stop_sniffing_unlocked(self) -> None:
        self._sniff_running = False
        self.stop_calls += 1


class TestCaptureControl(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.app = FakeSniffApp(log_dir=os.path.join(self._tmp.name, "logs"), capture_dir=os.path.join(self._tmp.name, "cap"))
        self.app.active_interface = "dummy-nic"
        self.app._sniff_running = True

    def test_stop_then_start_toggles_state_and_notifies(self) -> None:
        self.assertFalse(self.app.set_capture_running(False))
        self.assertEqual(self.app.stop_calls, 1)
        self.assertEqual(self.app.broadcasts[-1], {"type": "capture_state", "running": False})

        self.assertTrue(self.app.set_capture_running(True))
        self.assertEqual(self.app.start_calls, 1)
        self.assertEqual(self.app.broadcasts[-1], {"type": "capture_state", "running": True})

    def test_redundant_requests_do_not_restart_or_restop(self) -> None:
        self.app.set_capture_running(True)   # 既に動作中
        self.assertEqual(self.app.start_calls, 0)
        self.app.set_capture_running(False)
        self.app.set_capture_running(False)  # 既に停止中
        self.assertEqual(self.app.stop_calls, 1)

    def test_resume_resets_stale_monitors_and_rotates_pcap(self) -> None:
        self.app.querier_monitor.observe_query("192.168.1.254", "aa:aa:aa:aa:aa:aa", 3)
        self.app.ptp_monitor.observe({"proto": "PTP", "version": 2, "domain": "0", "clock_id": "c", "ptp_msg_type": "Sync"})
        rotated: List[bool] = []
        assert self.app.recorder is not None
        self.app.recorder.rotate = lambda: rotated.append(True)  # type: ignore[method-assign]

        self.app.set_capture_running(False)
        self.app.set_capture_running(True)

        self.assertEqual(self.app.querier_monitor.status()["state"], "unknown")  # 停止中の経過で「不在」と誤警告しない
        self.assertEqual(self.app.ptp_monitor.status()["rows"], [])
        self.assertEqual(rotated, [True])

    def test_start_without_nic_raises(self) -> None:
        self.app.active_interface = None
        self.app._sniff_running = False
        with self.assertRaises(ValueError):
            self.app.set_capture_running(True)

    def test_reset_state_clears_monitors_keeps_names_and_rotates(self) -> None:
        self.app.querier_monitor.observe_query("192.168.1.254", "aa:aa:aa:aa:aa:aa", 3)
        self.app.resolver._cache["10.0.0.1"] = "host.local"
        rotated: List[bool] = []
        assert self.app.recorder is not None
        self.app.recorder.rotate = lambda: rotated.append(True)  # type: ignore[method-assign]

        self.app.reset_state()

        self.assertEqual(self.app.querier_monitor.status()["state"], "unknown")
        self.assertEqual(self.app.resolver.resolve("10.0.0.1"), "host.local")  # 機器名は残す
        self.assertEqual(rotated, [True])
        types = {m["type"] for m in self.app.broadcasts}
        self.assertTrue({"capture_state", "querier_status", "ptp_status"} <= types)

    def test_status_messages_include_capture_state(self) -> None:
        self.assertIn("capture_state", [m["type"] for m in self.app.get_status_messages()])


TEST_WS_PORT = 8768


class TestWsCommands(unittest.IsolatedAsyncioTestCase):
    """WebSocket経由の set_capture / reset_state コマンドがコールバックへ届くこと。"""

    def setUp(self) -> None:
        self.calls: List[Any] = []
        self.server = WebSocketServer(
            host="127.0.0.1", port=TEST_WS_PORT,
            on_set_capture=lambda running: (self.calls.append(("capture", running)), running)[1],
            on_reset=lambda: self.calls.append(("reset",)),
        )
        self.server.start()

    def tearDown(self) -> None:
        self.server.stop()

    async def test_commands_reach_callbacks(self) -> None:
        async with websockets.connect(f"ws://127.0.0.1:{TEST_WS_PORT}") as client:
            await client.send(json.dumps({"action": "set_capture", "running": False}))
            await client.send(json.dumps({"action": "reset_state"}))
            await client.send(json.dumps({"action": "set_capture", "running": True}))
            await asyncio.sleep(0.3)
        self.assertEqual(self.calls, [("capture", False), ("reset",), ("capture", True)])

    async def test_capture_error_is_reported_to_client(self) -> None:
        def boom(running: bool) -> bool:
            raise ValueError("NIC未選択")
        self.server.on_set_capture = boom
        async with websockets.connect(f"ws://127.0.0.1:{TEST_WS_PORT}") as client:
            await client.send(json.dumps({"action": "set_capture", "running": True}))
            msg = json.loads(await asyncio.wait_for(client.recv(), timeout=1.0))
        self.assertEqual(msg["type"], "capture_error")
        self.assertIn("NIC未選択", msg["error"])


if __name__ == "__main__":
    unittest.main()
