"""終了要求・ブラウザ切断時の確認ダイアログ・二重起動検出のテスト (test_shutdown.py)

実際のダイアログ表示や実NICは使わず、依存部分を差し替えて動作を検証します。
"""

import asyncio
import json
import os
import socket
import tempfile
import time
import unittest
from typing import Any, List
from unittest import mock

import websockets

from backend.constants import CLOSE_PROMPT_GRACE_SECONDS
from backend.main import IGMPFlowApp
from backend.websocket_server import WebSocketServer


class TestShutdownAndClosePrompt(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.app = IGMPFlowApp(
            log_dir=os.path.join(self._tmp.name, "logs"), capture_dir=os.path.join(self._tmp.name, "cap"),
            enable_pcap=False,
        )
        self.sent: List[Any] = []
        self.app.ws_server.broadcast = lambda d: self.sent.append(d)  # type: ignore[method-assign]
        self.clients = 0
        # client_count はプロパティのため、クラスごと差し替えて任意の接続数を返させる
        patcher = mock.patch.object(WebSocketServer, "client_count", new_callable=mock.PropertyMock, side_effect=lambda: self.clients)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.prompts: List[bool] = []
        self.app._run_close_prompt = lambda: self.prompts.append(True)  # type: ignore[method-assign]

    # --- 終了要求 ---------------------------------------------------------

    def test_request_shutdown_notifies_ui_and_sets_stop_event_once(self) -> None:
        self.app.request_shutdown(delay_s=0)
        self.assertTrue(self.app._stop_event.is_set())
        self.assertEqual(self.sent, [{"type": "shutting_down"}])
        self.app.request_shutdown(delay_s=0)  # 二重要求は無視される
        self.assertEqual(len(self.sent), 1)

    def test_close_prompt_yes_requests_shutdown_no_keeps_running(self) -> None:
        real = IGMPFlowApp._run_close_prompt
        with mock.patch("backend.main.ask_exit_on_close", return_value=False):
            real(self.app)
        self.assertFalse(self.app._stop_event.is_set())  # 「いいえ」なら継続
        with mock.patch("backend.main.ask_exit_on_close", return_value=True), \
             mock.patch.object(IGMPFlowApp, "request_shutdown") as req:
            real(self.app)
            req.assert_called_once()  # 「はい」なら終了を要求

    # --- 切断時ダイアログ -----------------------------------------------------

    def test_no_prompt_if_browser_never_connected(self) -> None:
        self.clients = 0
        for _ in range(3):
            self.app._check_close_prompt()
        self.app._zero_since = time.monotonic() - CLOSE_PROMPT_GRACE_SECONDS - 1
        self.app._check_close_prompt()
        self.assertEqual(self.prompts, [])  # 一度も接続が無ければ確認しない(ヘッドレス運用)

    def test_prompt_once_after_grace_when_all_browsers_closed(self) -> None:
        self.clients = 1
        self.app._check_close_prompt()          # 接続を記録
        self.clients = 0
        self.app._check_close_prompt()          # 切断の起点を記録(まだ出さない)
        self.assertEqual(self.prompts, [])
        self.app._check_close_prompt()          # 猶予内
        self.assertEqual(self.prompts, [])

        self.app._zero_since = time.monotonic() - CLOSE_PROMPT_GRACE_SECONDS - 0.1
        with mock.patch("threading.Thread") as thread_cls:
            self.app._check_close_prompt()
            thread_cls.assert_called_once()      # 猶予超過で専用スレッドを起動
            self.assertTrue(thread_cls.call_args.kwargs["daemon"])
            self.app._check_close_prompt()
            thread_cls.assert_called_once()      # 同じ切断では2回目を出さない

    def test_reconnect_within_grace_cancels_prompt_and_rearms(self) -> None:
        self.clients = 1
        self.app._check_close_prompt()
        self.clients = 0
        self.app._check_close_prompt()
        self.clients = 1                         # リロード等で再接続
        self.app._check_close_prompt()
        self.assertIsNone(self.app._zero_since)
        self.assertFalse(self.app._prompted)

    def test_prompt_disabled_by_option_and_during_shutdown(self) -> None:
        self.app.close_prompt = False
        self.app._had_client, self.app._zero_since = True, time.monotonic() - 100
        with mock.patch("threading.Thread") as thread_cls:
            self.app._check_close_prompt()
            thread_cls.assert_not_called()
        self.app.close_prompt = True
        self.app._shutting_down = True
        with mock.patch("threading.Thread") as thread_cls:
            self.app._check_close_prompt()
            thread_cls.assert_not_called()

    # --- 二重起動 ------------------------------------------------------------

    def test_already_running_detects_listener_on_ws_port(self) -> None:
        with socket.socket() as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            self.app.ws_port = srv.getsockname()[1]
            self.assertTrue(self.app._already_running())
        self.assertFalse(self.app._already_running())  # ソケットを閉じた後は未使用


TEST_WS_PORT = 8769


class TestWsShutdownCommand(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.calls: List[str] = []
        self.server = WebSocketServer(host="127.0.0.1", port=TEST_WS_PORT, on_shutdown=lambda: self.calls.append("shutdown"))
        self.server.start()

    def tearDown(self) -> None:
        self.server.stop()

    async def test_shutdown_command_reaches_callback(self) -> None:
        async with websockets.connect(f"ws://127.0.0.1:{TEST_WS_PORT}") as client:
            await client.send(json.dumps({"action": "shutdown"}))
            await asyncio.sleep(0.3)
        self.assertEqual(self.calls, ["shutdown"])


if __name__ == "__main__":
    unittest.main()
