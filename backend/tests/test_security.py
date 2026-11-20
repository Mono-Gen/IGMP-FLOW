"""セキュリティ対策のテスト (test_security.py)

脅威: (1)他サイトのページからのWebSocket操作(CSWSH) (2)CSV数式インジェクション
(3)偽装パケットによるメモリ枯渇/ログ注入 (4)ローカルHTTPサーバーへのDNSリバインディング/一覧表示/トラバーサル
"""

import asyncio
import csv
import http.client
import json
import os
import sys
import tempfile
import unittest
from typing import Any
from unittest import mock

import websockets

from backend.csv_safety import csv_safe
from backend.constants import (
    AGGREGATOR_MAX_FLOWS, ARP_CACHE_MAX_ENTRIES, HOSTNAME_MAX_LEN, PTP_MAX_MASTERS, QUERIER_MAX_TRACKED,
    RESOLVER_MAX_ENTRIES, UI_HTTP_PORT, WS_MAX_MESSAGE_BYTES,
)
from backend.dns_resolver import DNSResolver
from backend.flow_aggregator import FlowAggregator
from backend.logger_manager import LoggerManager
from backend.packet_analyzer import PacketAnalyzer
from backend.paths import (
    DATA_DIR_ENV, app_base_dir, data_dir, frontend_dir, is_cloud_synced_path, user_data_root,
)
from backend.pcap_export import export_csv, list_capture_files
from backend.pcap_recorder import PcapRecorder
from backend.ptp_monitor import PtpMonitor
from backend.querier_monitor import QuerierMonitor
from backend.static_server import start_ui_server
from backend.tests.mock_packet_generator import create_igmp_join_v2, create_mdns_answer_packet
from backend.websocket_server import ClientState, WebSocketServer, default_allowed_origins


class TestCsvInjection(unittest.TestCase):
    def test_formula_prefixes_are_neutralized(self) -> None:
        for bad in ("=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\t=1", "\r=1"):
            self.assertTrue(csv_safe(bad).startswith("'"), bad)
        for ok in ("Yamaha-QL5.local", "10.0.0.1", "aa:bb:cc:dd:ee:ff", "", "224.0.0.251"):
            self.assertEqual(csv_safe(ok), ok)
        self.assertEqual(csv_safe(5), 5)  # 数値はそのまま

    def test_export_and_live_log_neutralize_malicious_device_name(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            rec = PcapRecorder(capture_dir=d)
            rec.start()
            pkts = [create_mdns_answer_packet("192.168.1.51", "=HYPERLINK(\"http://evil.example\",\"x\").local"),
                    create_igmp_join_v2("192.168.1.51", "239.67.1.1")]
            for i, p in enumerate(pkts):
                p.time = 1_700_000_000.0 + i
                rec.submit(p)
            rec.stop()
            out = os.path.join(d, "o.csv")
            export_csv(list_capture_files(d), out)
            with open(out, newline="", encoding="utf-8-sig") as f:
                names = [r["Device Name"] for r in csv.DictReader(f)]
            self.assertTrue(names and all(not n.startswith("=") for n in names), names)

            lm = LoggerManager(log_dir=os.path.join(d, "logs"))
            path = lm.write_log("Join", "10.0.0.1", "aa:bb:cc:dd:ee:ff", "239.1.1.1", resolved_name="=1+1")
            with open(path, newline="", encoding="utf-8-sig") as f:
                self.assertEqual(list(csv.DictReader(f))[0]["Device Name"], "'=1+1")


class TestBoundedState(unittest.TestCase):
    """偽装パケットで増やせる状態に上限があること。"""

    def test_resolver_sanitizes_and_caps(self) -> None:
        r = DNSResolver()
        with r._lock:
            r._remember("10.0.0.1", "evil\x1b[2J\nname.local")
            r._remember("10.0.0.2", "a" * 1000)
            r._remember("10.0.0.3", "\x00\x01")  # 制御文字のみ -> 学習しない
        self.assertEqual(r.resolve("10.0.0.1"), "evil[2Jname.local")  # ESC/改行は除去
        self.assertEqual(len(r.resolve("10.0.0.2")), HOSTNAME_MAX_LEN)
        self.assertIsNone(r.resolve("10.0.0.3"))
        with r._lock:
            for i in range(RESOLVER_MAX_ENTRIES + 50):
                r._remember(f"172.16.{i // 250}.{i % 250}", "h.local")
            self.assertLessEqual(r.cache_size if False else len(r._cache), RESOLVER_MAX_ENTRIES)
            r._remember("10.0.0.1", "renamed.local")  # 既知IPの更新は上限後も可能
        self.assertEqual(r.resolve("10.0.0.1"), "renamed.local")

    def test_arp_cache_is_capped(self) -> None:
        a = PacketAnalyzer(load_system_info=False)
        from scapy.all import ARP, Ether
        for i in range(ARP_CACHE_MAX_ENTRIES + 20):
            a.decode_packet_events(Ether() / ARP(op=2, psrc=f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}", hwsrc="aa:bb:cc:00:00:01"))
        self.assertLessEqual(len(a.arp_cache), ARP_CACHE_MAX_ENTRIES)

    def test_aggregator_flow_cap(self) -> None:
        agg = FlowAggregator()
        for i in range(AGGREGATOR_MAX_FLOWS + 100):
            agg.add({"proto": "Dante-Audio", "src_ip": f"10.1.{i // 250}.{i % 250}", "group_ip": "239.255.1.1", "frame_len": 100})
        self.assertEqual(len(agg.drain(1.0)), AGGREGATOR_MAX_FLOWS)

    def test_querier_and_ptp_master_caps(self) -> None:
        q = QuerierMonitor()
        for i in range(QUERIER_MAX_TRACKED + 30):
            q.observe_query(f"10.2.0.{i}", "aa:aa:aa:aa:aa:aa", 3)
        self.assertLessEqual(len(q.status()["queriers"]), QUERIER_MAX_TRACKED)

        p = PtpMonitor()
        for i in range(PTP_MAX_MASTERS + 30):
            p.observe({"proto": "PTP", "version": 2, "domain": "0", "clock_id": f"c{i}", "ptp_msg_type": "Announce",
                       "grandmaster_id": f"g{i}", "ts": 1.0})
        self.assertLessEqual(len(p.status()["masters"]), PTP_MAX_MASTERS)


class TestFilterInputValidation(unittest.TestCase):
    def test_malformed_filter_values_are_ignored(self) -> None:
        st = ClientState()
        st.set_filter({"protos": "IGMP", "ptp_types": {"a": 1}, "text": "X" * 10_000})
        self.assertIsNone(st.protos)       # リスト以外は無視
        self.assertIsNone(st.ptp_types)
        self.assertEqual(len(st.text), 200)  # 長さ制限
        st.set_filter({"protos": ["IGMP", 5, None, ["x"]]})
        self.assertEqual(st.protos, {"IGMP"})  # 文字列以外の要素は除去(unhashableでも落ちない)


TEST_WS_PORT = 8771


class TestWebSocketOrigin(unittest.IsolatedAsyncioTestCase):
    """他サイトのページ(悪意あるWebサイト)からの接続を拒否し、自UIとOriginなしは許可する。"""

    def setUp(self) -> None:
        self.calls: list = []
        self.server = WebSocketServer(host="127.0.0.1", port=TEST_WS_PORT, on_shutdown=lambda: self.calls.append("shutdown"))
        self.server.start()

    def tearDown(self) -> None:
        self.server.stop()

    async def test_foreign_origin_is_rejected(self) -> None:
        with self.assertRaises(websockets.exceptions.WebSocketException):
            async with websockets.connect(f"ws://127.0.0.1:{TEST_WS_PORT}", origin="http://evil.example") as ws:
                await ws.send(json.dumps({"action": "shutdown"}))
        # 別サイトが同じホスト名でポート違いを装う場合も拒否する
        with self.assertRaises(websockets.exceptions.WebSocketException):
            async with websockets.connect(f"ws://127.0.0.1:{TEST_WS_PORT}", origin="http://localhost:9999"):
                pass
        self.assertEqual(self.calls, [])

    async def test_own_ui_origin_and_no_origin_are_allowed(self) -> None:
        for origin in (f"http://localhost:{UI_HTTP_PORT}", f"http://127.0.0.1:{UI_HTTP_PORT}", None):
            async with websockets.connect(f"ws://127.0.0.1:{TEST_WS_PORT}", origin=origin) as ws:
                await ws.send(json.dumps({"action": "noop"}))
        self.assertIn(None, default_allowed_origins())

    async def test_oversized_message_closes_connection(self) -> None:
        async with websockets.connect(f"ws://127.0.0.1:{TEST_WS_PORT}") as ws:
            await ws.send("x" * (WS_MAX_MESSAGE_BYTES + 10))
            with self.assertRaises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=2)
                await asyncio.wait_for(ws.recv(), timeout=2)

    async def test_non_object_json_is_ignored(self) -> None:
        async with websockets.connect(f"ws://127.0.0.1:{TEST_WS_PORT}") as ws:
            await ws.send(json.dumps([1, 2, 3]))
            await ws.send(json.dumps("shutdown"))
            await ws.send(json.dumps({"action": "shutdown"}))  # 正規のコマンドは引き続き処理される
            await asyncio.sleep(0.3)
        self.assertEqual(self.calls, ["shutdown"])


class TestStaticServer(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        os.makedirs(os.path.join(self.dir.name, "sub"))
        with open(os.path.join(self.dir.name, "index.html"), "w") as f:
            f.write("<html>ok</html>")
        with open(os.path.join(self.dir.name, "sub", "x.txt"), "w") as f:
            f.write("x")
        # 配信ディレクトリの外側に置いた秘密(トラバーサルで読めてはならない)
        with open(os.path.join(os.path.dirname(self.dir.name), "outside_secret.txt"), "w") as f:
            f.write("secret")
        self.addCleanup(lambda: os.remove(os.path.join(os.path.dirname(self.dir.name), "outside_secret.txt")))
        self.server = start_ui_server(self.dir.name, port=0)
        assert self.server is not None
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def _get(self, path: str, host: Any = None) -> http.client.HTTPResponse:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.putrequest("GET", path, skip_host=True)
        conn.putheader("Host", host or f"localhost:{self.port}")
        conn.endheaders()
        return conn.getresponse()

    def test_serves_files_with_security_headers(self) -> None:
        r = self._get("/index.html")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("Cache-Control"), "no-store")
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertIn("frame-ancestors 'none'", r.getheader("Content-Security-Policy"))
        self.assertIn("object-src 'none'", r.getheader("Content-Security-Policy"))

    def test_dns_rebinding_host_is_rejected(self) -> None:
        self.assertEqual(self._get("/index.html", host="evil.example").status, 403)
        self.assertEqual(self._get("/index.html", host=f"evil.example:{self.port}").status, 403)
        self.assertEqual(self._get("/index.html", host=f"127.0.0.1:{self.port}").status, 200)

    def test_no_directory_listing_and_no_traversal(self) -> None:
        self.assertEqual(self._get("/sub/").status, 404)
        for p in ("/../outside_secret.txt", "/..%2foutside_secret.txt", "/%2e%2e/outside_secret.txt", "/sub/../../outside_secret.txt"):
            self.assertNotEqual(self._get(p).status, 200, p)

    def test_port_in_use_returns_none(self) -> None:
        self.assertIsNone(start_ui_server(self.dir.name, port=self.port))


class TestDataDirectory(unittest.TestCase):
    """実データの保存先が、リポジトリ/クラウド同期フォルダの外にあること。"""

    def test_default_is_outside_the_app_folder_and_not_synced(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(DATA_DIR_ENV, None)
            root = user_data_root()
        self.assertFalse(os.path.abspath(root).startswith(app_base_dir() + os.sep))  # gitに誤って入らない
        if sys.platform == "win32":
            self.assertTrue(os.path.normcase(root).startswith(os.path.normcase(os.environ["LOCALAPPDATA"])))

    def test_env_override(self) -> None:
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {DATA_DIR_ENV: d}):
            self.assertEqual(user_data_root(), os.path.abspath(d))
            self.assertEqual(data_dir("captures"), os.path.join(os.path.abspath(d), "captures"))

    def test_cloud_synced_detection(self) -> None:
        sep = os.sep
        for p in (f"C{sep}Users{sep}x{sep}OneDrive{sep}Desktop{sep}app", f"C{sep}Users{sep}x{sep}Dropbox{sep}app",
                  f"C{sep}Users{sep}x{sep}OneDrive - Contoso{sep}app", f"C{sep}Users{sep}x{sep}Google Drive{sep}app"):
            self.assertTrue(is_cloud_synced_path(p), p)
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(is_cloud_synced_path(d))
            with mock.patch.dict(os.environ, {"OneDrive": os.path.dirname(d)}):  # 環境変数のOneDriveルート配下
                self.assertTrue(is_cloud_synced_path(d))

    def test_recorder_status_reports_sync_warning(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(PcapRecorder(capture_dir=d).status()["sync_warning"])
            self.assertTrue(PcapRecorder(capture_dir=os.path.join(d, "OneDrive", "captures")).status()["sync_warning"])


class TestIconArtwork(unittest.TestCase):
    """生成したアイコンが妥当なICO(複数サイズのPNG)であること。"""

    def test_icons_are_valid_multi_size_ico(self) -> None:
        import struct
        for rel in (os.path.join("assets", "icon.ico"), os.path.join("frontend", "favicon.ico")):
            with open(os.path.join(app_base_dir(), rel), "rb") as f:
                data = f.read()
            reserved, kind, count = struct.unpack("<HHH", data[:6])
            self.assertEqual((reserved, kind), (0, 1), rel)
            sizes = set()
            for i in range(count):
                w, _h, _c, _r, _pl, _bc, size, off = struct.unpack("<BBBBHHII", data[6 + 16 * i:22 + 16 * i])
                sizes.add(w or 256)
                self.assertEqual(data[off:off + 8], b"\x89PNG\r\n\x1a\n")
            self.assertTrue({16, 32, 48, 256} <= sizes, (rel, sizes))


class TestPaths(unittest.TestCase):
    def test_paths_do_not_depend_on_cwd(self) -> None:
        old = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                self.assertTrue(os.path.isfile(os.path.join(frontend_dir(), "index.html")))
                self.assertTrue(os.path.isabs(app_base_dir()))
            finally:
                os.chdir(old)


if __name__ == "__main__":
    unittest.main()
