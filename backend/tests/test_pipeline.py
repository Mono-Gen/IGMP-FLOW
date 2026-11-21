"""PCAP記録 / フロー集計 / クエリア監視 / PCAP→CSVエクスポート / UIフィルタのテスト (test_pipeline.py)

期待値は仕様(合成した入力パケットの内容・時刻)から導出しています。
"""

import asyncio
import csv
import json
import os
import struct
import tempfile
import unittest
from typing import Any, Dict, List

import websockets
from scapy.all import Ether, IP, UDP, Raw, RawPcapReader, rdpcap

from backend.flow_aggregator import FlowAggregator
from backend.pcap_export import export_csv, list_capture_files
from backend.pcap_recorder import PcapRecorder
from backend.querier_monitor import QuerierMonitor
from backend.tests.mock_packet_generator import (
    create_igmp_join_v2,
    create_igmp_query,
    create_mdns_answer_packet,
    create_ptp_packet,
)
from backend.websocket_server import ClientState, WebSocketServer
from backend.constants import PTP_VERSION_2

BASE_TS = 1_700_000_000.0


def audio_packet(src_ip: str, group: str, ts: float, size: int = 400) -> Ether:
    """Dante音声(239.255.x.x宛UDP)の合成パケット。"""
    pkt = Ether(src="00:aa:bb:cc:dd:ee") / IP(src=src_ip, dst=group) / UDP(sport=4321, dport=4321) / Raw(load=b"\x00" * size)
    pkt.time = ts
    return pkt


def stamped(pkt: Any, ts: float) -> Any:
    pkt.time = ts
    return pkt


class TestPcapRecorder(unittest.TestCase):
    """PcapRecorder: 全件記録・データ面の切り詰め・ローテーション。"""

    def test_records_all_packets_and_truncates_data_plane(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            rec = PcapRecorder(capture_dir=d, data_snaplen=128)
            self.assertTrue(rec.start())
            rec.submit(stamped(create_igmp_join_v2("192.168.1.51", "239.67.1.1"), BASE_TS), truncate=False)
            rec.submit(audio_packet("192.168.1.20", "239.255.1.1", BASE_TS + 0.1, size=400), truncate=True)
            rec.stop()

            files = list_capture_files(d)
            self.assertEqual(len(files), 1)
            metas = [m for _, m in RawPcapReader(files[0])]
            self.assertEqual(len(metas), 2)
            # 制御面は全長、データ面は128バイトに切り詰め(元の長さは wirelen に残る)
            self.assertLess(metas[0].caplen, 128)
            self.assertEqual(metas[0].caplen, metas[0].wirelen)
            self.assertEqual(metas[1].caplen, 128)
            self.assertEqual(metas[1].wirelen, 14 + 20 + 8 + 400)
            self.assertEqual(rec.status()["packets"], 2)
            self.assertEqual(rec.status()["dropped"], 0)

    def test_roundtrip_preserves_timestamp_and_content(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            rec = PcapRecorder(capture_dir=d)
            rec.start()
            rec.submit(stamped(create_igmp_join_v2("192.168.1.51", "239.67.1.1"), BASE_TS + 0.5))
            rec.stop()
            pkts = rdpcap(list_capture_files(d)[0])
            self.assertEqual(len(pkts), 1)
            self.assertAlmostEqual(float(pkts[0].time), BASE_TS + 0.5, places=3)
            self.assertEqual(pkts[0][IP].src, "192.168.1.51")

    def test_rotation_by_size_and_by_request(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            rec = PcapRecorder(capture_dir=d, max_file_bytes=300)
            rec.start()
            for i in range(6):
                rec.submit(audio_packet("192.168.1.20", "239.255.1.1", BASE_TS + i, size=100))
            rec.stop()
            self.assertGreater(len(list_capture_files(d)), 1)
            total = sum(len(rdpcap(p)) for p in list_capture_files(d))
            self.assertEqual(total, 6)  # ローテーションしても1件も欠けない

    def test_start_fails_gracefully_when_dir_uncreatable(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            blocker = os.path.join(d, "file")
            open(blocker, "w").close()
            rec = PcapRecorder(capture_dir=os.path.join(blocker, "sub"))  # ファイルの下にはディレクトリを作れない
            self.assertFalse(rec.start())
            self.assertIsNotNone(rec.status()["error"])


class TestFlowAggregator(unittest.TestCase):
    def test_counts_packets_and_bytes_per_flow(self) -> None:
        agg = FlowAggregator()
        for _ in range(4):
            agg.add({"proto": "Dante-Audio", "src_ip": "10.0.0.1", "group_ip": "239.255.1.1", "frame_len": 500})
        agg.add({"proto": "Dante-Audio", "src_ip": "10.0.0.2", "group_ip": "239.255.1.1", "frame_len": 100})
        flows = agg.drain(interval_s=2.0)
        self.assertEqual(flows[0]["src_ip"], "10.0.0.1")  # パケット数の多い順
        self.assertEqual((flows[0]["packets"], flows[0]["bytes"], flows[0]["pps"]), (4, 2000, 2.0))
        self.assertEqual(flows[0]["bps"], 2000 * 8 // 2)
        self.assertEqual(agg.drain(1.0), [])  # drain後は空


class TestQuerierMonitor(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 0.0
        self.mon = QuerierMonitor(timeout_s=260, clock=lambda: self.now)

    def test_unknown_then_none_after_timeout_without_query(self) -> None:
        self.assertEqual(self.mon.status()["state"], "unknown")
        self.now = 261
        self.assertEqual(self.mon.status()["state"], "none")

    def test_ok_then_none_when_querier_disappears(self) -> None:
        self.mon.observe_query("192.168.1.254", "aa:aa:aa:aa:aa:aa", 3)
        self.assertEqual(self.mon.status()["state"], "ok")
        self.now = 125
        self.mon.observe_query("192.168.1.254", "aa:aa:aa:aa:aa:aa", 3)
        self.assertEqual(self.mon.status()["queriers"][0]["interval_s"], 125.0)
        self.now = 125 + 261
        self.assertEqual(self.mon.status()["state"], "none")

    def test_multiple_queriers_elects_lowest_ip(self) -> None:
        self.mon.observe_query("192.168.1.254", "aa:aa:aa:aa:aa:aa", 2)
        self.mon.observe_query("192.168.1.9", "bb:bb:bb:bb:bb:bb", 2)
        st = self.mon.status()
        self.assertEqual(st["state"], "multiple")
        self.assertEqual(st["elected"], "192.168.1.9")  # 数値順で最小(文字列順だと誤る例)

    def test_reset_clears_state(self) -> None:
        self.mon.observe_query("192.168.1.254", "aa:aa:aa:aa:aa:aa", 2)
        self.mon.reset()
        self.assertEqual(self.mon.status()["state"], "unknown")


class TestReportVisibility(unittest.TestCase):
    """Queryは届くのに他端末のReportが届かない(=Snoopingに絞られた通常ポート)ことの診断。"""

    QUERIER = ("192.168.1.254", "aa:aa:aa:aa:aa:aa")
    OWN = ("192.168.1.5", "02:00:00:00:00:05")

    def setUp(self) -> None:
        self.now = 0.0
        self.mon = QuerierMonitor(timeout_s=260, clock=lambda: self.now, report_grace_s=30)
        self.mon.set_own_addresses([self.OWN[0]], self.OWN[1])

    def hidden(self) -> bool:
        return self.mon.status()["reports_hidden"]

    def test_no_hint_before_any_query(self) -> None:
        """Queryが無ければ判断材料が無いので出さない(クエリア不在はクエリア表示が警告する)。"""
        self.now = 1000
        self.assertFalse(self.hidden())

    def test_hint_only_after_grace_period(self) -> None:
        """General Query後、Max Response Time(10秒)を見込んだ猶予の間は出さず、過ぎたら出す。"""
        self.mon.observe_query(*self.QUERIER, 2)
        self.now = 29.9
        self.assertFalse(self.hidden())
        self.now = 30
        self.assertTrue(self.hidden())

    def test_report_from_other_device_clears_hint(self) -> None:
        self.mon.observe_query(*self.QUERIER, 2)
        self.now = 40
        self.mon.observe_report("192.168.1.51", "00:aa:bb:cc:dd:ee")
        self.assertFalse(self.hidden())
        self.assertEqual(self.mon.status()["reports_seen"], 1)

    def test_own_reports_are_not_counted(self) -> None:
        """このPC自身のReport(OSのmDNS参加など)はIPでもMACでも除外する(大文字小文字を問わない)。"""
        self.mon.observe_query(*self.QUERIER, 2)
        self.mon.observe_report(self.OWN[0], "")
        self.mon.observe_report("0.0.0.0", self.OWN[1].upper())
        self.now = 30
        self.assertTrue(self.hidden())

    def test_group_specific_query_does_not_start_grace(self) -> None:
        """Group-Specific Queryは全端末に応答を促さないため、診断の起点にしない。"""
        self.mon.observe_query(*self.QUERIER, 2, general=False)
        self.now = 1000
        self.assertFalse(self.hidden())

    def test_reset_clears_diagnosis(self) -> None:
        self.mon.observe_query(*self.QUERIER, 2)
        self.now = 30
        self.assertTrue(self.hidden())
        self.mon.reset()
        self.assertFalse(self.hidden())


class TestPcapExport(unittest.TestCase):
    """PCAP→CSV: 時刻・機器名の2パス解決・データ面集計・絞り込み。"""

    def _make_pcap(self, d: str) -> str:
        rec = PcapRecorder(capture_dir=d)
        rec.start()
        # 機器名(mDNS応答)は Join より後に現れる。2パス解決で Join 行にも名前が入るはず
        rec.submit(stamped(create_igmp_query("192.168.1.254", "0.0.0.0"), BASE_TS + 0.0))
        rec.submit(stamped(create_igmp_join_v2("192.168.1.51", "239.67.1.1"), BASE_TS + 1.0))
        for i in range(5):  # 同じ1秒内の音声5パケット
            rec.submit(audio_packet("192.168.1.20", "239.255.1.1", BASE_TS + 2.0 + i * 0.1), truncate=True)
        rec.submit(stamped(create_ptp_packet("192.168.1.10", "224.0.1.129", PTP_VERSION_2), BASE_TS + 3.0))
        rec.submit(stamped(create_mdns_answer_packet("192.168.1.51", "Yamaha-QL5.local"), BASE_TS + 4.0))
        rec.stop()
        return list_capture_files(d)[0]

    def _rows(self, path: str) -> List[Dict[str, str]]:
        with open(path, newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))

    def test_export_rows_names_and_time_order(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            pcap = self._make_pcap(d)
            out = os.path.join(d, "out.csv")
            res = export_csv([pcap], out)
            rows = self._rows(out)

            self.assertEqual(res["rows"], len(rows))
            events = [r["Event"] for r in rows]
            self.assertEqual(events[0], "General Query")
            self.assertEqual(events[1], "Join")
            # 音声5パケットは1秒集計1行(Packets=5)
            audio = [r for r in rows if r["Protocol"] == "Dante-Audio"]
            self.assertEqual(len(audio), 1)
            self.assertEqual(audio[0]["Packets"], "5")
            # Join行(mDNS応答より前)にも2パス解決で機器名が入る
            join = rows[1]
            self.assertEqual(join["Device Name"], "Yamaha-QL5.local")
            self.assertEqual(join["Multicast Group"], "239.67.1.1")
            # 時刻は記録時刻の昇順
            stamps = [r["Timestamp"] for r in rows]
            self.assertEqual(stamps, sorted(stamps))

    def test_data_modes(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            pcap = self._make_pcap(d)
            raw = export_csv([pcap], os.path.join(d, "raw.csv"), data_mode="raw")
            none = export_csv([pcap], os.path.join(d, "none.csv"), data_mode="none")
            agg = export_csv([pcap], os.path.join(d, "agg.csv"), data_mode="aggregate")
            self.assertEqual(raw["rows"], agg["rows"] + 4)   # 集計1行 → 全件5行
            self.assertEqual(none["rows"], agg["rows"] - 1)  # 音声行なし
            with self.assertRaises(ValueError):
                export_csv([pcap], os.path.join(d, "x.csv"), data_mode="bogus")

    def test_filters_proto_group_text_and_time_range(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            pcap = self._make_pcap(d)
            only_igmp = self._rows(export_csv([pcap], os.path.join(d, "a.csv"), protos={"IGMP"})["out"])
            self.assertEqual({r["Protocol"] for r in only_igmp}, {"IGMP"})

            by_group = self._rows(export_csv([pcap], os.path.join(d, "b.csv"), group="239.67")["out"])
            self.assertEqual([r["Multicast Group"] for r in by_group], ["239.67.1.1"])

            by_text = self._rows(export_csv([pcap], os.path.join(d, "c.csv"), text="yamaha")["out"])
            self.assertTrue(by_text and all("Yamaha" in r["Device Name"] for r in by_text))

            ranged = self._rows(export_csv([pcap], os.path.join(d, "t.csv"), since=BASE_TS + 3.0, until=BASE_TS + 3.5)["out"])
            self.assertEqual([r["Protocol"] for r in ranged], ["PTP"])

    def test_truncated_pcap_tail_is_reported_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            pcap = self._make_pcap(d)
            with open(pcap, "ab") as f:
                f.write(struct.pack("<IIII", 1, 0, 500, 500) + b"\x00" * 10)  # 書込途中で切れた末尾レコード
            res = export_csv([pcap], os.path.join(d, "o.csv"))
            self.assertGreater(res["rows"], 0)  # 取得済みの分は出力される


TEST_WS_PORT = 8767


class TestUiFilter(unittest.IsolatedAsyncioTestCase):
    """サーバー側フィルタ: プロトコル絞込・データ面の集計配信・IGMPのレート上限除外。"""

    def setUp(self) -> None:
        self.server = WebSocketServer(host="127.0.0.1", port=TEST_WS_PORT)
        self.server.start()

    def tearDown(self) -> None:
        self.server.stop()

    async def _recv_all(self, client: Any, wait: float = 0.4) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            while True:
                out.append(json.loads(await asyncio.wait_for(client.recv(), timeout=wait)))
        except asyncio.TimeoutError:
            return out

    async def test_proto_text_filter_and_data_plane_gating(self) -> None:
        async with websockets.connect(f"ws://127.0.0.1:{TEST_WS_PORT}") as client:
            await asyncio.sleep(0.1)
            await client.send(json.dumps({"action": "set_filter", "protos": ["PTP"], "text": "192.168.1.10", "raw_data": False}))
            await asyncio.sleep(0.1)

            self.server.send_event({"proto": "PTP", "event": "同期シグナル", "src_ip": "192.168.1.10", "group_ip": "224.0.1.129"})
            self.server.send_event({"proto": "PTP", "event": "同期シグナル", "src_ip": "192.168.1.99", "group_ip": "224.0.1.129"})  # テキスト不一致
            self.server.send_event({"proto": "IGMP", "event": "x", "src_ip": "192.168.1.10", "group_ip": "239.1.1.1"})            # プロトコル不一致
            self.server.send_event({"proto": "PTP", "plane": "data", "src_ip": "192.168.1.10", "group_ip": "224.0.1.129"})        # raw_data=False
            msgs = await self._recv_all(client)
            self.assertEqual(len(msgs), 1)
            self.assertEqual(msgs[0]["src_ip"], "192.168.1.10")

            # raw_data を有効にするとデータ面も個別に届く
            await client.send(json.dumps({"action": "set_filter", "protos": ["PTP"], "text": "", "raw_data": True}))
            await asyncio.sleep(0.1)
            self.assertTrue(self.server.wants_raw_data)
            self.server.send_event({"proto": "PTP", "plane": "data", "src_ip": "192.168.1.10", "group_ip": "224.0.1.129"})
            self.assertEqual(len(await self._recv_all(client)), 1)

    async def test_flow_stats_are_filtered_per_client(self) -> None:
        async with websockets.connect(f"ws://127.0.0.1:{TEST_WS_PORT}") as client:
            await asyncio.sleep(0.1)
            await client.send(json.dumps({"action": "set_filter", "protos": ["Dante-Audio"], "text": "10.0.0.1"}))
            await asyncio.sleep(0.1)
            self.server.send_flow_stats([
                {"proto": "Dante-Audio", "src_ip": "10.0.0.1", "group_ip": "239.255.1.1", "packets": 10},
                {"proto": "Dante-Audio", "src_ip": "10.0.0.2", "group_ip": "239.255.1.1", "packets": 10},
                {"proto": "AES67-Audio", "src_ip": "10.0.0.1", "group_ip": "239.1.1.1", "packets": 10},
            ], 1.0)
            msgs = await self._recv_all(client)
            self.assertEqual(len(msgs), 1)
            self.assertEqual(msgs[0]["type"], "flow_stats")
            self.assertEqual([f["src_ip"] for f in msgs[0]["flows"]], ["10.0.0.1"])
            self.assertEqual(msgs[0]["flows"][0]["proto"], "Dante-Audio")

    async def test_rate_limit_drops_excess_but_never_igmp(self) -> None:
        state = ClientState()
        allowed = sum(state.allow_rate("Dante-ConMon") for _ in range(1000))
        self.assertLess(allowed, 1000)          # 上限(既定300/秒)で頭打ち
        self.assertGreater(state.suppressed, 0)  # 破棄件数は計数される
        self.assertTrue(all(state.allow_rate("IGMP") for _ in range(1000)))  # IGMPは常に通す


if __name__ == "__main__":
    unittest.main()
