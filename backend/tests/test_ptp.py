"""PTP詳細解析 / PTP監視(間隔・異常検出) / v1・v2・種別フィルタのテスト (test_ptp.py)

期待値は IEEE 1588-2008 のヘッダ/Announceのフィールド配置と、テストが与えた入力時刻から導出しています。
"""

import csv
import os
import tempfile
import unittest
from typing import Any, Dict, List

from scapy.all import Ether, IP, UDP, Raw

from backend.constants import PTP_VERSION_1, PTP_VERSION_2
from backend.packet_analyzer import PacketAnalyzer
from backend.pcap_export import export_csv, list_capture_files
from backend.pcap_recorder import PcapRecorder
from backend.ptp_monitor import PtpMonitor
from backend.tests.mock_packet_generator import create_igmp_join_v2, create_ptp_packet
from backend.websocket_server import ClientState

BASE_TS = 1_700_000_000.0


def ptp_v2_payload(msg_type: int, domain: int = 0, log_interval: int = 0) -> bytearray:
    """PTPv2ヘッダ(34バイト)+Announce本体まで確保したペイロードを作る。"""
    p = bytearray(64)
    p[0], p[1] = msg_type, 0x02
    p[4] = domain
    p[33] = log_interval & 0xFF  # 符号付き1バイト
    return p


def udp_ptp(payload: bytes, dport: int = 320) -> Ether:
    return Ether(src="00:11:22:33:44:55") / IP(src="192.168.1.10", dst="224.0.1.129") / UDP(sport=dport, dport=dport) / Raw(load=payload)


class TestPtpDetails(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = PacketAnalyzer(load_system_info=False)

    def test_v2_announce_all_fields(self) -> None:
        """Announce: domain / logMessageInterval / priority1 / class / accuracy / priority2 / stepsRemoved / GM。"""
        p = ptp_v2_payload(0x0B, domain=4, log_interval=1)  # 2秒間隔
        p[20:28] = bytes.fromhex("0011223344556677")
        p[47], p[48], p[49], p[52] = 128, 248, 0x21, 130
        p[53:61] = bytes.fromhex("aabbccddeeff0011")
        p[61:63] = (3).to_bytes(2, "big")
        ev = self.analyzer.decode_packet_events(udp_ptp(bytes(p)))[0]
        self.assertEqual(ev["filter_key"], "PTPv2")
        self.assertEqual((ev["domain"], ev["log_interval"]), ("4", 1))
        self.assertEqual((ev["priority1"], ev["clock_class"], ev["clock_accuracy"], ev["priority2"]), (128, 248, 0x21, 130))
        self.assertEqual(ev["steps_removed"], 3)
        self.assertEqual(ev["grandmaster_id"], "aa-bb-cc-dd-ee-ff-00-11")

    def test_v2_sync_negative_log_interval_and_delay_req_has_none(self) -> None:
        """Sync の logMessageInterval=-3 は 0.125秒(符号付き解釈)。Delay_Req では間隔を採用しない。"""
        sync = self.analyzer.decode_packet_events(udp_ptp(bytes(ptp_v2_payload(0x0, log_interval=-3)), 319))[0]
        self.assertEqual(sync["log_interval"], -3)
        delay_req = self.analyzer.decode_packet_events(udp_ptp(bytes(ptp_v2_payload(0x1, log_interval=0x7F)), 319))[0]
        self.assertNotIn("log_interval", delay_req)

    def test_v1_subdomain_and_source_uuid(self) -> None:
        """PTPv1: subdomain(offset4-19, NUL終端ASCII)とsourceUuid(offset22-27)を抽出。"""
        p = bytearray(60)
        p[0:2] = b"\x00\x01"
        p[4:9] = b"_DFLT"
        p[20] = 1  # Sync
        p[22:28] = bytes.fromhex("001dc1aabbcc")
        p[54:60] = bytes.fromhex("001dc1000001")  # grandmasterClockUuid
        ev = self.analyzer.decode_packet_events(udp_ptp(bytes(p), 319))[0]
        self.assertEqual((ev["filter_key"], ev["version"], ev["domain"]), ("PTPv1", 1, "_DFLT"))
        self.assertEqual(ev["clock_id"], "00-1d-c1-aa-bb-cc")
        self.assertEqual(ev["grandmaster_id"], "00-1d-c1-00-00-01")

    def test_v1_out_of_range_sync_interval_is_not_adopted(self) -> None:
        """実機未検証のoffsetから読んだ値が妥当範囲外(例 100)なら、宣言間隔として採用しない。"""
        p = bytearray(90)
        p[0:2] = b"\x00\x01"
        p[20] = 1
        p[83] = 100
        ev = self.analyzer.decode_packet_events(udp_ptp(bytes(p), 319))[0]
        self.assertNotIn("log_interval", ev)


class TestPtpMonitor(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1000.0
        self.mon = PtpMonitor(clock=lambda: self.now)

    @staticmethod
    def ev(msg: str, ts: float, clock: str = "c1", gm: str = "", log_interval: Any = None, **kw: Any) -> Dict[str, Any]:
        e: Dict[str, Any] = {"proto": "PTP", "version": 2, "domain": "0", "clock_id": clock, "src_ip": "10.0.0.1",
                             "ptp_msg_type": msg, "ts": ts}
        if gm:
            e["grandmaster_id"] = gm
        if log_interval is not None:
            e["log_interval"] = log_interval
        e.update(kw)
        return e

    def _rows(self) -> List[Dict[str, Any]]:
        return self.mon.status()["rows"]

    def test_measured_interval_equals_packet_spacing(self) -> None:
        """実測間隔はパケット時刻の差(中央値)。宣言値(2^-3=0.125s)と一致すれば異常なし。"""
        for i in range(10):
            self.mon.observe(self.ev("Sync", ts=100 + i * 0.125, log_interval=-3))
        row = self._rows()[0]
        self.assertAlmostEqual(row["measured_s"], 0.125, places=3)
        self.assertAlmostEqual(row["declared_s"], 0.125)
        self.assertEqual(self.mon.status()["alerts"], [])

    def test_interval_mismatch_alert_needs_enough_samples(self) -> None:
        """宣言0.125sなのに実測1.0s。サンプル不足の間は警告せず、5間隔以上で interval_mismatch。"""
        for i in range(4):  # 差分は3個 -> まだ判定しない
            self.mon.observe(self.ev("Sync", ts=100 + i, log_interval=-3))
        self.assertEqual(self.mon.status()["alerts"], [])
        for i in range(4, 8):
            self.mon.observe(self.ev("Sync", ts=100 + i, log_interval=-3))
        kinds = [a["kind"] for a in self.mon.status()["alerts"]]
        self.assertEqual(kinds, ["interval_mismatch"])

    def test_announce_lost_after_three_intervals(self) -> None:
        """宣言間隔1sのAnnounceが3秒を超えて途絶 -> announce_lost。3秒以内なら警告なし。"""
        self.mon.observe(self.ev("Announce", ts=1000.0, log_interval=0, gm="gm1"))
        self.now = 1002.5
        self.assertEqual(self.mon.status()["alerts"], [])
        self.now = 1003.5
        self.assertEqual([a["kind"] for a in self.mon.status()["alerts"]], ["announce_lost"])

    def test_multiple_grandmasters_in_same_domain(self) -> None:
        """同一ドメインで異なるGM IDを広告するクロックが2つ -> multiple_gm。同じGMなら警告なし。"""
        self.mon.observe(self.ev("Announce", 1000.0, clock="c1", gm="gmA", log_interval=0))
        self.mon.observe(self.ev("Announce", 1000.0, clock="c2", gm="gmA", log_interval=0))
        self.assertEqual(self.mon.status()["alerts"], [])
        self.mon.observe(self.ev("Announce", 1001.0, clock="c3", gm="gmB", log_interval=0))
        self.assertIn("multiple_gm", [a["kind"] for a in self.mon.status()["alerts"]])

    def test_master_info_and_reset(self) -> None:
        self.mon.observe(self.ev("Announce", 1000.0, gm="gmA", log_interval=0, priority1=128, clock_class=248))
        m = self.mon.status()["masters"][0]
        self.assertEqual((m["gm_id"], m["priority1"], m["clock_class"]), ("gmA", 128, 248))
        self.mon.reset()
        self.assertEqual(self.mon.status()["rows"], [])


class TestPtpFilters(unittest.TestCase):
    def test_client_filter_splits_v1_v2_and_message_types(self) -> None:
        st = ClientState()
        v1 = {"proto": "PTP", "filter_key": "PTPv1", "ptp_msg_type": "Sync"}
        v2_sync = {"proto": "PTP", "filter_key": "PTPv2", "ptp_msg_type": "Sync"}
        v2_ann = {"proto": "PTP", "filter_key": "PTPv2", "ptp_msg_type": "Announce"}
        igmp = {"proto": "IGMP"}

        st.set_filter({"protos": ["PTPv2", "IGMP"], "ptp_types": ["Announce"]})
        self.assertFalse(st.matches(v1))        # v1は除外
        self.assertFalse(st.matches(v2_sync))   # v2でもSyncは除外
        self.assertTrue(st.matches(v2_ann))
        self.assertTrue(st.matches(igmp))       # PTP種別フィルタはPTP以外に影響しない

        st.set_filter({"protos": None, "ptp_types": None})
        self.assertTrue(all(st.matches(e) for e in (v1, v2_sync, v2_ann, igmp)))

    def test_export_filters_by_ptp_version_and_type(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            rec = PcapRecorder(capture_dir=d)
            rec.start()
            for i, (ver, ip) in enumerate([(PTP_VERSION_1, "192.168.1.10"), (PTP_VERSION_2, "192.168.1.11")]):
                pkt = create_ptp_packet(ip, "224.0.1.129", ver)
                pkt.time = BASE_TS + i
                rec.submit(pkt)
            join = create_igmp_join_v2("192.168.1.51", "239.67.1.1")
            join.time = BASE_TS + 5
            rec.submit(join)
            rec.stop()
            pcap = list_capture_files(d)[0]

            def rows(**kw: Any) -> List[Dict[str, str]]:
                out = os.path.join(d, "o.csv")
                export_csv([pcap], out, **kw)
                with open(out, newline="", encoding="utf-8-sig") as f:
                    return list(csv.DictReader(f))

            self.assertEqual([r["IP Address"] for r in rows(protos={"PTPv2"})], ["192.168.1.11"])
            self.assertEqual([r["IP Address"] for r in rows(protos={"PTPv1"})], ["192.168.1.10"])
            self.assertEqual(len(rows(protos={"PTP"})), 2)  # 従来指定の "PTP" は両方に一致
            # mockのPTPはSync(種別0)なので、Announceのみ指定するとPTP行は消え、IGMPは影響を受けない
            only_announce = rows(ptp_types={"Announce"})
            self.assertEqual([r["Protocol"] for r in only_announce], ["IGMP"])
            self.assertIn("domain=", rows(protos={"PTPv2"})[0]["Detail"])


if __name__ == "__main__":
    unittest.main()
