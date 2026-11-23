"""IGMPv3 / IGMP Query バージョン判別 / PTP詳細 / 未分類マルチキャストの解析テスト (test_igmp_v3_ptp.py)

期待値は実装の出力ではなく、RFC 3376 (IGMPv3) / RFC 2236 (IGMPv2) / IEEE 1588 のフォーマット仕様から導出しています。
"""

import socket
import struct
import unittest
from typing import Any, Dict, List, Tuple

from scapy.all import Ether, IP, UDP, Raw

from backend.packet_analyzer import (
    EVENT_JOIN,
    EVENT_LEAVE,
    PacketAnalyzer,
    _decode_igmpv3_time_code,
)


def build_v3_report(records: List[Tuple[int, str, List[str]]]) -> bytes:
    """IGMPv3 Membership Report の生バイト列を組み立てる(チェックサムは検証対象外のため0)。"""
    body = b""
    for rtype, group, sources in records:
        body += struct.pack("!BBH", rtype, 0, len(sources)) + socket.inet_aton(group)
        body += b"".join(socket.inet_aton(s) for s in sources)
    header = struct.pack("!BBHHH", 0x22, 0, 0, 0, len(records))
    return header + body


def build_v3_query(max_resp_code: int, qrv: int, qqic: int, group: str = "0.0.0.0") -> bytes:
    """IGMPv3 Membership Query (送信元なし, 12バイト) の生バイト列を組み立てる。"""
    return struct.pack("!BBH", 0x11, max_resp_code, 0) + socket.inet_aton(group) + struct.pack("!BBH", qrv, qqic, 0)


def wrap(igmp: bytes, src_ip: str = "192.168.1.60", dst_ip: str = "224.0.0.22") -> Ether:
    """IGMPバイト列を Ethernet/IP(proto=2, TTL=1) で包む。"""
    return Ether(src="00:aa:bb:cc:dd:01") / IP(src=src_ip, dst=dst_ip, ttl=1, proto=2) / Raw(load=igmp)


class TestIgmpV3(unittest.TestCase):
    """IGMPv3 Report / Query の展開・判別テスト。"""

    def setUp(self) -> None:
        self.analyzer = PacketAnalyzer(load_system_info=False)

    def test_v3_report_expands_each_group_record(self) -> None:
        """Group Record 1件につき1イベントとなり、レコード種別に応じてJoin/Leaveへ分類される。"""
        report = build_v3_report([
            (4, "239.1.1.1", []),                      # CHANGE_TO_EXCLUDE: Join(ASM相当)
            (3, "239.2.2.2", []),                      # CHANGE_TO_INCLUDE{}: Leave
            (5, "239.3.3.3", ["10.0.0.1", "10.0.0.2"]),  # ALLOW_NEW_SOURCES: ソース指定Join
        ])
        events = self.analyzer.decode_packet_events(wrap(report))

        self.assertEqual([e["group_ip"] for e in events], ["239.1.1.1", "239.2.2.2", "239.3.3.3"])
        self.assertEqual([e["event"] for e in events], [EVENT_JOIN, EVENT_LEAVE, EVENT_JOIN])
        self.assertEqual(events[2]["sources"], ["10.0.0.1", "10.0.0.2"])
        self.assertTrue(all(e["version"] == 3 and e["src_ip"] == "192.168.1.60" for e in events))

    def test_v3_report_survives_ethernet_padding_after_wire_roundtrip(self) -> None:
        """ワイヤ上のEthernetパディングをレコードと誤認せず、数値どおりの件数だけ展開する。"""
        raw_frame = bytes(wrap(build_v3_report([(1, "239.9.9.9", ["10.1.1.1"])]))) + b"\x00" * 20
        events = self.analyzer.decode_packet_events(Ether(raw_frame))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["group_ip"], "239.9.9.9")
        self.assertEqual(events[0]["sources"], ["10.1.1.1"])

    def test_v3_report_truncated_gives_note_event(self) -> None:
        """Group Record が壊れている(切り詰め)場合も、見落とさず注記イベントを1件返す。"""
        events = self.analyzer.decode_packet_events(wrap(build_v3_report([(4, "239.1.1.1", [])])[:10]))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["version"], 3)

    def test_v3_query_fields(self) -> None:
        """v3 Query: 12バイト以上でv3判定、MaxResp(1/10秒)・QRV・QQICを復号する。"""
        events = self.analyzer.decode_packet_events(
            wrap(build_v3_query(max_resp_code=100, qrv=0x02, qqic=125), dst_ip="224.0.0.1")
        )
        ev = events[0]
        self.assertEqual(ev["version"], 3)
        self.assertTrue(ev["is_querier"])
        self.assertAlmostEqual(ev["max_resp_time_s"], 10.0)
        self.assertEqual(ev["robustness"], 2)
        self.assertEqual(ev["qqic_s"], 125)

    def test_query_version_1_vs_2_by_max_resp_time(self) -> None:
        """8バイトQueryは Max Resp Time=0 ならv1、非0ならv2 (RFC 2236)。"""
        v1 = struct.pack("!BBH", 0x11, 0, 0) + socket.inet_aton("0.0.0.0")
        v2 = struct.pack("!BBH", 0x11, 100, 0) + socket.inet_aton("0.0.0.0")
        self.assertEqual(self.analyzer.decode_packet_events(wrap(v1, dst_ip="224.0.0.1"))[0]["version"], 1)
        self.assertEqual(self.analyzer.decode_packet_events(wrap(v2, dst_ip="224.0.0.1"))[0]["version"], 2)

    def test_v1_report_is_join(self) -> None:
        """IGMPv1 Report (0x12) もJoinとして扱う。"""
        v1_report = struct.pack("!BBH", 0x12, 0, 0) + socket.inet_aton("239.5.5.5")
        ev = self.analyzer.decode_packet_events(wrap(v1_report, dst_ip="239.5.5.5"))[0]
        self.assertEqual((ev["version"], ev["event"], ev["group_ip"]), (1, EVENT_JOIN, "239.5.5.5"))

    def test_time_code_decoding_matches_rfc3376(self) -> None:
        """RFC 3376 4.1.1: 128未満はそのまま、以上は (mant|0x10) << (exp+3)。"""
        self.assertEqual(_decode_igmpv3_time_code(100), 100)
        self.assertEqual(_decode_igmpv3_time_code(0x8A), (0xA | 0x10) << 3)   # exp=0, mant=0xA -> 208
        self.assertEqual(_decode_igmpv3_time_code(0xFF), (0xF | 0x10) << (7 + 3))  # 最大値 31744


class TestNpcapDetection(unittest.TestCase):
    """Npcapの既定インストール(System32\\Npcap配下のみ)でも「インストール済み」と判定すること。"""

    def test_detects_default_and_compat_mode_layouts(self) -> None:
        import os
        from unittest import mock
        from backend import packet_analyzer as pa

        sysroot = os.environ.get("SystemRoot", "C:\\Windows")
        default_layout = os.path.join(sysroot, "System32", "Npcap", "wpcap.dll")
        compat_layout = os.path.join(sysroot, "System32", "wpcap.dll")
        with mock.patch.object(pa.sys, "platform", "win32"):
            with mock.patch.object(pa.os.path, "exists", side_effect=lambda p: p == default_layout):
                self.assertTrue(pa.check_npcap_installed())
            with mock.patch.object(pa.os.path, "exists", side_effect=lambda p: p == compat_layout):
                self.assertTrue(pa.check_npcap_installed())
            with mock.patch.object(pa.os.path, "exists", return_value=False):
                self.assertFalse(pa.check_npcap_installed())


class TestPtpAndMulticast(unittest.TestCase):
    """PTPメッセージ種別/クロックID、未分類マルチキャスト、プレーン区分のテスト。"""

    def setUp(self) -> None:
        self.analyzer = PacketAnalyzer(load_system_info=False)

    def _udp(self, dst: str, dport: int, payload: bytes, sport: int = 40000) -> Ether:
        return Ether(src="00:11:22:33:44:55") / IP(src="192.168.1.10", dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=payload)

    def test_ptp_v2_announce_extracts_clock_and_grandmaster(self) -> None:
        """PTPv2 Announce: messageType=0xB、clockIdentity(offset20)とgrandmasterIdentity(offset53)を抽出する。"""
        payload = bytearray(64)
        payload[0], payload[1] = 0x0B, 0x02
        payload[20:28] = bytes.fromhex("0011223344556677")
        payload[53:61] = bytes.fromhex("aabbccddeeff0011")
        ev = self.analyzer.decode_packet_events(self._udp("224.0.1.129", 320, bytes(payload)))[0]
        self.assertEqual(ev["proto"], "PTP")
        self.assertEqual(ev["ptp_msg_type"], "Announce")
        self.assertEqual(ev["clock_id"], "00-11-22-33-44-55-66-77")
        self.assertEqual(ev["grandmaster_id"], "aa-bb-cc-dd-ee-ff-00-11")

    def test_ptp_v1_message_type(self) -> None:
        """PTPv1: ヘッダ20バイト目が messageType (1=Sync)。"""
        payload = bytearray(60)
        payload[0:2] = b"\x00\x01"
        payload[20] = 1
        ev = self.analyzer.decode_packet_events(self._udp("224.0.1.129", 319, bytes(payload)))[0]
        self.assertEqual((ev["version"], ev["ptp_msg_type"]), (1, "Sync"))

    def test_ptp_requires_ptp_port(self) -> None:
        """PTPマルチキャストIP宛でもポートが319/320でなければPTPと判定しない。"""
        payload = b"\x00\x02" + b"\x00" * 40
        ev = self.analyzer.decode_packet_events(self._udp("224.0.1.129", 9999, payload))[0]
        self.assertNotEqual(ev["proto"], "PTP")

    def test_unclassified_multicast_is_reported_as_data_plane(self) -> None:
        """既知プロトコル外の 239.x 宛UDPは「未分類マルチキャスト」(データ面)として検出する。"""
        ev = self.analyzer.decode_packet_events(self._udp("239.10.10.10", 9999, b"x" * 10))[0]
        self.assertEqual((ev["proto"], ev["plane"], ev["group_ip"]), ("Multicast-Other", "data", "239.10.10.10"))

    def test_link_local_non_udp_multicast_is_control_plane(self) -> None:
        """224.0.0.x 宛のUDP以外(例: OSPF proto 89)は制御面の未分類マルチキャストとして検出する。"""
        pkt = Ether(src="00:11:22:33:44:55") / IP(src="192.168.1.1", dst="224.0.0.5", proto=89) / Raw(load=b"\x00" * 20)
        ev = self.analyzer.decode_packet_events(pkt)[0]
        self.assertEqual((ev["proto"], ev["plane"]), ("Multicast-Other", "control"))

    def test_dante_audio_is_data_plane_and_has_common_fields(self) -> None:
        """Dante音声はデータ面で、全イベントに ts / frame_len が付く。"""
        pkt = self._udp("239.255.1.1", 4321, b"\x00" * 100)
        pkt.time = 1_700_000_000.25
        ev = self.analyzer.decode_packet_events(pkt)[0]
        self.assertEqual((ev["proto"], ev["plane"]), ("Dante-Audio", "data"))
        self.assertAlmostEqual(ev["ts"], 1_700_000_000.25, places=2)
        self.assertGreaterEqual(ev["frame_len"], 100)

    def test_sacn_is_not_reported_as_dante(self) -> None:
        """照明の sACN(UDP 5568)は Dante と同じ 239.255.x.x 宛でも sACN として検出する(Issue #1)。"""
        ev = self.analyzer.decode_packet_events(self._udp("239.255.0.37", 5568, b"x" * 126))[0]
        self.assertEqual((ev["proto"], ev["event_code"], ev["plane"]), ("sACN", "sacn", "data"))
        self.assertEqual((ev["universe"], ev["tag"]), (37, "sACN universe 37"))

    def test_other_ports_in_239_255_are_not_assumed_to_be_dante(self) -> None:
        """239.255.x.x でも Dante 音声のポート(4321)以外は Dante と決めつけず未分類にする。"""
        ev = self.analyzer.decode_packet_events(self._udp("239.255.1.1", 7000, b"x" * 10))[0]
        self.assertEqual(ev["proto"], "Multicast-Other")

    def test_sacn_universe_from_address(self) -> None:
        """宛先IPからのユニバース番号算出。期待値は E1.31 の式 239.255.(N>>8).(N&0xFF) から求めた値。"""
        from backend.packet_analyzer import sacn_universe
        cases = {
            "239.255.0.1": 1, "239.255.0.255": 255, "239.255.1.0": 256, "239.255.2.138": 650,
            "239.255.249.255": 63999,  # 上限
            "239.255.0.0": None,  # ユニバース0は無効
            "239.255.250.0": None,  # 64000 は範囲外
            "239.254.0.1": None, "224.0.0.251": None, "bad": None,
        }
        for ip, expected in cases.items():
            self.assertEqual(sacn_universe(ip), expected, ip)

    def test_discovery_protocols_use_their_common_names(self) -> None:
        """探索系は総称ではなく、一般的なプロトコル名(mDNS/SSDP/SAP/LLMNR)をprotoに持つ。"""
        cases = [
            ("224.0.0.251", 5353, "mDNS"), ("239.255.255.250", 1900, "SSDP"),
            ("239.255.255.255", 9875, "SAP"), ("224.0.0.252", 5355, "LLMNR"),
        ]
        for dst, port, expected in cases:
            ev = self.analyzer.decode_packet_events(self._udp(dst, port, b"x", sport=port))[0]
            self.assertEqual((ev["proto"], ev["event_code"], ev["plane"]), (expected, "discovery", "control"), dst)

    def test_event_codes_are_language_independent(self) -> None:
        """画面の処理分岐に使う event_code が、英語ラベルとは別に付与される。"""
        ptp = self.analyzer.decode_packet_events(self._udp("224.0.1.129", 319, b"\x00\x02" + b"\x00" * 40))[0]
        self.assertEqual((ptp["event"], ptp["event_code"]), ("PTP message", "ptp_message"))
        audio = self.analyzer.decode_packet_events(self._udp("239.255.1.1", 4321, b"\x00" * 10))[0]
        self.assertEqual(audio["event_code"], "dante_audio")

    def test_unicast_udp_is_ignored(self) -> None:
        """マルチキャストでも既知ポートでもないUDPは対象外。"""
        self.assertEqual(self.analyzer.decode_packet_events(self._udp("192.168.1.99", 12345, b"x")), [])


if __name__ == "__main__":
    unittest.main()
