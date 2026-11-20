"""IGMP-FLOW パケット解析エンジン単体テスト (test_packet_analyzer.py)

このモジュールは、PacketAnalyzer クラスが各種ネットワークパケット（IGMP, PTPv1/v2, mDNSなど）を
設計仕様書通りに正確にデコード・タグ判定できるかを自動検証するテストスイートです。

AI rulesに基づき、厳密な型ヒント、明確なテスト定義、および検証（Check）を徹底しています。
"""

import unittest
from typing import Any, Dict, Optional

# テスト対象モジュールのインポート
from backend.packet_analyzer import PacketAnalyzer
from backend.tests.mock_packet_generator import (
    create_igmp_query,
    create_igmp_join_v2,
    create_igmp_leave_v2,
    create_ptp_packet,
    create_mdns_packet,
    create_dante_conmon_packet,
    create_ssdp_packet
)
from backend.constants import PTP_VERSION_1, PTP_VERSION_2


class TestPacketAnalyzer(unittest.TestCase):
    """PacketAnalyzerの全デコードロジックを検証するテストクラス。"""

    def setUp(self) -> None:
        """テストケースごとの初期化処理。"""
        self.analyzer = PacketAnalyzer()

    def assert_valid_packet_data(self, data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """デコード結果が有効であることをアサートし、辞書として返します。"""
        self.assertIsNotNone(data, "デコード結果が None です。解析対象外の可能性があります。")
        assert data is not None  # 静的解析用の型保証
        return data

    def test_igmp_query_decoding(self) -> None:
        """IGMP Query (生存確認) パケットのデコードテスト。"""
        # クエリアIP: 192.168.1.254, グループIP: 0.0.0.0 (General Query)
        packet = create_igmp_query(src_ip="192.168.1.254", group_ip="0.0.0.0")
        res = self.assert_valid_packet_data(self.analyzer.decode_packet(packet))

        self.assertEqual(res["proto"], "IGMP")
        self.assertEqual(res["event"], "General Query")
        self.assertEqual(res["event_code"], "igmp_query")
        self.assertEqual(res["src_ip"], "192.168.1.254")
        self.assertEqual(res["group_ip"], "0.0.0.0")
        self.assertTrue(res.get("is_querier", False))

    def test_igmp_join_v2_decoding(self) -> None:
        """IGMPv2 Join (Membership Report) パケットのデコードテスト。"""
        # ホストIP: 192.168.1.51, 参加グループ: 239.67.1.1
        packet = create_igmp_join_v2(src_ip="192.168.1.51", group_ip="239.67.1.1")
        res = self.assert_valid_packet_data(self.analyzer.decode_packet(packet))

        self.assertEqual(res["proto"], "IGMP")
        self.assertEqual(res["event"], "Join")
        self.assertEqual(res["event_code"], "igmp_join")
        self.assertEqual(res["src_ip"], "192.168.1.51")
        self.assertEqual(res["group_ip"], "239.67.1.1")

    def test_igmp_leave_v2_decoding(self) -> None:
        """IGMPv2 Leave (離脱) パケットのデコードテスト。"""
        # ホストIP: 192.168.1.51, 離脱グループ: 239.67.1.1
        packet = create_igmp_leave_v2(src_ip="192.168.1.51", group_ip="239.67.1.1")
        res = self.assert_valid_packet_data(self.analyzer.decode_packet(packet))

        self.assertEqual(res["proto"], "IGMP")
        self.assertEqual(res["event"], "Leave")
        self.assertEqual(res["event_code"], "igmp_leave")
        self.assertEqual(res["src_ip"], "192.168.1.51")
        self.assertEqual(res["group_ip"], "239.67.1.1")

    def test_ptp_v1_decoding(self) -> None:
        """Dante標準の PTPv1 クロック同期信号のデコードテスト。"""
        # 送信元: 192.168.1.10 (マスタークロック), 宛先: 224.0.1.129, バージョン: PTPv1
        packet = create_ptp_packet(src_ip="192.168.1.10", dst_ip="224.0.1.129", version=PTP_VERSION_1)
        res = self.assert_valid_packet_data(self.analyzer.decode_packet(packet))

        self.assertEqual(res["proto"], "PTP")
        self.assertEqual(res["version"], PTP_VERSION_1)
        self.assertEqual(res["tag"], "Clock sync (PTPv1 / Dante)")
        self.assertEqual(res["src_ip"], "192.168.1.10")
        self.assertEqual(res["group_ip"], "224.0.1.129")

    def test_ptp_v2_decoding(self) -> None:
        """AES67の PTPv2 クロック同期信号のデコードテスト。"""
        # 送信元: 192.168.1.11, 宛先: 224.0.1.129, バージョン: PTPv2
        packet = create_ptp_packet(src_ip="192.168.1.11", dst_ip="224.0.1.129", version=PTP_VERSION_2)
        res = self.assert_valid_packet_data(self.analyzer.decode_packet(packet))

        self.assertEqual(res["proto"], "PTP")
        self.assertEqual(res["version"], PTP_VERSION_2)
        self.assertEqual(res["tag"], "Clock sync (PTPv2 / AES67)")
        self.assertEqual(res["src_ip"], "192.168.1.11")
        self.assertEqual(res["group_ip"], "224.0.1.129")

    def test_mdns_decoding(self) -> None:
        """mDNS (機器名解決) パケットの自動タグ判定テスト。"""
        packet = create_mdns_packet(src_ip="192.168.1.52")
        res = self.assert_valid_packet_data(self.analyzer.decode_packet(packet))

        self.assertEqual(res["proto"], "mDNS")  # 一般的なプロトコル名をそのまま表示する
        self.assertEqual(res["tag"], "Name resolution (mDNS)")
        self.assertEqual(res["src_ip"], "192.168.1.52")
        self.assertEqual(res["group_ip"], "224.0.0.251")

    def test_dante_conmon_decoding(self) -> None:
        """Dante制御 (ConMon) パケットの自動タグ判定テスト。"""
        packet = create_dante_conmon_packet(src_ip="192.168.1.53")
        res = self.assert_valid_packet_data(self.analyzer.decode_packet(packet))

        self.assertEqual(res["proto"], "Dante-ConMon")
        self.assertEqual(res["tag"], "Dante control (ConMon)")
        self.assertEqual(res["src_ip"], "192.168.1.53")

    def test_ssdp_decoding(self) -> None:
        """SSDP (探索シグナル) パケットの自動タグ判定テスト。"""
        packet = create_ssdp_packet(src_ip="192.168.1.99")
        res = self.assert_valid_packet_data(self.analyzer.decode_packet(packet))

        self.assertEqual(res["proto"], "SSDP")
        self.assertEqual(res["tag"], "Discovery (SSDP/UPnP)")
        self.assertEqual(res["src_ip"], "192.168.1.99")
        self.assertEqual(res["group_ip"], "239.255.255.250")


if __name__ == "__main__":
    unittest.main()
