"""IGMP-FLOW mDNS解決マネージャ単体テスト (test_dns_resolver.py)

このモジュールは、DNSResolver クラスが mDNS パケットをパッシブ解析し、
IPアドレスから実名ホスト名を自動解決・キャッシュ・逆引きできるかを自動検証するテストスイートです。

AI rulesに基づき、スレッドセーフティや学習の境界条件の検証を行います。
"""

import unittest

# テスト対象モジュールのインポート
from backend.dns_resolver import DNSResolver
from backend.tests.mock_packet_generator import create_mdns_answer_packet, create_ssdp_packet


class TestDNSResolver(unittest.TestCase):
    """DNSResolverの自動解決およびキャッシュ機能を検証するテストクラス。"""

    def setUp(self) -> None:
        """テストケースごとの初期化処理。"""
        self.resolver = DNSResolver()

    def test_mdns_a_record_learning(self) -> None:
        """mDNSのAレコードからIPアドレスとホスト名を正しく自動学習・逆引きできるかのテスト。"""
        # テスト対象IPと期待するホスト名
        target_ip = "192.168.1.150"
        expected_name = "Yamaha-CL5-Mixer.local"

        # 1. 初期状態では未学習
        self.assertIsNone(self.resolver.resolve(target_ip))
        self.assertEqual(self.resolver.cache_size, 0)

        # 2. Aレコードを含むmDNS応答パケットを流し込む
        packet = create_mdns_answer_packet(src_ip=target_ip, host_name=expected_name)
        self.resolver.update_from_packet(packet)

        # 3. 正しく逆引き解決できることを検証
        resolved_name = self.resolver.resolve(target_ip)
        self.assertEqual(resolved_name, expected_name)
        self.assertEqual(self.resolver.cache_size, 1)

    def test_unrelated_packet_ignored(self) -> None:
        """mDNS以外の関係のないパケット（例: SSDP）が入力された際に、学習が無視されるかのテスト。"""
        self.assertEqual(self.resolver.cache_size, 0)

        # SSDPパケット（無関係）を流し込む
        packet = create_ssdp_packet(src_ip="192.168.1.99")
        self.resolver.update_from_packet(packet)

        # キャッシュが空であることを検証
        self.assertEqual(self.resolver.cache_size, 0)
        self.assertIsNone(self.resolver.resolve("192.168.1.99"))

    def test_cache_clear(self) -> None:
        """キャッシュのクリア機能が正常に機能するかのテスト。"""
        # 1台学習させる
        packet = create_mdns_answer_packet(src_ip="192.168.1.200", host_name="Shure-ULXD4.local")
        self.resolver.update_from_packet(packet)
        self.assertEqual(self.resolver.cache_size, 1)

        # キャッシュクリアを実行
        self.resolver.clear_cache()

        # キャッシュが空になり、解決できなくなっていることを検証
        self.assertEqual(self.resolver.cache_size, 0)
        self.assertIsNone(self.resolver.resolve("192.168.1.200"))


if __name__ == "__main__":
    unittest.main()
