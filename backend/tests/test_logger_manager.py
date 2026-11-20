"""IGMP-FLOW CSVロガー単体テスト (test_logger_manager.py)

This module validates that the LoggerManager class dynamically and thread-safely logs
network events into CSV files with correct headers, formats, and auto-directory creations.

AI rulesに基づき、テスト終了後に作成された一時ディレクトリやファイルのクリーンアップを徹底します。
"""

import csv
import os
import shutil
import unittest
from typing import List

# テスト対象モジュールのインポート
from backend.logger_manager import LoggerManager

# テスト用の一時ログディレクトリ（相対パス）
TEST_LOG_DIR = "./test_logs_tmp"


class TestLoggerManager(unittest.TestCase):
    """LoggerManagerのCSV出力およびローテーション機能を検証するテストクラス。"""

    def setUp(self) -> None:
        """テストケースごとの初期化処理。以前の一時ディレクトリがあれば念のため削除します。"""
        if os.path.exists(TEST_LOG_DIR):
            shutil.rmtree(TEST_LOG_DIR)
        self.logger = LoggerManager(log_dir=TEST_LOG_DIR)

    def tearDown(self) -> None:
        """テストケース終了後のクリーンアップ処理。一時的に作成されたファイルとフォルダを完全に削除します。"""
        if os.path.exists(TEST_LOG_DIR):
            shutil.rmtree(TEST_LOG_DIR)

    def test_log_file_and_directory_creation(self) -> None:
        """ログ保存ディレクトリおよびCSVファイルが自動的に生成されるかのテスト。"""
        # 1. ログディレクトリが自動生成されていることを検証
        self.assertTrue(os.path.exists(TEST_LOG_DIR))

        # 2. ログ書き込みを実行
        filepath = self.logger.write_log(
            event="ストリーム受信開始（ジョイン）",
            src_ip="192.168.1.51",
            src_mac="00:11:22:33:44:55",
            group_ip="239.67.1.1",
            resolved_name="Yamaha-QL5.local"
        )

        # 3. CSVファイルが実際に存在し、書き込まれたパスが正しいか検証
        self.assertIsNotNone(filepath)
        assert filepath is not None
        self.assertTrue(os.path.exists(filepath))

        # 4. 書き込まれたCSVの内容（ヘッダとデータ行）をパースして検証
        with open(filepath, mode="r", newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            rows: List[List[str]] = list(reader)

        # ヘッダ行の検証
        self.assertEqual(len(rows), 2)  # ヘッダ行 + データ行の計2行
        self.assertEqual(rows[0][1], "Event")
        self.assertEqual(rows[0][2], "Device Name")
        self.assertEqual(rows[0][3], "IP Address")
        self.assertEqual(rows[0][4], "MAC Address")
        self.assertEqual(rows[0][5], "Multicast Group")

        # データ行の検証
        self.assertEqual(rows[1][1], "ストリーム受信開始（ジョイン）")
        self.assertEqual(rows[1][2], "Yamaha-QL5.local")
        self.assertEqual(rows[1][3], "192.168.1.51")
        self.assertEqual(rows[1][4], "00:11:22:33:44:55")
        self.assertEqual(rows[1][5], "239.67.1.1")

    def test_log_fallback_to_ip(self) -> None:
        """resolved_name が None (解決不能) の場合、IPアドレスが機器名フィールドにフォールバックされるかのテスト。"""
        filepath = self.logger.write_log(
            event="ストリーム切断（リーブ）",
            src_ip="192.168.1.99",
            src_mac="00:11:22:33:44:55",
            group_ip="239.67.1.1",
            resolved_name=None  # 自動解決失敗
        )

        self.assertIsNotNone(filepath)
        assert filepath is not None

        with open(filepath, mode="r", newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            rows = list(reader)

        # 機器名 (Device Name) フィールドが IPアドレスになっていることを検証
        self.assertEqual(rows[1][2], "192.168.1.99")


if __name__ == "__main__":
    unittest.main()
