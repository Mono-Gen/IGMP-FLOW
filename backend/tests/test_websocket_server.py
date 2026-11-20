"""IGMP-FLOW WebSocketサーバー単体テスト (test_websocket_server.py)

このモジュールは、WebSocketServerクラスがバックグラウンドスレッドで正常に起動し、
接続されたクライアントを安全に追跡・管理・ブロードキャスト中継できるかを自動検証する非同期テストスイートです。

Python 3.8+ 標準の unittest.IsolatedAsyncioTestCase を使用して、非同期ネットワーク処理を厳密にテストします。
"""

import asyncio
import json
import unittest
from typing import Any, Dict

import websockets

# テスト対象モジュールのインポート
from backend.websocket_server import WebSocketServer

# テスト用のポート
TEST_WS_PORT = 8766


class TestWebSocketServer(unittest.IsolatedAsyncioTestCase):
    """WebSocketServerの非同期接続および配信機能を検証するテストクラス。"""

    def setUp(self) -> None:
        """テストケースごとの初期化処理。テスト用のWebSocketサーバーを起動します。"""
        self.server = WebSocketServer(host="127.0.0.1", port=TEST_WS_PORT)
        self.server.start()

    def tearDown(self) -> None:
        """テストケース終了後のクリーンアップ処理。サーバーを停止してスレッドを解放します。"""
        self.server.stop()

    async def test_connection_and_broadcast(self) -> None:
        """クライアントの接続と、データの一斉ブロードキャスト受信機能のテスト。"""
        # 1. 初期状態ではクライアント接続数 0
        self.assertEqual(self.server.client_count, 0)

        # 2. テスト用クライアントを非同期接続
        uri = f"ws://127.0.0.1:{TEST_WS_PORT}"
        async with websockets.connect(uri) as client:
            # 3. サーバー側でクライアント件数が 1 に増加していることを検証
            # スレッド間の反映ラグを考慮し、短いウェイトを入れてから検証
            await asyncio.sleep(0.1)
            self.assertEqual(self.server.client_count, 1)

            # 4. 同期メソッドを模して、パケット受信イベントを送信
            test_event: Dict[str, Any] = {
                "proto": "IGMP",
                "event": "ストリーム受信開始（ジョイン）",
                "src_ip": "192.168.1.51",
                "group_ip": "239.67.1.1"
            }
            self.server.send_event(test_event)

            # 5. クライアント側でデータを受信し、パースして検証
            try:
                # タイムアウト付きでメッセージ受信待ち
                response_str = await asyncio.wait_for(client.recv(), timeout=1.0)
                response_data = json.loads(response_str)

                # 送信データと完全一致することを検証
                self.assertEqual(response_data["proto"], "IGMP")
                self.assertEqual(response_data["event"], "ストリーム受信開始（ジョイン）")
                self.assertEqual(response_data["src_ip"], "192.168.1.51")
                self.assertEqual(response_data["group_ip"], "239.67.1.1")
            except asyncio.TimeoutError:
                self.fail("WebSocket経由でのイベント受信がタイムアウトしました。")

        # 6. クライアント切断後、接続数が 0 に戻ることを検証
        await asyncio.sleep(0.1)
        self.assertEqual(self.server.client_count, 0)


if __name__ == "__main__":
    unittest.main()
