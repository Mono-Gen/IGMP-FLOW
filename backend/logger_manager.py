"""IGMP-FLOW 状態遷移CSVロガー (logger_manager.py)

このモジュールは、IGMP Join / Leave / Query 等のイベントが発生した際に、
現在時刻、イベント名、逆引き機器名、IPアドレス、MACアドレス、対象マルチキャストグループ情報を
ローカルのCSVファイルにスレッドセーフかつ動的に保存（自動ローテーション）します。

AI rulesに基づき、相対パスでのログ保存、厳密な型ヒント、および詳細な日本語Docstringを徹底しています。
"""

import csv
import datetime
import os
import threading
from typing import Optional

from backend.constants import DEFAULT_LOG_DIR
from backend.csv_safety import csv_safe


class LoggerManager:
    """IGMPおよびネットワークイベントの遷移状態をCSVファイルへスレッドセーフに出力・管理するクラス。"""

    def __init__(self, log_dir: str = DEFAULT_LOG_DIR) -> None:
        """ログ管理クラスの初期化。

        Args:
            log_dir (str): ログファイルを保存するディレクトリパス。
        """
        self.log_dir = log_dir
        self._lock = threading.Lock()
        self._last_date_str: Optional[str] = None
        
        # ログ保存用ディレクトリを安全に自動生成（相対パス）
        self._ensure_log_dir_exists()

    def _ensure_log_dir_exists(self) -> None:
        """ログディレクトリが存在しない場合、安全に自動生成します。"""
        if not os.path.exists(self.log_dir):
            try:
                os.makedirs(self.log_dir, mode=0o700, exist_ok=True)  # 実データを含むため本人のみ(POSIX)
            except Exception as e:
                # 起動失敗を防ぐため、エラーは例外として出さずにログディレクトリをカレント（"."）にフォールバック
                self.log_dir = "."

    def _get_current_log_filepath(self) -> str:
        """現在の日付に対応するCSVログファイルのパスを取得します（日付ローテーション対応）。

        Returns:
            str: ログファイルの絶対・または相対パス。
        """
        now = datetime.datetime.now()
        date_str = now.strftime("%Y-%m-%d")
        
        # 日付文字列を更新
        self._last_date_str = date_str
        
        filename = f"igmp_flow_{date_str}.csv"
        return os.path.join(self.log_dir, filename)

    def _write_csv_headers(self, filepath: str) -> None:
        """CSVファイルの新規作成時にヘッダ行を書き込みます。

        Args:
            filepath (str): 対象のCSVファイルパス。
        """
        headers = [
            "Timestamp",      # 時刻 (YYYY-MM-DD HH:MM:SS.fff)
            "Event",          # イベント名 (日本語表記)
            "Device Name",    # mDNS解決機器名 (解決できない場合は空欄/IP)
            "IP Address",     # IPアドレス
            "MAC Address",    # MACアドレス
            "Multicast Group" # 対象マルチキャストIP
        ]
        
        try:
            with open(filepath, mode="w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
        except Exception:
            # ファイル書き込み権限エラー等は上位で処理するか無視
            pass

    def write_log(
        self,
        event: str,
        src_ip: str,
        src_mac: str,
        group_ip: str,
        resolved_name: Optional[str] = None
    ) -> Optional[str]:
        """ネットワーク状態遷移イベントをCSVログファイルに追記保存します。

        Args:
            event (str): 発生したイベント（例: 「ストリーム受信開始（ジョイン）」）。
            src_ip (str): 送信元IPアドレス。
            src_mac (str): 送信元MACアドレス。
            group_ip (str): 宛先マルチキャストIPアドレス。
            resolved_name (Optional[str]): 解決済みの機器名。Noneの場合はIPアドレスが補填されます。

        Returns:
            Optional[str]: 実際に書き込まれたログファイルのパス（テスト検証用）。
        """
        now = datetime.datetime.now()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # ミリ秒までに丸める
        
        # 自動解決機器名がない場合のフォールバック（IPアドレス）
        display_name = resolved_name if resolved_name else src_ip

        # 機器名などはネットワーク上の第三者が決められる値のため、数式として評価されないよう無害化する
        row = [csv_safe(c) for c in (timestamp, event, display_name, src_ip, src_mac, group_ip)]

        with self._lock:
            filepath = self._get_current_log_filepath()
            
            # ファイルが新規作成される場合、先にヘッダを書き込む
            if not os.path.exists(filepath):
                self._write_csv_headers(filepath)

            try:
                with open(filepath, mode="a", newline="", encoding="utf-8-sig") as f:
                    writer = csv.writer(f)
                    writer.writerow(row)
                return filepath
            except Exception:
                return None
