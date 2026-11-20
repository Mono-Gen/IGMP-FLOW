"""IGMP-FLOW PCAP記録モジュール (pcap_recorder.py)

キャプチャした全パケットを、専用スレッド+キューで非ブロッキングに libpcap 形式(Ethernet)で保存します。
パケット受信コールバックをディスクI/Oで止めないため、キューが溢れた場合は取りこぼしとして
件数を計数し(UIへ警告可能)、キャプチャ自体は継続します。

自動削除は行いません(トラブル調査の証跡を勝手に消さないため)。保存先の合計サイズが閾値を超えた場合は
`status()` の `disk_warning` で通知します。
"""

import logging
import os
import queue
import struct
import threading
import time
from typing import Any, Dict, Optional, Tuple

from backend.constants import (
    DEFAULT_CAPTURE_DIR,
    PCAP_DATA_PLANE_SNAPLEN,
    PCAP_DISK_WARN_BYTES,
    PCAP_FLUSH_INTERVAL_SECONDS,
    PCAP_LINKTYPE_ETHERNET,
    PCAP_MAGIC,
    PCAP_MAX_FILE_BYTES,
    PCAP_QUEUE_MAX,
)

from backend.paths import is_cloud_synced_path

logger = logging.getLogger("IGMP-FLOW.PcapRecorder")

# pcapグローバルヘッダ: magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, linktype
_GLOBAL_HEADER = struct.Struct("<IHHiIII")
# レコードヘッダ: ts_sec, ts_usec, incl_len, orig_len
_RECORD_HEADER = struct.Struct("<IIII")
# 記録時の最大パケット長(これを超えるフレームは通常存在しない)
_PCAP_SNAPLEN = 65535
# IPパケットのみでEthernetヘッダが無い場合に前置するダミーEthernetヘッダ(宛先/送信元ゼロ, EtherType=IPv4)
_DUMMY_ETHER = b"\x00" * 12 + b"\x08\x00"

_STOP = object()


class PcapRecorder:
    """パケットをキュー経由で別スレッドからPCAPファイルへ書き込む記録クラス。"""

    def __init__(
        self,
        capture_dir: str = DEFAULT_CAPTURE_DIR,
        max_file_bytes: int = PCAP_MAX_FILE_BYTES,
        data_snaplen: int = PCAP_DATA_PLANE_SNAPLEN,
        queue_max: int = PCAP_QUEUE_MAX,
    ) -> None:
        """記録クラスの初期化(スレッドは start() で起動)。

        Args:
            capture_dir (str): PCAPの保存先ディレクトリ(相対パス可)。
            max_file_bytes (int): 1ファイルの上限サイズ。超過で次のファイルへローテーション。
            data_snaplen (int): データ面パケットを切り詰めて記録するバイト数。
            queue_max (int): 書込キューの最大件数。
        """
        self.capture_dir = capture_dir
        self.max_file_bytes = max_file_bytes
        self.data_snaplen = data_snaplen
        self._queue: "queue.Queue[Any]" = queue.Queue(maxsize=queue_max)
        self._thread: Optional[threading.Thread] = None
        self._file: Optional[Any] = None
        self._file_path: Optional[str] = None
        self._file_bytes = 0
        self._file_seq = 0
        self._stats_lock = threading.Lock()
        self._packets = 0
        self._dropped = 0
        self._last_error: Optional[str] = None
        self._last_flush = time.monotonic()
        self._rotate_requested = False

    # ------------------------------------------------------------------
    # 公開API
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """保存先を作成し、書込スレッドを起動します。

        Returns:
            bool: 起動できた場合True。保存先を作成できない場合はFalse(キャプチャ自体は継続可能)。
        """
        try:
            # 実データを含むため、POSIXでは本人のみアクセス可(0o700)にする。Windowsでは親(LOCALAPPDATA)のACLを継承する
            os.makedirs(self.capture_dir, mode=0o700, exist_ok=True)
        except OSError as e:
            self._set_error(f"Cannot create the PCAP directory: {e}")
            return False
        self._thread = threading.Thread(target=self._run, name="pcap-writer", daemon=True)
        self._thread.start()
        return True

    def submit(self, packet: Any, truncate: bool = False) -> None:
        """パケット1件を書込キューへ追加します(ブロックしない)。

        Args:
            packet (Any): Scapyパケット。
            truncate (bool): Trueの場合、データ面として先頭 `data_snaplen` バイトに切り詰めて記録する。
        """
        if self._thread is None:
            return
        try:
            self._queue.put_nowait((packet, truncate))
        except queue.Full:
            with self._stats_lock:
                self._dropped += 1

    def rotate(self) -> None:
        """次のパケット書込から新しいPCAPファイルを使うよう要求します(NIC切替時など)。"""
        self._rotate_requested = True

    def stop(self) -> None:
        """キューを書き切ってスレッドを停止し、ファイルを閉じます。"""
        if self._thread is None:
            return
        self._queue.put(_STOP)
        self._thread.join(timeout=5.0)
        self._thread = None

    def status(self) -> Dict[str, Any]:
        """記録状況(UI表示用)を返します。"""
        with self._stats_lock:
            packets, dropped, error = self._packets, self._dropped, self._last_error
        total = self._dir_total_bytes()
        return {
            "type": "capture_status",
            "enabled": self._thread is not None,
            "file": os.path.basename(self._file_path) if self._file_path else None,
            "packets": packets,
            "dropped": dropped,
            "error": error,
            "dir_bytes": total,
            "disk_warning": total >= PCAP_DISK_WARN_BYTES,
            # 保存先がクラウド同期フォルダの中だと、実データ(IP/MAC/機器名)がクラウドへ複製される
            "sync_warning": is_cloud_synced_path(self.capture_dir),
        }

    # ------------------------------------------------------------------
    # 内部処理
    # ------------------------------------------------------------------

    def _set_error(self, message: str) -> None:
        with self._stats_lock:
            self._last_error = message
        logger.error(message)

    def _dir_total_bytes(self) -> int:
        """保存先ディレクトリ内の .pcap の合計サイズを返します。"""
        total = 0
        try:
            for name in os.listdir(self.capture_dir):
                if name.endswith(".pcap"):
                    total += os.path.getsize(os.path.join(self.capture_dir, name))
        except OSError:
            pass
        return total

    def _open_new_file(self) -> bool:
        """新しいPCAPファイルを作成してグローバルヘッダを書き込みます。"""
        self._close_file()
        self._file_seq += 1
        stamp = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.capture_dir, f"igmp_flow_{stamp}_{self._file_seq:03d}.pcap")
        try:
            self._file = open(path, "wb", buffering=1024 * 1024)
            self._file.write(_GLOBAL_HEADER.pack(PCAP_MAGIC, 2, 4, 0, 0, _PCAP_SNAPLEN, PCAP_LINKTYPE_ETHERNET))
        except OSError as e:
            self._file = None
            self._set_error(f"Cannot open the PCAP file: {e}")
            return False
        self._file_path = path
        self._file_bytes = _GLOBAL_HEADER.size
        return True

    def _close_file(self) -> None:
        if self._file is not None:
            try:
                self._file.close()
            except OSError as e:
                self._set_error(f"Failed to close the PCAP file: {e}")
            self._file = None

    @staticmethod
    def _frame_bytes_and_time(packet: Any) -> Tuple[bytes, float]:
        """パケットから生フレームとタイムスタンプを取り出します(Ethernetヘッダが無ければ補う)。"""
        # 実キャプチャでは original に取得時の生バイトが残り、チェックサム不正等も忠実に保存できる
        raw = getattr(packet, "original", None) or bytes(packet)
        if not packet.haslayer("Ether"):
            raw = _DUMMY_ETHER + raw
        try:
            ts = float(packet.time)
        except (AttributeError, TypeError, ValueError):
            ts = time.time()
        return raw, ts

    def _write(self, packet: Any, truncate: bool) -> None:
        raw, ts = self._frame_bytes_and_time(packet)
        orig_len = len(raw)
        if truncate and orig_len > self.data_snaplen:
            raw = raw[: self.data_snaplen]
        if self._rotate_requested:
            self._rotate_requested = False
            self._close_file()
        if self._file is None or self._file_bytes + _RECORD_HEADER.size + len(raw) > self.max_file_bytes:
            if not self._open_new_file():
                return
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        assert self._file is not None
        self._file.write(_RECORD_HEADER.pack(sec, usec, len(raw), orig_len))
        self._file.write(raw)
        self._file_bytes += _RECORD_HEADER.size + len(raw)
        with self._stats_lock:
            self._packets += 1

    def _run(self) -> None:
        """書込スレッド本体。キューを消化し、一定間隔でフラッシュする。"""
        try:
            while True:
                try:
                    item = self._queue.get(timeout=PCAP_FLUSH_INTERVAL_SECONDS)
                except queue.Empty:
                    item = None
                if item is _STOP:
                    break
                if item is not None:
                    try:
                        self._write(*item)
                    except Exception as e:  # 1パケットの失敗で記録全体を止めない
                        self._set_error(f"PCAP write error: {e}")
                now = time.monotonic()
                if self._file is not None and now - self._last_flush >= PCAP_FLUSH_INTERVAL_SECONDS:
                    try:
                        self._file.flush()
                    except OSError as e:
                        self._set_error(f"PCAP flush failed: {e}")
                    self._last_flush = now
        finally:
            self._close_file()
