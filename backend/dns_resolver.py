"""IGMP-FLOW mDNS機器名解決マネージャ (dns_resolver.py)

このモジュールは、ネットワーク上を流れる mDNS (Bonjour / UDP 5353) パケットをパッシブに監視し、
IPアドレスと実機のホスト名（例: `Yamaha-QL5.local`）の対応関係を自動で学習・解決します。
アクティブなクエリ（名前解決要求）を自発的に送信しないため、ネットワークに不要な負荷を与えません。

AI rulesに基づき、スレッドセーフな辞書管理、厳密な型ヒント、および詳細な日本語Docstringを徹底しています。
"""

import re
import threading
from typing import Dict, Optional

from backend.constants import HOSTNAME_MAX_LEN, RESOLVER_MAX_ENTRIES

# C0/C1制御文字とDEL(改行・ESC・NULなど)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# ScapyのDNSレイヤーインポートエラーをトラップ
try:
    from scapy.all import Packet, DNS, DNSRR
    SCAPY_DNS_AVAILABLE = True
except ImportError:
    SCAPY_DNS_AVAILABLE = False


class DNSResolver:
    """mDNSパケットを解析して、IPアドレスから機器の実名（ホスト名）を自動解決するマネージャクラス。"""

    def __init__(self) -> None:
        """mDNS解決キャッシュの初期化。マルチスレッドでの読み書きを保護するロックを装備。"""
        self._cache: Dict[str, str] = {}
        self._lock = threading.Lock()

    def _remember(self, ip_addr: str, name: str) -> None:
        """機器名を無害化して学習します(ロック取得済みの呼び出し元から使うこと)。

        mDNSの名前はネットワーク上の第三者が自由に決められるため、制御文字(端末エスケープ/ログ改行注入)を除去し、
        長さと件数に上限を設けます。上限に達した場合、既存の機器名の更新は許可し、新規追加のみ拒否します。
        """
        clean = _CONTROL_CHARS.sub("", name).strip()[:HOSTNAME_MAX_LEN]
        if not clean:
            return
        if ip_addr not in self._cache and len(self._cache) >= RESOLVER_MAX_ENTRIES:
            return
        self._cache[ip_addr] = clean

    def update_from_packet(self, packet: Packet) -> None:
        """mDNSパケット（UDPポート5353）からAレコードや各種リソースレコードを抽出し、キャッシュを更新します。

        Args:
            packet (Packet): スニフィングされたmDNSパケット。
        """
        if not SCAPY_DNS_AVAILABLE or not packet.haslayer(DNS):
            return

        # 通常のDNS通信(ポート53)の誤学習を防ぐため、mDNS(5353ポート)のみを厳密に対象とします
        if packet.haslayer("UDP"):
            udp_layer = packet["UDP"]
            if udp_layer.sport != 5353 and udp_layer.dport != 5353:
                return
        else:
            return

        dns_layer = packet[DNS]
        
        # DNSの応答（Response / QR == 1）レコードに機器の自己アピール情報が含まれる
        if dns_layer.qr == 1:
            with self._lock:
                # an (Answers), ns (Authority), ar (Additional Records) のすべてを走査
                for record_type in ("an", "ns", "ar"):
                    records = getattr(dns_layer, record_type, None)
                    if records is None:
                        continue

                    # ScapyのDNSレコードコレクションを走査
                    for i in range(getattr(dns_layer, f"{record_type}count", 0)):
                        try:
                            rr = records[i]
                            if not isinstance(rr, DNSRR):
                                continue

                            # rr.type == 1 (Aレコード: ホスト名 -> IPv4マッピング)
                            if rr.type == 1:
                                ip_addr: str = str(rr.rdata)
                                # 末尾のドット（.）を削除して綺麗にする
                                host_name: str = rr.rrname.decode("utf-8", errors="ignore").rstrip(".")
                                
                                # 有効なIPとホスト名であればキャッシュに学習させる
                                if ip_addr and host_name and ip_addr != "None":
                                    # 0.0.0.0 やループバック、マルチキャスト等の特殊IPは除外
                                    if ip_addr in ("0.0.0.0", "127.0.0.1") or ip_addr.startswith("224.") or ip_addr.startswith("239."):
                                        continue

                                    # mDNS特有の重複や不要なレコードをフィルタリング（IPフォーマットの簡易チェック）
                                    if "." in ip_addr and not host_name.startswith("_"):
                                        self._remember(ip_addr, host_name)

                            # rr.type == 12 (PTRレコード: サービス探索用。サービス名 -> インスタンス名)
                            elif rr.type == 12:
                                # PTRレコードからも一部デバイスのヒント情報を抽出可能
                                ptr_name: str = rr.rdata.decode("utf-8", errors="ignore").rstrip(".")
                                # 送信元IPアドレスをベースに補助学習
                                src_ip = packet["IP"].src if packet.haslayer("IP") else None
                                if src_ip and src_ip not in ("0.0.0.0", "127.0.0.1") and not src_ip.startswith("224.") and not src_ip.startswith("239.") and not ptr_name.startswith("_") and "." in ptr_name:
                                    # Aレコードによる完全一致を優先するため、未登録の場合のみ学習
                                    if src_ip not in self._cache:
                                        self._remember(src_ip, ptr_name)

                        except Exception:
                            # 異常なパケットによる解析停止を防ぐため、個別レコードのパースエラーはスキップ
                            continue

    def resolve(self, ip_addr: str) -> Optional[str]:
        """IPアドレスに対応するホスト名（解決済みの実機名）を返します。

        Args:
            ip_addr (str): 逆引きしたいIPアドレス。

        Returns:
            Optional[str]: 学習済みのホスト名。見つからない場合はNone。
        """
        with self._lock:
            return self._cache.get(ip_addr)

    def clear_cache(self) -> None:
        """キャッシュ情報を完全にクリアします（テスト用）。"""
        with self._lock:
            self._cache.clear()

    @property
    def cache_size(self) -> int:
        """現在学習済みのキャッシュ件数を取得します。"""
        with self._lock:
            return len(self._cache)
