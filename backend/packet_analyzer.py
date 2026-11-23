"""IGMP-FLOW パケット解析エンジン (packet_analyzer.py)

このモジュールは、Scapyで取得したパケットからIGMPおよびPTP (v1/v2) 等の状態遷移・送信元・
グループアドレス情報を抽出します。ライブキャプチャとPCAPオフライン変換の両方から
同じ解析ロジックを再利用できるよう、パケット1件を「イベントのリスト」に変換する
`decode_packet_events()` を中核としています(IGMPv3 Reportは1パケットに複数グループを含むため)。
"""

import logging
import os
import socket
import sys
from typing import Any, Dict, List, Optional

# ScapyのインポートエラーおよびNpcap未インストール状態をトラップするための準備
try:
    from scapy.all import Dot1Q, Packet, IP, UDP, Ether
    import scapy.contrib.igmp
    IGMP = scapy.contrib.igmp.IGMP
    SCAPY_AVAILABLE = True
except ImportError:
    # 実行時のNameErrorを防ぐためのダミー定義(フォールバック)
    class Packet: pass
    class IP: pass
    class UDP: pass
    class Ether: pass
    class Dot1Q: pass
    class IGMP: pass
    SCAPY_AVAILABLE = False

# get_windows_if_list は Windows 専用。他OSでScapy全体が使えなくならないよう分離して取り込む
try:
    from scapy.arch import get_windows_if_list
except ImportError:
    get_windows_if_list = None  # type: ignore[assignment]

from backend.constants import (
    ARP_CACHE_MAX_ENTRIES,
    PTP_PORT_EVENT,
    PTP_PORT_GENERAL,
    PTP_VERSION_1,
    PTP_VERSION_2,
    PTP_TAG_MAP,
    PTP_V1_MSG_TYPES,
    PTP_V1_MSG_TYPE_OFFSET,
    PTP_V2_MSG_TYPES,
    PTP_V2_CLOCK_ID_OFFSET,
    PTP_V2_ANNOUNCE_GM_ID_OFFSET,
    PTP_V2_MSG_ANNOUNCE,
    PTP_V2_DOMAIN_OFFSET,
    PTP_V2_LOG_INTERVAL_OFFSET,
    PTP_V2_ANNOUNCE_PRIORITY1_OFFSET,
    PTP_V2_ANNOUNCE_CLOCK_CLASS_OFFSET,
    PTP_V2_ANNOUNCE_CLOCK_ACCURACY_OFFSET,
    PTP_V2_ANNOUNCE_PRIORITY2_OFFSET,
    PTP_V2_ANNOUNCE_STEPS_REMOVED_OFFSET,
    PTP_V2_ANNOUNCE_TIME_SOURCE_OFFSET,
    PTP_V1_SUBDOMAIN_RANGE,
    PTP_V1_SOURCE_UUID_RANGE,
    PTP_V1_SYNC_GM_UUID_RANGE,
    PTP_V1_SYNC_INTERVAL_OFFSET,
    PTP_LOG_INTERVAL_VALID_RANGE,
    PROTOCOL_TAG_MAP,
    DANTE_CONMON_IPS,
    DANTE_CONMON_PORTS,
    DANTE_AUDIO_PORT,
    SACN_PORT,
    SACN_UNIVERSE_MAX,
    SACN_UNIVERSE_MIN,
    PLANE_CONTROL,
    PLANE_DATA,
    IGMP_TYPE_QUERY,
    IGMP_TYPE_REPORT_V1,
    IGMP_TYPE_REPORT_V2,
    IGMP_TYPE_LEAVE_V2,
    IGMP_TYPE_REPORT_V3,
    IGMP_LEN_V3_QUERY_MIN,
    IGMP_V3_REPORT_HEADER_LEN,
    IGMP_V3_RECORD_HEADER_LEN,
    IGMP_V3_RECORD_NAMES,
)

logger = logging.getLogger("IGMP-FLOW.Analyzer")

# 表示用イベント名(英語)。画面/CSVの処理分岐には言語非依存の event_code を使い、この文字列には依存しない
EVENT_JOIN = "Join"
EVENT_LEAVE = "Leave"
EVENT_QUERY_GENERAL = "General Query"


# ==============================================================================
# Npcapインストール状態のチェックロジック
# ==============================================================================

def check_npcap_installed() -> bool:
    """Windows環境において、Npcap（キャプチャドライバ）がインストールされているか確認します。

    Returns:
        bool: Npcapが検出された場合はTrue、それ以外はFalse。
    """
    if sys.platform != "win32":
        # Windows以外（macOS/Linux）は標準のキャプチャライブラリ（libpcap）を使用するためTrueを返す
        return True

    # Windowsの場合は wpcap.dll や Packet.dll の存在をチェック
    system32_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
    # Npcapは「WinPcap API互換モード」ならSystem32直下に、既定の設定ならSystem32\Npcap配下にDLLを置く。
    # 後者だけを持つ環境でも誤って「未インストール」と判定しないよう、両方を確認する
    candidates = [
        os.path.join(system32_path, name) for name in ("wpcap.dll", "Packet.dll")
    ] + [
        os.path.join(system32_path, "Npcap", name) for name in ("wpcap.dll", "Packet.dll")
    ]
    return any(os.path.exists(p) for p in candidates)


def _decode_igmpv3_time_code(code: int) -> int:
    """IGMPv3 の Max Resp Code / QQIC の浮動小数点風エンコード(RFC 3376 4.1.1 / 4.1.7)を整数へ復号します。

    Args:
        code (int): 0〜255 の符号値。

    Returns:
        int: 復号後の値(単位は呼び出し側で解釈: MaxRespは1/10秒、QQICは秒)。
    """
    if code < 128:
        return code
    exp = (code >> 4) & 0x07
    mant = code & 0x0F
    return (mant | 0x10) << (exp + 3)


def sacn_universe(ip: str) -> Optional[int]:
    """sACN のマルチキャスト宛先IPからユニバース番号を求めます。

    E1.31 ではユニバースNを 239.255.(N>>8).(N&0xFF) へ送るため、下位2オクテットがユニバース番号になる。

    Args:
        ip (str): 宛先IPv4アドレス。

    Returns:
        Optional[int]: 有効範囲(1〜63999)のユニバース番号。sACN の宛先として有り得ない場合は None。
    """
    parts = ip.split(".")
    if len(parts) != 4 or parts[0] != "239" or parts[1] != "255":
        return None
    try:
        universe = (int(parts[2]) << 8) | int(parts[3])
    except ValueError:
        return None
    return universe if SACN_UNIVERSE_MIN <= universe <= SACN_UNIVERSE_MAX else None


def _is_multicast_ip(ip: str) -> bool:
    """IPv4アドレスがマルチキャスト範囲(224.0.0.0/4)かを判定します。"""
    try:
        return 224 <= int(ip.split(".", 1)[0]) <= 239
    except (ValueError, AttributeError):
        return False


# ==============================================================================
# パケットデコーダクラス
# ==============================================================================

class PacketAnalyzer:
    """IGMPおよびPTPパケットをデコードし、トポロジ描画・ログ用のイベント辞書を抽出するクラス。"""

    def __init__(self, load_system_info: bool = True) -> None:
        """解析エンジンの初期化。

        Args:
            load_system_info (bool): Trueの場合、ローカルNIC/ARPテーブルからIP-MAC対応を初期学習する。
                PCAPオフライン変換では実行環境の情報を混ぜないためFalseにする。
        """
        self.npcap_installed = check_npcap_installed()
        # 仮想NICやループバックにおけるMACアドレス 00:00... フォールバックを避けるためのIP-MAC対応キャッシュ
        self.arp_cache: Dict[str, str] = {}
        if load_system_info:
            self._load_local_nic_macs()
            self._load_system_arp_table()

    def _load_local_nic_macs(self) -> None:
        """Windowsシステム上の全物理NICのIPアドレスと物理MACアドレスのペアを自動ロードします。"""
        if not SCAPY_AVAILABLE or get_windows_if_list is None or sys.platform != "win32":
            return
        try:
            for iface in get_windows_if_list():
                mac = iface.get("mac")
                ips = iface.get("ips", [])
                if mac and ips:
                    formatted_mac = mac.replace("-", ":").lower()
                    for ip in ips:
                        if ip and not ip.startswith("169.254.") and ip != "127.0.0.1":
                            self.arp_cache[ip] = formatted_mac
        except Exception as e:
            logger.debug("ローカルNICのMAC取得に失敗しました: %s", e)

    def _load_system_arp_table(self) -> None:
        """WindowsのシステムARPキャッシュテーブルを読み込み、IP-MAC対応表を初期学習します。"""
        if sys.platform != "win32":
            return
        import subprocess
        import re
        try:
            # arp -a コマンドをバックグラウンド実行（コンソールは非表示）
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            output = subprocess.check_output(
                ["arp", "-a"],
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW
            ).decode("cp932", errors="ignore")

            # IPとMACアドレスのパターンを抽出
            pattern = re.compile(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9a-fA-F-]{17})")
            for match in pattern.finditer(output):
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").lower()
                if not _is_multicast_ip(ip) and ip != "255.255.255.255":
                    self.arp_cache[ip] = mac
        except Exception as e:
            logger.debug("ARPテーブルの取得に失敗しました: %s", e)

    # --------------------------------------------------------------------------
    # PTP
    # --------------------------------------------------------------------------

    def parse_ptp_version(self, payload: bytes) -> Optional[int]:
        """PTPパケットの生ペイロードをバイナリ解析し、PTPv1かPTPv2かを自動判定します。

        Danteはデフォルトで PTPv1 (IEEE 1588-2002)、AES67/ST2110は PTPv2 (IEEE 1588-2008) を使用します。

        Args:
            payload (bytes): UDPの生ペイロードデータ。

        Returns:
            Optional[int]: PTPv1 (1) または PTPv2 (2)。解析不能な場合はNone。
        """
        if len(payload) < 4:
            return None

        # PTPv2: 2バイト目の下位4ビットが versionPTP (0x02)
        # PTPv1: 先頭2バイトが versionPTP (0x0001)
        version_v2_candidate = payload[1] & 0x0F
        version_v1_candidate = int.from_bytes(payload[0:2], byteorder="big")

        if version_v2_candidate == PTP_VERSION_2:
            return PTP_VERSION_2
        elif version_v1_candidate == PTP_VERSION_1:
            return PTP_VERSION_1

        return None

    def parse_ptp_details(self, payload: bytes, version: int) -> Dict[str, Any]:
        """PTPヘッダからメッセージ種別・送信クロックID・(Announceの)グランドマスターIDを抽出します。

        Args:
            payload (bytes): UDPの生ペイロード。
            version (int): parse_ptp_version() で判定したPTPバージョン。

        Returns:
            Dict[str, Any]: `ptp_msg_type` と、取得できた場合のみ `clock_id` / `grandmaster_id`。
        """
        details: Dict[str, Any] = {}
        if version == PTP_VERSION_2:
            msg_type = payload[0] & 0x0F
            details["ptp_msg_type"] = PTP_V2_MSG_TYPES.get(msg_type, f"Unknown(0x{msg_type:X})")
            if len(payload) > PTP_V2_DOMAIN_OFFSET:
                details["domain"] = str(payload[PTP_V2_DOMAIN_OFFSET])
            if len(payload) >= PTP_V2_CLOCK_ID_OFFSET + 8:
                details["clock_id"] = payload[PTP_V2_CLOCK_ID_OFFSET:PTP_V2_CLOCK_ID_OFFSET + 8].hex("-")
            # logMessageInterval: Sync/Announce等では送信間隔(log2秒)。Delay_Req(0x7F)等は意味を持たないので除外
            if len(payload) > PTP_V2_LOG_INTERVAL_OFFSET and msg_type in (0x0, 0x8, PTP_V2_MSG_ANNOUNCE):
                details["log_interval"] = int.from_bytes(
                    payload[PTP_V2_LOG_INTERVAL_OFFSET:PTP_V2_LOG_INTERVAL_OFFSET + 1], "big", signed=True
                )
            if msg_type == PTP_V2_MSG_ANNOUNCE and len(payload) > PTP_V2_ANNOUNCE_TIME_SOURCE_OFFSET:
                details["grandmaster_id"] = payload[
                    PTP_V2_ANNOUNCE_GM_ID_OFFSET:PTP_V2_ANNOUNCE_GM_ID_OFFSET + 8
                ].hex("-")
                details["priority1"] = payload[PTP_V2_ANNOUNCE_PRIORITY1_OFFSET]
                details["clock_class"] = payload[PTP_V2_ANNOUNCE_CLOCK_CLASS_OFFSET]
                details["clock_accuracy"] = payload[PTP_V2_ANNOUNCE_CLOCK_ACCURACY_OFFSET]
                details["priority2"] = payload[PTP_V2_ANNOUNCE_PRIORITY2_OFFSET]
                details["steps_removed"] = int.from_bytes(
                    payload[PTP_V2_ANNOUNCE_STEPS_REMOVED_OFFSET:PTP_V2_ANNOUNCE_STEPS_REMOVED_OFFSET + 2], "big"
                )
        else:
            if len(payload) > PTP_V1_MSG_TYPE_OFFSET:
                msg_type = payload[PTP_V1_MSG_TYPE_OFFSET]
                details["ptp_msg_type"] = PTP_V1_MSG_TYPES.get(msg_type, f"Unknown({msg_type})")
                lo, hi = PTP_V1_SUBDOMAIN_RANGE
                # subdomain は NUL 埋めのASCII文字列(例 "_DFLT")
                details["domain"] = payload[lo:hi].split(b"\x00", 1)[0].decode("ascii", errors="replace")
                lo, hi = PTP_V1_SOURCE_UUID_RANGE
                if len(payload) >= hi:
                    details["clock_id"] = payload[lo:hi].hex("-")
                if msg_type == 1:  # Sync: 本体にグランドマスター情報と同期間隔を含む
                    lo, hi = PTP_V1_SYNC_GM_UUID_RANGE
                    if len(payload) >= hi:
                        details["grandmaster_id"] = payload[lo:hi].hex("-")
                    if len(payload) > PTP_V1_SYNC_INTERVAL_OFFSET:
                        interval = int.from_bytes(
                            payload[PTP_V1_SYNC_INTERVAL_OFFSET:PTP_V1_SYNC_INTERVAL_OFFSET + 1], "big", signed=True
                        )
                        # 実機未検証のoffsetのため、妥当範囲外の値は採用しない
                        if PTP_LOG_INTERVAL_VALID_RANGE[0] <= interval <= PTP_LOG_INTERVAL_VALID_RANGE[1]:
                            details["log_interval"] = interval
        return details

    # --------------------------------------------------------------------------
    # IGMP
    # --------------------------------------------------------------------------

    @staticmethod
    def _extract_igmp_raw(packet: Packet) -> Optional[bytes]:
        """パケットからIGMPメッセージの生バイト列を取り出します(Ethernetパディングは除去)。

        Args:
            packet (Packet): Scapyパケット。

        Returns:
            Optional[bytes]: IGMPメッセージ。IGMPでなければNone。
        """
        ip_layer = packet[IP]
        if packet.haslayer(IGMP):
            raw = bytes(packet[IGMP])
        elif getattr(ip_layer, "proto", None) == 2:
            # TTL!=1 等でScapyがIGMP層にバインドしなかった場合のフォールバック
            raw = bytes(ip_layer.payload)
        else:
            return None

        # IPヘッダ長から実際のIGMP長を求め、Ethernetの最小フレーム長パディングを切り捨てる
        total_len = getattr(ip_layer, "len", None)
        if total_len:
            ihl = getattr(ip_layer, "ihl", None) or 5
            raw = raw[: max(total_len - ihl * 4, 0)]
        return raw

    def _decode_igmp(self, raw: bytes, base: Dict[str, Any]) -> List[Dict[str, Any]]:
        """IGMPメッセージを解釈し、イベントのリストを返します。

        Args:
            raw (bytes): IGMPメッセージの生バイト列。
            base (Dict[str, Any]): 共通フィールド(src_ip, src_mac, dst_ip 等)。

        Returns:
            List[Dict[str, Any]]: イベントのリスト(解釈不能な場合は空)。
        """
        if len(raw) < 8:
            return []

        igmp_type = raw[0]
        gaddr = socket.inet_ntoa(raw[4:8])

        # --- Membership Query (v1 / v2 / v3) -----------------------------------
        if igmp_type == IGMP_TYPE_QUERY:
            event: Dict[str, Any] = {"proto": "IGMP", "is_querier": True, "group_ip": gaddr}
            if len(raw) >= IGMP_LEN_V3_QUERY_MIN:
                # v3 Query: S/QRV(raw[8]), QQIC(raw[9]), 送信元数(raw[10:12])
                event["version"] = 3
                event["max_resp_time_s"] = _decode_igmpv3_time_code(raw[1]) / 10
                event["robustness"] = raw[8] & 0x07
                event["qqic_s"] = _decode_igmpv3_time_code(raw[9])
                event["num_sources"] = int.from_bytes(raw[10:12], "big")
            elif raw[1] == 0:
                # Max Resp Time が 0 の8バイトQueryは IGMPv1
                event["version"] = 1
            else:
                event["version"] = 2
                event["max_resp_time_s"] = raw[1] / 10
            if gaddr == "0.0.0.0":
                event["event"] = EVENT_QUERY_GENERAL
                event["event_code"] = "igmp_query"
            else:
                event["event"] = f"Group-Specific Query ({gaddr})"
                event["event_code"] = "igmp_query_group"
            event["description"] = (
                f"IGMPv{event['version']} Membership Query from the querier (liveness check of multicast receivers)."
            )
            return [event]

        # --- v1 / v2 Report, v2 Leave -------------------------------------------
        if igmp_type == IGMP_TYPE_REPORT_V2 or igmp_type == IGMP_TYPE_REPORT_V1:
            version = 2 if igmp_type == IGMP_TYPE_REPORT_V2 else 1
            return [{
                "proto": "IGMP", "version": version, "event": EVENT_JOIN, "event_code": "igmp_join", "group_ip": gaddr,
                "description": f"Join request for group {gaddr} detected.",
            }]
        if igmp_type == IGMP_TYPE_LEAVE_V2:
            return [{
                "proto": "IGMP", "version": 2, "event": EVENT_LEAVE, "event_code": "igmp_leave", "group_ip": gaddr,
                "description": f"Leave for group {gaddr} detected.",
            }]

        # --- v3 Membership Report ------------------------------------------------
        if igmp_type == IGMP_TYPE_REPORT_V3:
            return self._decode_igmpv3_report(raw, base)

        # 未対応のIGMPタイプも見落とさないよう記録する
        return [{
            "proto": "IGMP", "version": 0, "event": f"Unsupported IGMP type (0x{igmp_type:02X})",
            "event_code": "igmp_unsupported", "group_ip": gaddr, "description": "IGMP message type that is not analyzed.",
        }]

    def _decode_igmpv3_report(self, raw: bytes, base: Dict[str, Any]) -> List[Dict[str, Any]]:
        """IGMPv3 Membership Report の Group Record を展開し、レコード毎にイベントを生成します (RFC 3376 4.2)。

        Args:
            raw (bytes): IGMPv3 Report の生バイト列。
            base (Dict[str, Any]): 共通フィールド。

        Returns:
            List[Dict[str, Any]]: Group Record 1件につき1イベント。レコードが無い/壊れている場合は注記イベント1件。
        """
        num_records = int.from_bytes(raw[6:8], "big")
        events: List[Dict[str, Any]] = []
        offset = IGMP_V3_REPORT_HEADER_LEN

        for _ in range(num_records):
            if offset + IGMP_V3_RECORD_HEADER_LEN > len(raw):
                break  # 切り詰められたパケット(snaplen等)。取得できた分だけ使う
            rtype = raw[offset]
            aux_words = raw[offset + 1]
            num_src = int.from_bytes(raw[offset + 2:offset + 4], "big")
            group = socket.inet_ntoa(raw[offset + 4:offset + 8])
            src_start = offset + IGMP_V3_RECORD_HEADER_LEN
            src_end = src_start + 4 * num_src
            if src_end > len(raw):
                break
            sources = [socket.inet_ntoa(raw[p:p + 4]) for p in range(src_start, src_end, 4)]
            offset = src_end + aux_words * 4

            rname = IGMP_V3_RECORD_NAMES.get(rtype, f"TYPE_{rtype}")
            if rtype in (2, 4):
                # EXCLUDE モード: 指定ソース以外の全ソースを受信 = 通常のJoin(ASM相当)
                event_name = EVENT_JOIN
            elif rtype in (1, 3) and num_src == 0:
                # INCLUDE{} への遷移/状態 = 受信停止
                event_name = EVENT_LEAVE
            elif rtype in (1, 3, 5) and num_src > 0:
                event_name = EVENT_JOIN
            else:
                event_name = f"Source update ({rname})"

            src_text = f" Sources: {', '.join(sources)}" if sources else ""
            event_code = (
                "igmp_join" if event_name == EVENT_JOIN
                else "igmp_leave" if event_name == EVENT_LEAVE else "igmp_source_update"
            )
            events.append({
                "proto": "IGMP", "version": 3, "event": event_name, "event_code": event_code, "group_ip": group,
                "record_type": rname, "sources": sources,
                "description": f"IGMPv3 report [{rname}] for group {group}.{src_text}".strip(),
            })

        if not events:
            events.append({
                "proto": "IGMP", "version": 3, "event": "IGMPv3 report (records unreadable)",
                "event_code": "igmp_report_unparsed", "group_ip": base["dst_ip"],
                "description": "IGMPv3 report detected but its Group Records could not be read.",
            })
        return events

    # --------------------------------------------------------------------------
    # 全体デコード
    # --------------------------------------------------------------------------

    @staticmethod
    def _frame_len(packet: Packet) -> int:
        """フレーム長(バイト)を、パケットを再構築せずに可能な範囲で取得します。"""
        wirelen = getattr(packet, "wirelen", None)
        if wirelen:
            return int(wirelen)
        original = getattr(packet, "original", None)
        if original:
            return len(original)
        return len(packet)

    def decode_packet_events(self, packet: Packet) -> List[Dict[str, Any]]:
        """Scapyパケット1件を解釈し、可視化・ログ用のイベント辞書のリストで返します。

        各イベントには共通フィールドとして `ts`(パケット時刻, epoch秒) / `plane`(control|data) /
        `frame_len` / `vlan` を付与します。

        Args:
            packet (Packet): Scapyパケット。

        Returns:
            List[Dict[str, Any]]: デコード結果。対象外のパケットなら空リスト。
        """
        # パッシブARPスニフィングによるリアルタイムIP-MAC学習フック
        if packet.haslayer("ARP"):
            try:
                arp = packet["ARP"]
                if arp.op in (1, 2) and arp.psrc and arp.hwsrc:
                    # 偽装ARPで無限に増やされないよう、新規IPの追加のみ上限を設ける(既知IPの更新は許可)
                    if arp.psrc in self.arp_cache or len(self.arp_cache) < ARP_CACHE_MAX_ENTRIES:
                        self.arp_cache[arp.psrc] = arp.hwsrc.replace("-", ":").lower()
            except Exception as e:
                logger.debug("ARP学習に失敗しました: %s", e)

        # IPレイヤーの存在確認
        if not packet.haslayer(IP):
            return []

        ip_layer = packet[IP]
        src_ip: str = ip_layer.src
        dst_ip: str = ip_layer.dst

        # MACアドレスの取得。イーサネットヘッダーが無い/00:00の場合はARPキャッシュから逆引きする
        src_mac: str = "00:00:00:00:00:00"
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
        if src_mac == "00:00:00:00:00:00" or not src_mac:
            src_mac = self.arp_cache.get(src_ip, "00:00:00:00:00:00")

        try:
            ts = float(packet.time)
        except (AttributeError, TypeError, ValueError):
            ts = 0.0

        base: Dict[str, Any] = {"src_ip": src_ip, "src_mac": src_mac, "dst_ip": dst_ip}
        events = self._classify(packet, ip_layer, base)

        frame_len = self._frame_len(packet) if events else 0
        vlan_tag = packet.getlayer(Dot1Q)
        vlan = vlan_tag.vlan if vlan_tag is not None else None
        for ev in events:
            ev.pop("dst_ip", None)
            ev["src_ip"] = src_ip
            ev["src_mac"] = src_mac
            ev["ts"] = ts
            ev["frame_len"] = frame_len
            ev["vlan"] = vlan
            ev.setdefault("plane", PLANE_CONTROL)
        return events

    def _classify(self, packet: Packet, ip_layer: Any, base: Dict[str, Any]) -> List[Dict[str, Any]]:
        """IGMP / UDP(PTP, mDNS, SAP, SSDP, Dante, AES67) / その他マルチキャストの分類を行います。"""
        src_ip, dst_ip = base["src_ip"], base["dst_ip"]

        # A. IGMP
        raw = self._extract_igmp_raw(packet)
        if raw is not None:
            return self._decode_igmp(raw, base)

        # B. UDP
        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            dport: int = udp_layer.dport
            payload: bytes = bytes(udp_layer.payload)

            # B-1. PTP (ポート319/320のみを対象とし、マルチキャストIPだけでの誤判定を避ける)
            if dport in (PTP_PORT_EVENT, PTP_PORT_GENERAL):
                ptp_ver = self.parse_ptp_version(payload)
                if ptp_ver is not None:
                    tag_info = PTP_TAG_MAP.get(ptp_ver, {"tag": "Clock sync (PTP)", "description": ""})
                    event = {
                        "proto": "PTP", "version": ptp_ver, "event": "PTP message", "event_code": "ptp_message",
                        "filter_key": f"PTPv{ptp_ver}",  # UIフィルタ/エクスポート絞込用(v1とv2を分けて選べる)
                        "group_ip": dst_ip, "tag": tag_info["tag"], "description": tag_info["description"],
                    }
                    event.update(self.parse_ptp_details(payload, ptp_ver))
                    return [event]

            # B-2. 定義済みプロトコルのタグ解決 (mDNS, SAP, SSDP)
            if (dst_ip, dport) in PROTOCOL_TAG_MAP:
                tag_info = PROTOCOL_TAG_MAP[(dst_ip, dport)]
                return [{
                    "proto": tag_info["proto"], "event": "Discovery / control", "event_code": "discovery", "group_ip": dst_ip,
                    "tag": tag_info["tag"], "description": tag_info["description"],
                }]

            # B-3. Dante 制御 (ConMon)
            if dst_ip in DANTE_CONMON_IPS or dport in DANTE_CONMON_PORTS:
                return [{
                    "proto": "Dante-ConMon", "event": "Dante control", "event_code": "dante_conmon", "group_ip": dst_ip,
                    "tag": "Dante control (ConMon)",
                    "description": "Control traffic for Dante routing and device monitoring.",
                }]

            # B-4. sACN (E1.31 照明制御)。Dante音声と同じ 239.255.0.0/16 を使うため、ポートで先に見分ける
            if dport == SACN_PORT and dst_ip.startswith("239.255."):
                universe = sacn_universe(dst_ip)
                label = f"sACN universe {universe}" if universe is not None else "sACN"
                return [{
                    "proto": "sACN", "event": "sACN data", "event_code": "sacn", "group_ip": dst_ip,
                    "tag": label, "plane": PLANE_DATA, "universe": universe,
                    "description": "Lighting control data (ANSI E1.31 / streaming ACN).",
                }]

            # B-5. Dante音声ストリーム (239.255.0.0/16 宛、UDP 4321)。他ポートの 239.255.x.x は未分類として扱う
            if dport == DANTE_AUDIO_PORT and dst_ip.startswith("239.255."):
                return [{
                    "proto": "Dante-Audio", "event": "Audio stream", "event_code": "dante_audio", "group_ip": dst_ip,
                    "tag": "Dante audio stream", "plane": PLANE_DATA,
                    "description": "Dante multicast audio payload.",
                }]

            # B-6. AES67音声ストリーム (UDP 5004ポート)
            if dport == 5004 and dst_ip.startswith("239."):
                return [{
                    "proto": "AES67-Audio", "event": "AES67 audio stream", "event_code": "aes67_audio", "group_ip": dst_ip,
                    "tag": "AES67 audio stream", "plane": PLANE_DATA,
                    "description": "Multicast audio payload (RTP) per AES67.",
                }]

        # C. 未分類のマルチキャスト(UDP/その他IPプロトコル)。フラッディングや想定外の流入の調査用
        if _is_multicast_ip(dst_ip):
            # 224.0.0.0/24 はリンクローカル制御(ルーティングプロトコル等)、それ以外は実データ扱い
            plane = PLANE_CONTROL if dst_ip.startswith("224.0.0.") else PLANE_DATA
            return [{
                "proto": "Multicast-Other", "event": "Unclassified multicast", "event_code": "multicast_other", "group_ip": dst_ip,
                "tag": f"Unclassified multicast (IP protocol {getattr(ip_layer, 'proto', '?')})",
                "plane": plane,
                "description": "Multicast traffic that matches no known protocol.",
            }]

        return []

    def decode_packet(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """後方互換API: パケットの先頭イベントのみを返します。

        IGMPv3 Report のように複数イベントを含み得るパケットは `decode_packet_events()` を使用してください。

        Args:
            packet (Packet): Scapyパケット。

        Returns:
            Optional[Dict[str, Any]]: デコード結果。対象外のパケットならNone。
        """
        events = self.decode_packet_events(packet)
        return events[0] if events else None
