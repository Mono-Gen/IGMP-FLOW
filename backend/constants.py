"""IGMP-FLOW 定数定義モジュール (constants.py)

このモジュールは、Dante / AES67 / PTP プロトコルに関するすべての定数、
マルチキャストIPアドレス、ポート番号、および可視化用の表示ラベルを一元管理する
単一情報源 (Single Source of Truth - SSOT) です。

AI rulesに従い、マジックナンバーを排除し、高い保守性と可視性を確保します。
"""

from typing import Dict, Final, Set, Tuple

from backend.paths import data_dir

# ==============================================================================
# ネットワーク・システム関連設定
# ==============================================================================

# クエリア不在判定のタイムアウト時間（秒）
# スイッチの標準的なグループメンバーシップインターバル（260秒）を基準とする
QUERIER_TIMEOUT_SECONDS: Final[int] = 260

# 「Reportが見えていない」診断を出すまでの猶予（秒）。General Query を観測してからこの時間内に
# 他の端末のReportを1件も観測しなければ、ミラーポートではない可能性を知らせる。
# IGMP の既定 Max Response Time（10秒、RFC 2236 / RFC 3376）に、遅延と取りこぼしの余裕を足した値
REPORT_VISIBILITY_GRACE_SECONDS: Final[int] = 30

# 状態ログのデフォルト保存ディレクトリ（相対パス）
DEFAULT_LOG_DIR: Final[str] = data_dir("logs")

# アプリのバージョン(リリース成果物の名前と --version 表示に使う。セマンティックバージョニング)
APP_VERSION: Final[str] = "0.2.1"

# Npcap公式ダウンロードURL
NPCAP_DOWNLOAD_URL: Final[str] = "https://nmap.org/npcap/"

# ==============================================================================
# 記録・集計・配信関連設定
# ==============================================================================

# PCAP保存先 / CSVエクスポート先(相対パス)
DEFAULT_CAPTURE_DIR: Final[str] = data_dir("captures")
DEFAULT_EXPORT_DIR: Final[str] = data_dir("exports")

# ローカルUI配信(HTTP)のポート。WebSocketのOrigin許可リストもこの値から組み立てる
UI_HTTP_PORT: Final[int] = 8000
# WebSocketで受け付ける1メッセージの最大バイト数(コマンドは数百バイト。巨大メッセージによるメモリ浪費を防ぐ)
WS_MAX_MESSAGE_BYTES: Final[int] = 64 * 1024
# UIフィルタのテキスト最大長
FILTER_TEXT_MAX_LEN: Final[int] = 200

# ネットワーク上の第三者が偽装パケットで増やせる状態の上限(メモリ枯渇=DoS対策)
RESOLVER_MAX_ENTRIES: Final[int] = 4096    # mDNSで学習する機器名
HOSTNAME_MAX_LEN: Final[int] = 253         # DNS名の最大長 (RFC 1035)
ARP_CACHE_MAX_ENTRIES: Final[int] = 4096   # IP-MAC対応
AGGREGATOR_MAX_FLOWS: Final[int] = 5000    # 1集計区間内のフロー数
QUERIER_MAX_TRACKED: Final[int] = 64       # 追跡するクエリア送信元
PTP_MAX_MASTERS: Final[int] = 200          # 追跡するグランドマスター情報

# PCAP 1ファイルあたりの上限サイズ(超過で次ファイルへローテーション)
PCAP_MAX_FILE_BYTES: Final[int] = 256 * 1024 * 1024
# データ面(音声ストリーム等)パケットのヘッダのみ記録するバイト数
PCAP_DATA_PLANE_SNAPLEN: Final[int] = 128
# 書込キューの最大件数(超過分は取りこぼしとして計数し、キャプチャ処理は止めない)
PCAP_QUEUE_MAX: Final[int] = 100_000
# 書込フラッシュ間隔(秒)
PCAP_FLUSH_INTERVAL_SECONDS: Final[float] = 1.0
# キャプチャ保存先の合計サイズがこの値を超えたらUIへ警告(自動削除はしない)
PCAP_DISK_WARN_BYTES: Final[int] = 5 * 1024 * 1024 * 1024

# PCAPファイル形式(libpcap classic / マイクロ秒 / Ethernet)
PCAP_MAGIC: Final[int] = 0xA1B2C3D4
PCAP_LINKTYPE_ETHERNET: Final[int] = 1

# ブラウザが全て閉じてから終了確認ダイアログを出すまでの猶予(秒)。リロード時の一時切断で出さないため
CLOSE_PROMPT_GRACE_SECONDS: Final[float] = 10.0

# UI配信: データ面の集計間隔(秒)とクライアント別の個別パケット配信レート上限(件/秒)
UI_AGGREGATE_INTERVAL_SECONDS: Final[float] = 1.0
UI_MAX_EVENTS_PER_SECOND: Final[int] = 300

# プレーン区分(制御面=状態遷移の把握に必要 / データ面=大量に流れる実データ)
PLANE_CONTROL: Final[str] = "control"
PLANE_DATA: Final[str] = "data"

# ==============================================================================
# IGMP 関連定数 (RFC 1112 / 2236 / 3376)
# ==============================================================================

IGMP_TYPE_QUERY: Final[int] = 0x11
IGMP_TYPE_REPORT_V1: Final[int] = 0x12
IGMP_TYPE_REPORT_V2: Final[int] = 0x16
IGMP_TYPE_LEAVE_V2: Final[int] = 0x17
IGMP_TYPE_REPORT_V3: Final[int] = 0x22

# IGMPメッセージ長 (バイト): v1/v2は8、v3 Queryは12以上
IGMP_LEN_V1V2: Final[int] = 8
IGMP_LEN_V3_QUERY_MIN: Final[int] = 12
# v3 Report: 固定ヘッダ8バイト、Group Record固定部8バイト
IGMP_V3_REPORT_HEADER_LEN: Final[int] = 8
IGMP_V3_RECORD_HEADER_LEN: Final[int] = 8

# IGMPv3 Group Record Type (RFC 3376 4.2.12)
IGMP_V3_RECORD_NAMES: Final[Dict[int, str]] = {
    1: "MODE_IS_INCLUDE",
    2: "MODE_IS_EXCLUDE",
    3: "CHANGE_TO_INCLUDE_MODE",
    4: "CHANGE_TO_EXCLUDE_MODE",
    5: "ALLOW_NEW_SOURCES",
    6: "BLOCK_OLD_SOURCES",
}

# ==============================================================================
# PTP (IEEE 1588) 関連定数
# ==============================================================================

# PTPバージョン定義
PTP_VERSION_1: Final[int] = 1  # IEEE 1588-2002 (Danteデフォルト)
PTP_VERSION_2: Final[int] = 2  # IEEE 1588-2008 (AES67/ST2110)

# PTP用ポート
PTP_PORT_EVENT: Final[int] = 319    # Sync, Delay_Req 等 (高精度スタンプ用)
PTP_PORT_GENERAL: Final[int] = 320  # Announce, Follow_Up 等

# PTPメッセージ種別名 (v2: messageType下位4bit / v1: ヘッダ先頭から20バイト目)
PTP_V2_MSG_TYPES: Final[Dict[int, str]] = {
    0x0: "Sync", 0x1: "Delay_Req", 0x2: "PDelay_Req", 0x3: "PDelay_Resp",
    0x8: "Follow_Up", 0x9: "Delay_Resp", 0xA: "PDelay_Resp_Follow_Up",
    0xB: "Announce", 0xC: "Signaling", 0xD: "Management",
}
PTP_V1_MSG_TYPES: Final[Dict[int, str]] = {
    1: "Sync", 2: "Delay_Req", 3: "Follow_Up", 4: "Delay_Resp", 5: "Management",
}
PTP_V1_MSG_TYPE_OFFSET: Final[int] = 20
# PTPv2 共通ヘッダ: sourcePortIdentity(clockIdentity 8byte)は offset 20、Announce本体の grandmasterIdentity は offset 53
PTP_V2_CLOCK_ID_OFFSET: Final[int] = 20
PTP_V2_ANNOUNCE_GM_ID_OFFSET: Final[int] = 53
PTP_V2_MSG_ANNOUNCE: Final[int] = 0xB

# PTPv2 共通ヘッダ: domainNumber(offset 4) / logMessageInterval(offset 33, 符号付き1byte)
PTP_V2_DOMAIN_OFFSET: Final[int] = 4
PTP_V2_LOG_INTERVAL_OFFSET: Final[int] = 33
# PTPv2 Announce本体 (IEEE 1588-2008 Table 25): priority1=47, clockClass=48, clockAccuracy=49, priority2=52, stepsRemoved=61, timeSource=63
PTP_V2_ANNOUNCE_PRIORITY1_OFFSET: Final[int] = 47
PTP_V2_ANNOUNCE_CLOCK_CLASS_OFFSET: Final[int] = 48
PTP_V2_ANNOUNCE_CLOCK_ACCURACY_OFFSET: Final[int] = 49
PTP_V2_ANNOUNCE_PRIORITY2_OFFSET: Final[int] = 52
PTP_V2_ANNOUNCE_STEPS_REMOVED_OFFSET: Final[int] = 61
PTP_V2_ANNOUNCE_TIME_SOURCE_OFFSET: Final[int] = 63

# PTPv1 (IEEE 1588-2002): subdomain(4-19), sourceUuid(22-27)
PTP_V1_SUBDOMAIN_RANGE: Final[Tuple[int, int]] = (4, 20)
PTP_V1_SOURCE_UUID_RANGE: Final[Tuple[int, int]] = (22, 28)
# PTPv1 Sync本体: grandmasterClockUuid(54-59)。syncInterval(log2秒)のoffsetはWireshark旧版のPTP_SDR_SYNCINTERVAL_OFFSET(83)による。
# 実機Dante未検証のため、値が妥当範囲外なら採用しない(実測間隔を正とする)
PTP_V1_SYNC_GM_UUID_RANGE: Final[Tuple[int, int]] = (54, 60)
PTP_V1_SYNC_INTERVAL_OFFSET: Final[int] = 83
PTP_LOG_INTERVAL_VALID_RANGE: Final[Tuple[int, int]] = (-7, 7)

# PTP監視: Announce途絶=宣言間隔のこの倍数(announceReceiptTimeoutの既定値3)を超えた場合
PTP_ANNOUNCE_TIMEOUT_MULT: Final[int] = 3
# 実測間隔が宣言間隔からこの割合以上ずれたら不一致(判定には最低サンプル数が必要)
PTP_INTERVAL_TOLERANCE: Final[float] = 0.5
PTP_MIN_SAMPLES: Final[int] = 5
# 追跡するクロック×メッセージ種別の上限(メモリ保護)
PTP_MAX_TRACKED: Final[int] = 500

# ==============================================================================
# プロトコル判定マッピング (マルチキャストIP & ポート)
# ==============================================================================

# mDNS (Multicast DNS / Bonjour) 機器名解決用
MDNS_MULTICAST_IP: Final[str] = "224.0.0.251"
MDNS_PORT: Final[int] = 5353

# AES67 セッション探索 (SAP - Session Announcement Protocol)
AES67_SAP_MULTICAST_IP: Final[str] = "239.255.255.255"
AES67_SAP_PORT: Final[int] = 9875

# SSDP (Simple Service Discovery Protocol) ※オフィス不要トラフィック検出用
SSDP_MULTICAST_IP: Final[str] = "239.255.255.250"
SSDP_PORT: Final[int] = 1900

# LLMNR (Link-Local Multicast Name Resolution, RFC 4795): 224.0.0.252 / UDP 5355
LLMNR_MULTICAST_IP: Final[str] = "224.0.0.252"
LLMNR_PORT: Final[int] = 5355

# Dante 制御/監視 (ConMon) マルチキャストIP範囲
DANTE_CONMON_IPS: Final[Set[str]] = {
    "224.0.0.230",
    "224.0.0.231",
    "224.0.0.232",
    "224.0.0.233"
}
# Dante ConMon用ポート範囲
DANTE_CONMON_PORTS: Final[Set[int]] = {8700, 8701, 8702, 8703, 8704, 8705, 8706, 8707, 8708, 8800}

# PTPマルチキャストIP範囲
PTP_MULTICAST_IPS: Final[Set[str]] = {
    "224.0.1.129",
    "224.0.1.130",
    "224.0.1.131",
    "224.0.1.132",
    "224.0.0.107"  # PTPv2 Peer Delay
}

# ==============================================================================
# タグ定義辞書 (可視化表示用ラベル)
# ==============================================================================

# 定義済みのマルチキャストアドレス・プロトコルに対する日本語ラベルと詳細説明
PROTOCOL_TAG_MAP: Final[Dict[Tuple[str, int], Dict[str, str]]] = {
    # (IPアドレス, ポート番号) -> {タグ名, 説明}
    (MDNS_MULTICAST_IP, MDNS_PORT): {
        "proto": "mDNS",
        "tag": "Name resolution (mDNS)",
        "description": "Essential traffic for automatic device discovery by Dante Controller and Bonjour."
    },
    (AES67_SAP_MULTICAST_IP, AES67_SAP_PORT): {
        "proto": "SAP",
        "tag": "AES67 session info (SAP)",
        "description": "Announcements that let AES67 devices from different vendors discover and connect streams."
    },
    (LLMNR_MULTICAST_IP, LLMNR_PORT): {
        "proto": "LLMNR",
        "tag": "Name resolution (LLMNR)",
        "description": "Windows link-local name resolution. Not needed on an audio network and may add noise."
    },
    (SSDP_MULTICAST_IP, SSDP_PORT): {
        "proto": "SSDP",
        "tag": "Discovery (SSDP/UPnP)",
        "description": "Office-network discovery traffic (e.g. Windows). May needlessly consume audio-network bandwidth."
    }
}

# PTPバージョン固有の表示タグ
PTP_TAG_MAP: Final[Dict[int, Dict[str, str]]] = {
    PTP_VERSION_1: {
        "tag": "Clock sync (PTPv1 / Dante)",
        "description": "Default Dante clock synchronization. Required for grandmaster election across the network."
    },
    PTP_VERSION_2: {
        "tag": "Clock sync (PTPv2 / AES67)",
        "description": "Clock synchronization used when AES67 or SMPTE ST 2110 is enabled."
    }
}
