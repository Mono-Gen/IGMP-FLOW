"""IGMP-FLOW PCAP→CSV エクスポート (pcap_export.py)

PCAPを唯一の全件記録(SSOT)とし、CSVはそこから都度生成します。解析ロジックは
ライブキャプチャと同じ `PacketAnalyzer` を再利用するため、解析のバグを直せば
過去のPCAPから正しいCSVを再生成できます。

- 時刻はパケット自体の記録時刻(エクスポート実行時刻ではない)
- mDNSの機器名は2パスで解決(1パス目で学習→2パス目で出力)し、名前が判明する前のパケットにも反映
- データ面(音声ストリーム)は既定で「1秒×フロー」単位に集計(`--data raw` で全件、`none` で除外)

CLI例:
    python -m backend.pcap_export captures/a.pcap -o out.csv --proto IGMP --since "2026-01-01 10:00:00"
"""

import argparse
import csv
import datetime
import heapq
import logging
import os
import sys
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from backend.constants import DEFAULT_CAPTURE_DIR, DEFAULT_EXPORT_DIR, PLANE_DATA
from backend.csv_safety import csv_safe
from backend.dns_resolver import DNSResolver
from backend.packet_analyzer import PacketAnalyzer

logger = logging.getLogger("IGMP-FLOW.Export")

CSV_HEADERS = [
    "Timestamp", "Event", "Device Name", "IP Address", "MAC Address", "Multicast Group",
    "Protocol", "Packets", "Detail", "Event Code",
]
# 集計行・通常行を時刻順に整列して書き出すためのバッファ窓(秒)
_REORDER_WINDOW_S = 3.0
DATA_MODES = ("aggregate", "raw", "none")


def list_capture_files(capture_dir: str = DEFAULT_CAPTURE_DIR) -> List[str]:
    """保存先内の .pcap をファイル名(=作成時刻)順に返します。"""
    if not os.path.isdir(capture_dir):
        return []
    return sorted(
        os.path.join(capture_dir, n) for n in os.listdir(capture_dir) if n.endswith(".pcap")
    )


def parse_local_datetime(text: Optional[str]) -> Optional[float]:
    """'YYYY-MM-DD HH:MM:SS' 形式(ローカル時刻)をepoch秒へ変換します。空/Noneならそのまま None。"""
    if not text:
        return None
    return datetime.datetime.strptime(text.strip(), "%Y-%m-%d %H:%M:%S").timestamp()


def _iter_packets(paths: Iterable[str], warnings: List[str]) -> Iterator[Any]:
    """複数PCAPからパケットを順に返します。壊れた/書込中の末尾は警告として記録し継続します。"""
    from scapy.utils import PcapReader

    for path in paths:
        try:
            with PcapReader(path) as reader:
                for pkt in reader:
                    yield pkt
        except Exception as e:  # 書込中ファイルの末尾切れ等。取得済み分は有効
            warnings.append(f"{os.path.basename(path)}: reading stopped early ({e})")


def _format_ts(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _detail(ev: Dict[str, Any]) -> str:
    """CSVのDetail列用に、イベント固有の補足情報を短くまとめます。"""
    parts: List[str] = []
    if ev.get("record_type"):
        parts.append(str(ev["record_type"]))
    if ev.get("sources"):
        parts.append("src=" + "/".join(ev["sources"]))
    if ev.get("ptp_msg_type"):
        parts.append(str(ev["ptp_msg_type"]))
    if ev.get("domain") not in (None, ""):
        parts.append(f"domain={ev['domain']}")
    if ev.get("log_interval") is not None:
        parts.append(f"interval={2.0 ** ev['log_interval']:g}s")
    if ev.get("grandmaster_id"):
        parts.append("GM=" + ev["grandmaster_id"])
    elif ev.get("clock_id"):
        parts.append("clock=" + ev["clock_id"])
    for key, label in (("priority1", "P1"), ("priority2", "P2"), ("clock_class", "class")):
        if ev.get(key) is not None:
            parts.append(f"{label}={ev[key]}")
    if ev.get("robustness") is not None:
        parts.append(f"QRV={ev['robustness']}")
    if ev.get("qqic_s") is not None:
        parts.append(f"QQIC={ev['qqic_s']}s")
    if ev.get("max_resp_time_s") is not None:
        parts.append(f"MaxResp={ev['max_resp_time_s']}s")
    if not parts and ev.get("tag"):
        parts.append(str(ev["tag"]))
    return "; ".join(parts)


def _matches(
    ev: Dict[str, Any], name: str, protos: Optional[Set[str]], group: str, src: str, text: str = "",
    ptp_types: Optional[Set[str]] = None,
) -> bool:
    """イベントが絞込条件(プロトコル/PTP種別/グループ/送信元/UIと同じ自由テキスト)を満たすか判定します。"""
    # PTPは "PTPv1"/"PTPv2" で絞れる(filter_key)。従来の "PTP" 指定でも両方に一致させる
    if protos and ev.get("filter_key", ev["proto"]) not in protos and ev["proto"] not in protos:
        return False
    if ptp_types and ev["proto"] == "PTP" and ev.get("ptp_msg_type") not in ptp_types:
        return False
    if text:
        # UIのテキストフィルタと同じ対象(IP/MAC/グループ/機器名/タグ)の部分一致
        hay = " ".join([
            ev.get("src_ip", ""), ev.get("src_mac", ""), ev.get("group_ip", ""), name, ev.get("tag", ""),
        ]).lower()
        if text.lower() not in hay:
            return False
    if group and group not in ev.get("group_ip", ""):
        return False
    if src:
        hay = f"{ev.get('src_ip', '')} {ev.get('src_mac', '')} {name}".lower()
        if src.lower() not in hay:
            return False
    return True


def export_csv(
    pcap_paths: List[str],
    out_path: str,
    since: Optional[float] = None,
    until: Optional[float] = None,
    protos: Optional[Set[str]] = None,
    group: str = "",
    src: str = "",
    data_mode: str = "aggregate",
    text: str = "",
    ptp_types: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """PCAPを解析してCSVへ書き出します。

    Args:
        pcap_paths (List[str]): 入力PCAP(複数可。時刻順に並べて渡す)。
        out_path (str): 出力CSVのパス。
        since (Optional[float]): この時刻(epoch秒)以降のみ出力。
        until (Optional[float]): この時刻(epoch秒)以前のみ出力。
        protos (Optional[Set[str]]): 出力するプロトコル名(例 {"IGMP","PTP"})。None/空で全て。
        group (str): マルチキャストグループの部分一致絞込。
        src (str): 送信元IP/MAC/機器名の部分一致絞込。
        data_mode (str): データ面の扱い。"aggregate"(1秒集計) / "raw"(全件) / "none"(除外)。
        text (str): IP/MAC/グループ/機器名/タグへの自由テキスト部分一致(UIのテキストフィルタ相当)。
        ptp_types (Optional[Set[str]]): 出力するPTPメッセージ種別(例 {"Announce","Sync"})。None/空で全て。

    Returns:
        Dict[str, Any]: {"out": 出力パス, "rows": 行数, "packets": 読み込みパケット数, "warnings": [...]}。
    """
    if data_mode not in DATA_MODES:
        raise ValueError(f"data_mode must be one of {DATA_MODES}: {data_mode}")

    warnings: List[str] = []
    resolver = DNSResolver()

    # 1パス目: mDNS応答から機器名を学習(出力はしない)
    for pkt in _iter_packets(pcap_paths, warnings):
        resolver.update_from_packet(pkt)
    warnings.clear()  # 同じ警告が2パス目でも出るため、1パス目分は捨てる

    # 実行環境のNIC/ARP情報を混ぜない(PCAP内のEthernetヘッダとARPのみで解決する)
    analyzer = PacketAnalyzer(load_system_info=False)

    heap: List[Tuple[float, int, List[Any]]] = []
    seq = 0
    rows = 0
    packets = 0
    agg: Dict[Tuple[int, str, str, str], Dict[str, Any]] = {}

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)  # 実データを含むため本人のみ(POSIX)

    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)

        def push(ts: float, row: List[Any]) -> None:
            nonlocal seq
            seq += 1
            heapq.heappush(heap, (ts, seq, row))

        def drain(upto: float) -> None:
            nonlocal rows
            while heap and heap[0][0] <= upto:
                # 機器名等は第三者が決められる値のため、数式として評価されないよう無害化して書く
                writer.writerow([csv_safe(c) for c in heapq.heappop(heap)[2]])
                rows += 1

        def flush_agg(before_sec: Optional[int]) -> None:
            """before_sec より古い集計バケットを行にして heap へ送る(None なら全て)。"""
            for key in [k for k in agg if before_sec is None or k[0] < before_sec]:
                b = agg.pop(key)
                ev = b["ev"]
                push(float(key[0]), [
                    _format_ts(float(key[0])), f"{ev['event']} (1s aggregate)", b["name"] or ev["src_ip"],
                    ev["src_ip"], ev["src_mac"], ev["group_ip"], ev["proto"], b["count"], _detail(ev), ev.get("event_code", ""),
                ])

        for pkt in _iter_packets(pcap_paths, warnings):
            packets += 1
            for ev in analyzer.decode_packet_events(pkt):
                ts = ev["ts"]
                if (since is not None and ts < since) or (until is not None and ts > until):
                    continue
                name = resolver.resolve(ev["src_ip"]) or ""
                if not _matches(ev, name, protos, group, src, text, ptp_types):
                    continue

                if ev["plane"] == PLANE_DATA and data_mode != "raw":
                    if data_mode == "none":
                        continue
                    key = (int(ts), ev["proto"], ev["src_ip"], ev["group_ip"])
                    bucket = agg.get(key)
                    if bucket is None:
                        agg[key] = {"ev": ev, "name": name, "count": 1}
                    else:
                        bucket["count"] += 1
                else:
                    push(ts, [
                        _format_ts(ts), ev["event"], name or ev["src_ip"], ev["src_ip"], ev["src_mac"],
                        ev.get("group_ip", ""), ev["proto"], 1, _detail(ev), ev.get("event_code", ""),
                    ])

                flush_agg(int(ts) - 1)
                drain(ts - _REORDER_WINDOW_S)

        flush_agg(None)
        drain(float("inf"))

    return {"out": out_path, "rows": rows, "packets": packets, "warnings": warnings}


def export_captures(
    capture_dir: str = DEFAULT_CAPTURE_DIR,
    export_dir: str = DEFAULT_EXPORT_DIR,
    since: Optional[float] = None,
    until: Optional[float] = None,
    protos: Optional[Set[str]] = None,
    group: str = "",
    src: str = "",
    data_mode: str = "aggregate",
    text: str = "",
    ptp_types: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """保存先内のPCAPから、期間に関係するファイルを選んでCSVを `export_dir` に生成します。

    Returns:
        Dict[str, Any]: export_csv の戻り値。対象ファイルが無い場合は ValueError を送出。
    """
    files = list_capture_files(capture_dir)
    if since is not None:
        # 最終更新が開始時刻より前のファイルには該当パケットが無い
        files = [p for p in files if os.path.getmtime(p) >= since]
    if not files:
        raise ValueError("No PCAP files found for the selected period.")
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(export_dir, f"igmp_flow_export_{stamp}.csv")
    return export_csv(files, out_path, since, until, protos, group, src, data_mode, text, ptp_types)


def main(argv: Optional[List[str]] = None) -> int:
    """CLIエントリーポイント。"""
    p = argparse.ArgumentParser(description="IGMP-FLOW: export PCAP files to CSV")
    p.add_argument("pcap", nargs="+", help="Input PCAP file(s)")
    p.add_argument("-o", "--out", required=True, help="Output CSV path")
    p.add_argument("--since", help='Start time, local "YYYY-MM-DD HH:MM:SS"')
    p.add_argument("--until", help='End time, local "YYYY-MM-DD HH:MM:SS"')
    p.add_argument("--proto", action="append", help="Filter by protocol (repeatable), e.g. IGMP, PTPv1, PTPv2, mDNS")
    p.add_argument("--ptp-type", action="append", help="Filter by PTP message type (repeatable), e.g. Announce, Sync")
    p.add_argument("--group", default="", help="Substring match on the multicast group address")
    p.add_argument("--src", default="", help="Substring match on source IP / MAC / device name")
    p.add_argument("--data", choices=DATA_MODES, default="aggregate", help="How to handle data-plane (audio) packets")
    args = p.parse_args(argv)

    try:
        result = export_csv(
            args.pcap, args.out,
            since=parse_local_datetime(args.since), until=parse_local_datetime(args.until),
            protos=set(args.proto) if args.proto else None,
            group=args.group, src=args.src, data_mode=args.data,
            ptp_types=set(args.ptp_type) if args.ptp_type else None,
        )
    except (OSError, ValueError) as e:
        print(f"[ERROR] Export failed: {e}", file=sys.stderr)
        return 1
    print(f"[DONE] Wrote {result['rows']} rows ({result['packets']} packets read): {result['out']}")
    for w in result["warnings"]:
        print(f"[WARNING] {w}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
