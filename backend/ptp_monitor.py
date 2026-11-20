"""IGMP-FLOW PTP監視モジュール (ptp_monitor.py)

PTP(v1/v2)メッセージを、クロック(送信元)×メッセージ種別ごとに追跡し、
- 実測の送信間隔(直近の中央値)と、メッセージが宣言する間隔(logMessageInterval)
- グランドマスターID・プライオリティ・クロッククラス(Announce)
を一覧化します。あわせて次の異常を検出します:
- announce_lost      : Announceが宣言間隔×3(announceReceiptTimeout既定)を超えて途絶
- multiple_gm        : 同一ドメインで複数のグランドマスターIDが同時に存在
- interval_mismatch  : 実測間隔が宣言間隔から大きくずれている(Sync/Announce)
間隔の実測にはパケット自体の時刻(event["ts"])を使い、途絶判定にのみ現在時刻を使います。
"""

import statistics
import threading
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from backend.constants import (
    PTP_ANNOUNCE_TIMEOUT_MULT,
    PTP_INTERVAL_TOLERANCE,
    PTP_MAX_MASTERS,
    PTP_MAX_TRACKED,
    PTP_MIN_SAMPLES,
    QUERIER_TIMEOUT_SECONDS,
)

# 宣言間隔を持つメッセージ種別(間隔不一致の判定対象)
_INTERVAL_CHECKED = {"Sync", "Announce"}
# 状態表から外すまでの無通信時間(秒)
_STALE_SECONDS = float(QUERIER_TIMEOUT_SECONDS)

Key = Tuple[int, str, str, str]  # (PTPバージョン, ドメイン, clock_id, メッセージ種別)


class PtpMonitor:
    """PTPイベントを集計し、状態表と異常を返すスレッドセーフな監視器。"""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        """監視器の初期化。

        Args:
            clock (Callable[[], float]): 現在のepoch秒を返す関数。テストで差し替え可能。
        """
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: Dict[Key, Dict[str, Any]] = {}
        self._masters: Dict[Tuple[int, str, str], Dict[str, Any]] = {}

    def reset(self) -> None:
        """追跡状態を初期化します(NIC切替時など)。"""
        with self._lock:
            self._entries = {}
            self._masters = {}

    def observe(self, event: Dict[str, Any]) -> None:
        """PTPイベント1件を記録します。

        Args:
            event (Dict[str, Any]): PacketAnalyzer が生成した proto="PTP" のイベント。
        """
        msg_type = event.get("ptp_msg_type")
        if not msg_type:
            return
        version = int(event.get("version", 0))
        domain = str(event.get("domain", ""))
        clock_id = str(event.get("clock_id", event.get("src_ip", "")))
        ts = float(event.get("ts") or self._clock())
        key: Key = (version, domain, clock_id, msg_type)

        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                if len(self._entries) >= PTP_MAX_TRACKED:
                    return  # 異常な数のクロックを追跡し続けないための上限
                entry = {
                    "version": version, "domain": domain, "clock_id": clock_id, "msg_type": msg_type,
                    "src_ip": event.get("src_ip", ""), "count": 0, "last_ts": ts,
                    "deltas": deque(maxlen=8), "declared": None,
                }
                self._entries[key] = entry
            else:
                delta = ts - entry["last_ts"]
                if delta > 0:
                    entry["deltas"].append(delta)
            entry["count"] += 1
            entry["last_ts"] = ts
            entry["src_ip"] = event.get("src_ip", entry["src_ip"])
            entry["seen_at"] = self._clock()
            if event.get("log_interval") is not None:
                entry["declared"] = 2.0 ** int(event["log_interval"])

            # グランドマスター情報: v2はAnnounce、v1はSyncに含まれる
            gm_id = event.get("grandmaster_id")
            if gm_id and ((version, domain, clock_id) in self._masters or len(self._masters) < PTP_MAX_MASTERS):
                m = self._masters.setdefault((version, domain, clock_id), {})
                m.update(gm_id=gm_id, seen_at=self._clock())
                for k in ("priority1", "priority2", "clock_class", "clock_accuracy", "steps_removed"):
                    if event.get(k) is not None:
                        m[k] = event[k]

    @staticmethod
    def _measured(entry: Dict[str, Any]) -> Optional[float]:
        deltas: Deque[float] = entry["deltas"]
        return statistics.median(deltas) if deltas else None

    def status(self) -> Dict[str, Any]:
        """現在のPTP状態表と異常リストを返します(UI配信用)。"""
        now = self._clock()
        rows: List[Dict[str, Any]] = []
        alerts: List[Dict[str, str]] = []

        with self._lock:
            entries = [e for e in self._entries.values() if now - e["seen_at"] <= _STALE_SECONDS]
            masters = {k: dict(v) for k, v in self._masters.items() if now - v["seen_at"] <= _STALE_SECONDS}
            all_entries = list(self._entries.values())

        for e in entries:
            measured = self._measured(e)
            declared = e["declared"]
            rows.append({
                "version": e["version"], "domain": e["domain"], "clock_id": e["clock_id"],
                "src_ip": e["src_ip"], "msg_type": e["msg_type"], "count": e["count"],
                "measured_s": round(measured, 3) if measured is not None else None,
                "declared_s": declared, "age_s": round(now - e["seen_at"], 1),
            })

            if e["msg_type"] in _INTERVAL_CHECKED and declared and measured and len(e["deltas"]) >= PTP_MIN_SAMPLES:
                if abs(measured - declared) > declared * PTP_INTERVAL_TOLERANCE:
                    alerts.append({
                        "kind": "interval_mismatch",
                        "text": f"{e['src_ip']}: {e['msg_type']} interval differs from the declared {declared:g}s (measured {measured:.3g}s)",
                    })

        # Announce途絶: 宣言間隔が分かっているクロックのみ判定(全期間のエントリを見る=一度表から消えても検出)
        for e in all_entries:
            if e["msg_type"] == "Announce" and e["declared"]:
                silent = now - e["seen_at"]
                if silent > e["declared"] * PTP_ANNOUNCE_TIMEOUT_MULT and silent <= _STALE_SECONDS:
                    alerts.append({
                        "kind": "announce_lost",
                        "text": f"{e['src_ip']} (domain {e['domain']}): no Announce for {silent:.0f}s",
                    })

        # 複数グランドマスター: 同一バージョン×ドメイン内で異なる gm_id が同時に存在
        by_domain: Dict[Tuple[int, str], set] = {}
        for (version, domain, _clock), m in masters.items():
            by_domain.setdefault((version, domain), set()).add(m["gm_id"])
        for (version, domain), ids in by_domain.items():
            if len(ids) > 1:
                alerts.append({
                    "kind": "multiple_gm",
                    "text": f"PTPv{version} domain {domain}: multiple grandmasters present: {', '.join(sorted(ids))}",
                })

        rows.sort(key=lambda r: (r["version"], r["domain"], r["clock_id"], r["msg_type"]))
        return {
            "type": "ptp_status",
            "rows": rows,
            "masters": [
                {"version": v, "domain": d, "clock_id": c, **m} for (v, d, c), m in sorted(masters.items())
            ],
            "alerts": alerts,
        }
