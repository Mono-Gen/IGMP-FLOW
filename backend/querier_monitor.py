"""IGMP-FLOW クエリア監視モジュール (querier_monitor.py)

IGMP Query の送信元を追跡し、IGMP Snooping運用で典型的な障害である
「クエリア不在」と「複数クエリアの同時存在」を検出します。

判定:
- none     : 一度もQueryを観測せず監視開始から timeout 経過、または最後のQueryから timeout 経過
- multiple : timeout 以内に複数の送信元IPからQueryを観測(IGMPv2/v3の選出では最小IPがクエリア)
- ok       : 上記以外(単一クエリアが生存)
- unknown  : 監視開始直後で、まだ判定できない
"""

import threading
import time
from typing import Any, Callable, Dict

from backend.constants import QUERIER_MAX_TRACKED, QUERIER_TIMEOUT_SECONDS


class QuerierMonitor:
    """Query受信を記録し、クエリアの状態(none/multiple/ok/unknown)を返すスレッドセーフな監視器。"""

    def __init__(
        self,
        timeout_s: float = QUERIER_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """監視器の初期化。

        Args:
            timeout_s (float): クエリア不在とみなすまでの秒数。
            clock (Callable[[], float]): 現在時刻(秒)を返す関数。テストで差し替え可能。
        """
        self._timeout = timeout_s
        self._clock = clock
        self._lock = threading.Lock()
        self._started = clock()
        self._queriers: Dict[str, Dict[str, Any]] = {}

    def reset(self) -> None:
        """監視状態を初期化します(NIC切替時など)。"""
        with self._lock:
            self._started = self._clock()
            self._queriers = {}

    def observe_query(self, src_ip: str, src_mac: str, version: int) -> None:
        """Query 1件を記録します。

        Args:
            src_ip (str): Query送信元IP(IP未設定スイッチは 0.0.0.0)。
            src_mac (str): 送信元MAC。
            version (int): 観測したIGMPバージョン。
        """
        now = self._clock()
        with self._lock:
            if src_ip not in self._queriers and len(self._queriers) >= QUERIER_MAX_TRACKED:
                return  # 偽装Queryの送信元を無限に追跡しない
            entry = self._queriers.setdefault(
                src_ip, {"ip": src_ip, "mac": src_mac, "version": version, "count": 0, "last": now, "interval_s": None}
            )
            if entry["count"] > 0:
                entry["interval_s"] = round(now - entry["last"], 1)
            entry.update(mac=src_mac, version=version, last=now)
            entry["count"] += 1

    def status(self) -> Dict[str, Any]:
        """現在のクエリア状態を返します(UI配信用の辞書)。"""
        now = self._clock()
        with self._lock:
            alive = [
                {
                    "ip": q["ip"], "mac": q["mac"], "version": q["version"],
                    "interval_s": q["interval_s"], "age_s": round(now - q["last"], 1),
                }
                for q in self._queriers.values()
                if now - q["last"] <= self._timeout
            ]
            ever_seen = bool(self._queriers)
            uptime = now - self._started
            last_any = max((q["last"] for q in self._queriers.values()), default=None)

        alive.sort(key=lambda q: tuple(int(p) for p in q["ip"].split(".")))
        if len(alive) > 1:
            state = "multiple"
        elif len(alive) == 1:
            state = "ok"
        elif ever_seen or uptime >= self._timeout:
            state = "none"
        else:
            state = "unknown"

        return {
            "type": "querier_status",
            "state": state,
            "queriers": alive,
            # 選出ルール(最小IPが勝つ)に基づく本来のクエリア
            "elected": alive[0]["ip"] if alive else None,
            "since_last_query_s": round(now - last_any, 1) if last_any is not None else None,
            "timeout_s": self._timeout,
        }
