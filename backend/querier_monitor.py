"""IGMP-FLOW クエリア監視モジュール (querier_monitor.py)

IGMP Query の送信元を追跡し、IGMP Snooping運用で典型的な障害である
「クエリア不在」と「複数クエリアの同時存在」を検出します。

判定:
- none     : 一度もQueryを観測せず監視開始から timeout 経過、または最後のQueryから timeout 経過
- multiple : 同じVLAN(タグ無しの場合は同じ /24)で生存中のクエリアが複数
- ok       : 生存中のクエリアがいて、同じVLANまたは /24 内での競合が無い
- unknown  : 監視開始直後で、まだ判定できない

Reportの可視性診断(reports_hidden):
IGMP Snooping有効のスイッチは、Report(Join/Leave)をルーターポートにしか転送しない。
そのためミラー(SPAN)ではない通常ポートでは、Queryは届くのに他の端末のReportは届かない。
General Query を観測してから猶予時間が過ぎても、このPC以外からのReportが1件も無ければ
reports_hidden=True とし、「Join/Leaveが見えていない可能性」をUIに知らせる。
このPC自身のReport(OSのmDNS/SSDP参加など)はキャプチャされるため、自アドレスは数えない。
"""

import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from backend.constants import QUERIER_MAX_TRACKED, QUERIER_TIMEOUT_SECONDS, REPORT_VISIBILITY_GRACE_SECONDS


class QuerierMonitor:
    """Query受信を記録し、クエリアの状態(none/multiple/ok/unknown)を返すスレッドセーフな監視器。"""

    def __init__(
        self,
        timeout_s: float = QUERIER_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        report_grace_s: float = REPORT_VISIBILITY_GRACE_SECONDS,
    ) -> None:
        """監視器の初期化。

        Args:
            timeout_s (float): クエリア不在とみなすまでの秒数。
            clock (Callable[[], float]): 現在時刻(秒)を返す関数。テストで差し替え可能。
            report_grace_s (float): General Query 観測後、Report不可視と判定するまでの秒数。
        """
        self._timeout = timeout_s
        self._report_grace = report_grace_s
        self._own_ips: Set[str] = set()
        self._own_mac = ""
        self._first_general_query: Optional[float] = None
        self._reports_seen = 0
        self._clock = clock
        self._lock = threading.Lock()
        self._started = clock()
        self._queriers: Dict[Tuple[Optional[int], str], Dict[str, Any]] = {}

    def reset(self) -> None:
        """監視状態を初期化します(NIC切替時など)。"""
        with self._lock:
            self._started = self._clock()
            self._queriers = {}
            self._first_general_query = None
            self._reports_seen = 0

    def set_own_addresses(self, ips: Iterable[str], mac: str) -> None:
        """このPC自身のアドレスを設定します。自分のReportを「他の端末のReport」と数えないために使う。

        Args:
            ips (Iterable[str]): キャプチャNICのIPアドレス。
            mac (str): キャプチャNICのMACアドレス(不明なら空文字)。
        """
        with self._lock:
            self._own_ips = {ip for ip in ips if ip}
            self._own_mac = (mac or "").lower()

    def observe_report(self, src_ip: str, src_mac: str) -> None:
        """Report(Join/Leave等) 1件を記録します。このPC自身が送ったものは数えません。

        Args:
            src_ip (str): Report送信元IP。
            src_mac (str): Report送信元MAC。
        """
        with self._lock:
            if src_ip in self._own_ips or (self._own_mac and (src_mac or "").lower() == self._own_mac):
                return
            self._reports_seen += 1

    def observe_query(
        self, src_ip: str, src_mac: str, version: int, general: bool = True, *, vlan: Optional[int] = None,
    ) -> None:
        """Query 1件を記録します。

        Args:
            src_ip (str): Query送信元IP(IP未設定スイッチは 0.0.0.0)。
            src_mac (str): 送信元MAC。
            version (int): 観測したIGMPバージョン。
            general (bool): General Query か(Group-Specific Query は全端末の応答を促さないためFalse)。
            vlan (Optional[int]): 最外のVLANタグのID。タグ無しならNone。
        """
        now = self._clock()
        with self._lock:
            if general and self._first_general_query is None:
                self._first_general_query = now
            key = (vlan, src_ip)
            if key not in self._queriers and len(self._queriers) >= QUERIER_MAX_TRACKED:
                return  # 偽装Queryの送信元を無限に追跡しない
            entry = self._queriers.setdefault(
                key, {"ip": src_ip, "mac": src_mac, "version": version, "count": 0, "last": now, "interval_s": None}
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
                    "ip": q["ip"], "mac": q["mac"], "version": q["version"], "vlan": vlan,
                    "interval_s": q["interval_s"], "age_s": round(now - q["last"], 1),
                }
                for (vlan, _), q in self._queriers.items()
                if now - q["last"] <= self._timeout
            ]
            ever_seen = bool(self._queriers)
            uptime = now - self._started
            last_any = max((q["last"] for q in self._queriers.values()), default=None)
            reports_seen = self._reports_seen
            first_gq = self._first_general_query

        alive.sort(key=lambda q: tuple(int(p) for p in q["ip"].split(".")))
        grouped: Dict[Optional[int], List[Dict[str, Any]]] = {}
        for querier in alive:
            grouped.setdefault(querier["vlan"], []).append(querier)

        # NICがタグを外すことがあるため、タグ無しのクエリアは /24 ごとに分けて競合を判定する。
        # IP未設定のスイッチ(0.0.0.0)はどのサブネットか分からないので、タグ無しの他のクエリアすべてと同じ区画とみなす
        # (同じLANに IP未設定のクエリアと通常のクエリアがいる、という典型的な競合を見逃さないため)
        untagged = grouped.get(None, [])
        no_ip = [q for q in untagged if q["ip"] == "0.0.0.0"]
        by_subnet: Dict[str, List[Dict[str, Any]]] = {}
        for q in untagged:
            if q["ip"] != "0.0.0.0":
                by_subnet.setdefault(q["ip"].rsplit(".", 1)[0], []).append(q)
        by_vlan = []
        for vlan in sorted(k for k in grouped if k is not None):
            queriers = grouped[vlan]
            by_vlan.append({
                "vlan": vlan, "subnet": None, "state": "multiple" if len(queriers) > 1 else "ok",
                "elected": queriers[0]["ip"], "queriers": queriers,
            })
        untagged_sections = [(f"{net}.0/24", qs + no_ip) for net, qs in sorted(by_subnet.items())]
        if not untagged_sections and no_ip:
            untagged_sections = [(None, no_ip)]
        for subnet, queriers in untagged_sections:
            queriers = sorted(queriers, key=lambda q: tuple(int(p) for p in q["ip"].split(".")))
            # 0.0.0.0 は選出で最小IPに勝てないため、IPを持つクエリアがいればそちらを選出結果にする
            with_ip = [q for q in queriers if q["ip"] != "0.0.0.0"]
            by_vlan.append({
                "vlan": None, "subnet": subnet, "state": "multiple" if len(queriers) > 1 else "ok",
                "elected": (with_ip or queriers)[0]["ip"], "queriers": queriers,
            })
        untagged_subnets = by_subnet

        if any(entry["state"] == "multiple" for entry in by_vlan):
            state = "multiple"
        elif alive:
            state = "ok"
        elif ever_seen or uptime >= self._timeout:
            state = "none"
        else:
            state = "unknown"

        return {
            "type": "querier_status",
            "state": state,
            "queriers": alive,
            "by_vlan": by_vlan,
            "subnet_split": len(untagged_subnets) > 1,
            # 選出ルール(最小IPが勝つ)に基づく本来のクエリア
            "elected": alive[0]["ip"] if alive else None,
            "since_last_query_s": round(now - last_any, 1) if last_any is not None else None,
            "timeout_s": self._timeout,
            "reports_seen": reports_seen,
            # Queryは届くのに他端末のReportが届かない = Snoopingに絞られた通常ポートの可能性
            "reports_hidden": bool(first_gq is not None and reports_seen == 0 and now - first_gq >= self._report_grace),
        }
