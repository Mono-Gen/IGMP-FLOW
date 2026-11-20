"""IGMP-FLOW データ面フロー集計モジュール (flow_aggregator.py)

音声ストリームのように毎秒大量に流れるデータ面パケットを、UIへ1件ずつ送らず
(プロトコル, 送信元, グループ) 単位で一定間隔ごとに集計して配信するためのモジュールです。
全パケットの記録はPCAPが担うため、ここでは表示用の統計のみを扱います。
"""

import threading
from typing import Any, Dict, List, Tuple

from backend.constants import AGGREGATOR_MAX_FLOWS

FlowKey = Tuple[str, str, str]


class FlowAggregator:
    """データ面イベントをフロー単位で計数し、定期的に drain() で取り出すスレッドセーフな集計器。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._flows: Dict[FlowKey, Dict[str, Any]] = {}

    def add(self, event: Dict[str, Any]) -> None:
        """データ面イベント1件を集計に加算します。

        Args:
            event (Dict[str, Any]): PacketAnalyzer が生成したイベント。
        """
        key: FlowKey = (event.get("proto", ""), event.get("src_ip", ""), event.get("group_ip", ""))
        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                if len(self._flows) >= AGGREGATOR_MAX_FLOWS:
                    return  # 偽装した送信元を大量に使われても、1区間のメモリ使用量が増え続けないようにする
                flow = {
                    "proto": key[0], "src_ip": key[1], "group_ip": key[2],
                    "src_mac": event.get("src_mac", ""), "tag": event.get("tag", ""),
                    "packets": 0, "bytes": 0,
                }
                self._flows[key] = flow
            flow["packets"] += 1
            flow["bytes"] += int(event.get("frame_len", 0))

    def drain(self, interval_s: float, resolver: Any = None) -> List[Dict[str, Any]]:
        """集計結果を取り出して内部状態をリセットします。

        Args:
            interval_s (float): 集計区間の長さ(秒)。pps/bps 算出に使う。
            resolver (Any): `resolve(ip)` を持つ機器名解決器(任意)。

        Returns:
            List[Dict[str, Any]]: フロー統計のリスト(パケット数の多い順)。
        """
        with self._lock:
            flows = list(self._flows.values())
            self._flows = {}
        interval = interval_s if interval_s > 0 else 1.0
        for flow in flows:
            flow["pps"] = round(flow["packets"] / interval, 1)
            flow["bps"] = int(flow["bytes"] * 8 / interval)
            if resolver is not None:
                name = resolver.resolve(flow["src_ip"])
                if name:
                    flow["resolved_name"] = name
        flows.sort(key=lambda f: f["packets"], reverse=True)
        return flows
