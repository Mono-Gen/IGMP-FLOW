"""IGMP-FLOW NIC列挙・選択ロジック (nic_manager.py)

キャプチャ対象のネットワークインターフェース(NIC)の列挙、既定NICの自動選定、対話選択を担当します。
責任: NIC情報の取得と選定。 対象外: キャプチャの開始/停止(main.IGMPFlowApp が担当)。
"""

import sys
from typing import Any, Dict, List, Optional, Tuple

try:
    from scapy.all import get_if_list
    from scapy.arch import get_windows_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

NicInfo = Dict[str, Any]

# 既定NICの自動選定時に除外する名前(仮想/ループバック)。Hyper-V等は物理ポートの通信を見られないため後回しにする
_SKIP_NAME_WORDS = ("loopback", "virtual")


def list_nics(active_interface: Optional[str]) -> Tuple[List[NicInfo], int]:
    """利用可能なNICの一覧と、動作中NICの番号(1始まり。無ければ-1)を返します。

    Args:
        active_interface (Optional[str]): 現在キャプチャ中のNICの識別名(Windowsでは \\Device\\NPF_{...})。

    Returns:
        Tuple[List[NicInfo], int]: (NIC一覧, 動作中NICの index)。
    """
    if not SCAPY_AVAILABLE:
        return [], -1

    nics: List[NicInfo] = []
    active_idx = -1

    if sys.platform == "win32":
        count = 0
        for iface in get_windows_if_list():
            ips = iface.get("ips", [])
            if not ips:
                continue  # IP未割当(キャプチャ不可)のアダプタは除外
            ip_str = next((ip for ip in ips if "." in ip), ips[0])  # IPv4を優先
            count += 1
            if active_interface == iface["name"]:
                active_idx = count
            nics.append({"index": count, "name": iface["description"], "ip": ip_str, "guid": iface["name"]})
    else:
        for i, name in enumerate(get_if_list()):
            if active_interface == name:
                active_idx = i + 1
            nics.append({"index": i + 1, "name": name, "ip": "DHCP / dynamic", "guid": name})

    return nics, active_idx


def choose_default_nic(nics: List[NicInfo]) -> str:
    """IPが割り当てられた実アダプタを優先して、既定のキャプチャ対象NICを選びます。

    Args:
        nics (List[NicInfo]): list_nics() の結果。

    Returns:
        str: NICの識別名。候補が無い場合は Windows の既定名を返す。
    """
    for nic in nics:
        ip = nic.get("ip", "")
        name = nic.get("name", "").lower()
        if ip and ip != "127.0.0.1" and not any(w in name for w in _SKIP_NAME_WORDS):
            print(f"[AUTO-NIC] アクティブなNICを自動選択しました: {nic['name']} (IP: {nic['ip']})")
            return nic["guid"]
    for nic in nics:
        if nic.get("ip") and nic["ip"] != "127.0.0.1":
            return nic["guid"]
    if nics:
        return nics[0]["guid"]
    return "イーサネット"  # 日本語版Windowsの既定アダプタ名。他言語では候補が空のときのみ到達する最終手段


def choose_nic_interactive(nics: List[NicInfo]) -> Optional[str]:
    """NICの一覧を表示し、コンソールの入力で選ばせます。キャンセル/候補なしは None。"""
    if not nics:
        print("[エラー] 検出されたネットワークカードがありません。")
        return None

    for iface in nics:
        print(f" [{iface['index']}] {iface['name']}")
        print(f"     -> IP: {iface['ip']}")
        print(f"     -> ID: {iface['guid']}\n")

    while True:
        try:
            sel = input(f"Select the capture interface number (1-{len(nics)}): ").strip()
            if not sel:
                continue
            idx = int(sel)
            if 1 <= idx <= len(nics):
                print(f"-> Selected: {nics[idx - 1]['name']}\n")
                return nics[idx - 1]["guid"]
            print(f"[警告] 1 から {len(nics)} の範囲で入力してください。")
        except ValueError:
            print("[警告] 有効な数値を入力してください。")
        except (KeyboardInterrupt, EOFError):
            print("\n[情報] インターフェースの選択がキャンセルされました。")
            return None
