"""IGMP-FLOW テストパケット生成シミュレータ (mock_packet_generator.py)

このモジュールは、ネットワーク上の実際のパケットキャプチャを行うことなく、
あらゆる通信パターン（正常系および異常系のマルチクエリア、PTPv1/v2混在など）を
メモリ上で擬似生成するためのテスト用ヘルパー群を提供します。

AI rulesに基づき、各パケットの正確なヘッダ構造（特にPTPのバイナリ）を構築します。
"""

from scapy.all import Ether, IP, UDP, Packet, DNS, DNSRR
import scapy.contrib.igmp
IGMP = scapy.contrib.igmp.IGMP

from backend.constants import (
    MDNS_PORT,
    MDNS_MULTICAST_IP,
    PTP_PORT_EVENT,
    PTP_VERSION_1,
    PTP_VERSION_2,
    DANTE_CONMON_IPS,
    SSDP_MULTICAST_IP,
    SSDP_PORT
)


def create_ether_ip_base(src_ip: str, dst_ip: str, src_mac: str = "00:11:22:33:44:55") -> Ether:
    """イーサネットおよびIPのベースレイヤーを生成します。

    Args:
        src_ip (str): 送信元IPアドレス。
        dst_ip (str): 送信先IPアドレス。
        src_mac (str): 送信元MACアドレス。

    Returns:
        Ether: イーサネット/IPレイヤーオブジェクト。
    """
    return Ether(src=src_mac, dst="01:00:5e:00:00:01") / IP(src=src_ip, dst=dst_ip)


def create_igmp_query(src_ip: str, group_ip: str = "0.0.0.0", src_mac: str = "00:11:22:33:44:55") -> Packet:
    """IGMP Membership Query (生存確認) パケットを生成します。

    Args:
        src_ip (str): クエリア（スイッチ/ルータ）のIPアドレス。
        group_ip (str): 対象グループアドレス（0.0.0.0の場合はGeneral Query）。
        src_mac (str): クエリアのMACアドレス。

    Returns:
        Packet: IGMP Query パケット。
    """
    # IGMP Queryの宛先IPは通常 224.0.0.1 (All Systems)
    base = Ether(src=src_mac, dst="01:00:5e:00:00:01") / IP(src=src_ip, dst="224.0.0.1")
    # IGMP Type = 0x11 (Query)
    return base / IGMP(type=0x11, gaddr=group_ip)


def create_igmp_join_v2(src_ip: str, group_ip: str, src_mac: str = "00:aa:bb:cc:dd:ee") -> Packet:
    """IGMPv2 Membership Report (Join) パケットを生成します。

    Args:
        src_ip (str): 受信機器（ホスト）のIPアドレス。
        group_ip (str): 参加するマルチキャストグループアドレス。
        src_mac (str): 受信機器のMACアドレス。

    Returns:
        Packet: IGMPv2 Join パケット。
    """
    # Joinの宛先はグループアドレス自体
    base = Ether(src=src_mac, dst="01:00:5e:00:00:02") / IP(src=src_ip, dst=group_ip)
    # IGMP Type = 0x16 (v2 Report)
    return base / IGMP(type=0x16, gaddr=group_ip)


def create_igmp_leave_v2(src_ip: str, group_ip: str, src_mac: str = "00:aa:bb:cc:dd:ee") -> Packet:
    """IGMPv2 Leave Group パケットを生成します。

    Args:
        src_ip (str): 離脱する機器のIPアドレス。
        group_ip (str): 離脱するマルチキャストグループアドレス。
        src_mac (str): 離脱する機器のMACアドレス。

    Returns:
        Packet: IGMPv2 Leave パケット。
    """
    # Leaveの宛先は通常 224.0.0.2 (All Routers)
    base = Ether(src=src_mac, dst="01:00:5e:00:00:02") / IP(src=src_ip, dst="224.0.0.2")
    # IGMP Type = 0x17 (v2 Leave)
    return base / IGMP(type=0x17, gaddr=group_ip)


def create_ptp_packet(src_ip: str, dst_ip: str, version: int, src_mac: str = "00:11:22:33:44:55") -> Packet:
    """PTP (IEEE 1588) の同期パケットを生成します。

    Args:
        src_ip (str): 送信元（マスタークロック）のIPアドレス。
        dst_ip (str): マルチキャストアドレス (例: 224.0.1.129)。
        version (int): PTP_VERSION_1 (1) または PTP_VERSION_2 (2)。
        src_mac (str): クロック機器のMACアドレス。

    Returns:
        Packet: PTP パケット。
    """
    base = create_ether_ip_base(src_ip, dst_ip, src_mac)
    
    # PTPヘッダのバイナリ構築
    payload = b""
    if version == PTP_VERSION_1:
        # PTPv1 (IEEE 1588-2002): 先頭2バイトがバージョン (0x00 0x01)
        payload = b"\x00\x01\x00\x2c\x00\x00\x00\x00" + b"\x00" * 36
    elif version == PTP_VERSION_2:
        # PTPv2 (IEEE 1588-2008): 1バイト目がメッセージタイプ (例: 0x00 Sync)、2バイト目がバージョン (0x02)
        payload = b"\x00\x02\x00\x2c\x00\x00\x00\x00" + b"\x00" * 36

    return base / UDP(sport=PTP_PORT_EVENT, dport=PTP_PORT_EVENT) / payload


def create_mdns_packet(src_ip: str, src_mac: str = "00:aa:bb:cc:dd:ee") -> Packet:
    """mDNS (Bonjour) によるデバイス探索/広告パケットを生成します。

    Args:
        src_ip (str): 機器のIPアドレス。
        src_mac (str): 機器のMACアドレス。

    Returns:
        Packet: mDNS パケット。
    """
    base = create_ether_ip_base(src_ip, MDNS_MULTICAST_IP, src_mac)
    # mDNSは UDP 5353
    return base / UDP(sport=MDNS_PORT, dport=MDNS_PORT) / b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"


def create_dante_conmon_packet(src_ip: str, src_mac: str = "00:aa:bb:cc:dd:ee") -> Packet:
    """Dante 制御 (ConMon) パケットを生成します。

    Args:
        src_ip (str): Dante機器のIPアドレス。
        src_mac (str): Dante機器のMACアドレス。

    Returns:
        Packet: Dante ConMon パケット。
    """
    # ConMonの代表IP: 224.0.0.230
    dst_ip = list(DANTE_CONMON_IPS)[0]
    base = create_ether_ip_base(src_ip, dst_ip, src_mac)
    # 代表ポート 8700
    return base / UDP(sport=8700, dport=8700) / b"Dante ConMon Test Packet"


def create_ssdp_packet(src_ip: str, src_mac: str = "00:aa:bb:cc:dd:ee") -> Packet:
    """SSDP (オフィス不要探索) パケットを生成します。

    Args:
        src_ip (str): PC等のIPアドレス。
        src_mac (str): PC等のMACアドレス。

    Returns:
        Packet: SSDP パケット。
    """
    base = create_ether_ip_base(src_ip, SSDP_MULTICAST_IP, src_mac)
    return base / UDP(sport=SSDP_PORT, dport=SSDP_PORT) / b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"


def create_mdns_answer_packet(src_ip: str, host_name: str, src_mac: str = "00:aa:bb:cc:dd:ee") -> Packet:
    """ホスト名解決用の Aレコード（DNS Answer）を含んだmDNSパケットを生成します。

    Args:
        src_ip (str): 機器のIPアドレス。
        host_name (str): 解決したい機器名 (例: "Yamaha-QL5.local")
        src_mac (str): 機器のMACアドレス。

    Returns:
        Packet: Aレコードを含むmDNS応答パケット。
    """
    base = create_ether_ip_base(src_ip, MDNS_MULTICAST_IP, src_mac)
    # DNS応答パケットの構築
    # qr=1 (Response), aa=1 (Authoritative), ancount=1 (Answer Count 1)
    dns_layer = DNS(
        id=0, qr=1, opcode=0, aa=1, tc=0, rd=0, ra=0, z=0, rcode=0,
        qdcount=0, ancount=1, nscount=0, arcount=0,
        qd=[],  # 既定の質問(www.example.com)が付くとバイト列化→再解析で壊れる(PCAP経由のテストで判明)。Scapy 2.7 は None でなく [] を推奨
        an=DNSRR(rrname=host_name + ".", type=1, rclass=32769, ttl=120, rdata=src_ip)
    )
    return base / UDP(sport=MDNS_PORT, dport=MDNS_PORT) / dns_layer

