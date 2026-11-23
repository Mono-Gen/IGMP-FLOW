"""合成した単一タグ付きフレームでVLANの解析・配信・記録を検証する。"""

import csv
import shutil
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from scapy.all import ARP, Dot1Q, Ether, IP, UDP, Raw, conf, sniff, wrpcap

from backend.flow_aggregator import FlowAggregator
from backend.logger_manager import LoggerManager
from backend.main import CAPTURE_BPF, IGMPFlowApp
from backend.packet_analyzer import PacketAnalyzer
from backend.pcap_export import export_csv
from backend.querier_monitor import QuerierMonitor
from backend.tests.mock_packet_generator import (
    create_igmp_join_v2, create_igmp_leave_v2, create_igmp_query, create_mdns_packet, create_ptp_packet,
)
from backend.websocket_server import ClientState

SRC = "192.0.2.20"
MAC = "02:00:00:00:00:20"
GROUP = "239.255.0.37"


def frame(packet, vlan):
    eth = Ether(src=MAC, dst="01:00:5e:7f:00:25")
    if vlan is not None:
        eth /= Dot1Q(vlan=vlan)
    return Ether(bytes(eth / packet.payload))


def udp(group=GROUP, port=5568):
    return Ether() / IP(src=SRC, dst=group) / UDP(sport=12000, dport=port) / Raw(b"data")


@pytest.mark.parametrize("vlan", [None, 10])
@pytest.mark.parametrize(("make_packet", "proto", "event_code"), [
    (lambda: create_igmp_join_v2(SRC, GROUP), "IGMP", "igmp_join"),
    (lambda: create_igmp_leave_v2(SRC, GROUP), "IGMP", "igmp_leave"),
    (lambda: create_igmp_query(SRC), "IGMP", "igmp_query"),
    (udp, "sACN", "sacn"),
    (lambda: create_ptp_packet(SRC, "224.0.1.129", 2), "PTP", "ptp_message"),
    (lambda: create_mdns_packet(SRC), "mDNS", "discovery"),
    (lambda: udp(port=12001), "Multicast-Other", "multicast_other"),
])
def test_wire_frame_classification(make_packet, proto, event_code, vlan):
    analyzer = PacketAnalyzer(load_system_info=False)
    event, = analyzer.decode_packet_events(frame(make_packet(), vlan))
    assert (event["proto"], event["event_code"], event["vlan"]) == (proto, event_code, vlan)
    assert (event["src_ip"], event["src_mac"]) == (SRC, MAC)


@pytest.mark.parametrize(("queries", "state", "subnet_split", "expected"), [
    ([(10, "192.168.0.238"), (10, "192.168.10.1")], "multiple", False,
     [(10, "multiple", "192.168.0.238")]),
    ([(10, "192.168.0.238"), (1, "192.168.10.1")], "ok", False,
     [(1, "ok", "192.168.10.1"), (10, "ok", "192.168.0.238")]),
    ([(None, "192.168.0.238"), (None, "192.168.10.1")], "ok", True,
     [(None, "ok", "192.168.0.238"), (None, "ok", "192.168.10.1")]),
    # IP 未設定のスイッチ(0.0.0.0)は、同じ LAN の通常のクエリアと競合とみなし、別サブネットとは数えない
    ([(None, "0.0.0.0"), (None, "192.168.0.238")], "multiple", False,
     [(None, "multiple", "192.168.0.238")]),
    # 別の /24 で 1 台が競合していても、正常な /24 の行は ok のまま
    ([(None, "192.168.0.238"), (None, "192.168.10.1"), (None, "192.168.10.2")], "multiple", True,
     [(None, "ok", "192.168.0.238"), (None, "multiple", "192.168.10.1")]),
    ([(None, "192.168.0.238"), (None, "192.168.0.9")], "multiple", False,
     [(None, "multiple", "192.168.0.9")]),
    ([(None, "192.168.0.238"), (4095, "192.168.0.238"), (0, "192.168.0.238")], "ok", False,
     [(0, "ok", "192.168.0.238"), (4095, "ok", "192.168.0.238"), (None, "ok", "192.168.0.238")]),
])
def test_querier_status_by_vlan(queries, state, subnet_split, expected):
    monitor = QuerierMonitor(clock=lambda: 0)
    for vlan, ip in queries:
        monitor.observe_query(ip, MAC, 2, vlan=vlan)

    status = monitor.status()
    assert status["state"] == state
    assert status["subnet_split"] is subnet_split
    assert status["elected"] == min((ip for _, ip in queries), key=IPv4Address)
    assert {(q["vlan"], q["ip"]) for q in status["queriers"]} == set(queries)
    assert [(row["vlan"], row["state"], row["elected"]) for row in status["by_vlan"]] == expected
    for row in status["by_vlan"]:
        same_vlan = [q for q in status["queriers"] if q["vlan"] == row["vlan"]]
        if row["vlan"] is None and row["subnet"]:
            # タグ無しは /24 ごとの行。IP 未設定(0.0.0.0)はどの行にも入る
            net = row["subnet"].rsplit(".", 1)[0]
            same_vlan = [q for q in same_vlan if q["ip"].rsplit(".", 1)[0] == net or q["ip"] == "0.0.0.0"]
        assert row["queriers"] == same_vlan


def test_querier_vlan_status_excludes_expired_entries():
    now = 0
    monitor = QuerierMonitor(timeout_s=10, clock=lambda: now)
    monitor.observe_query("192.168.10.1", MAC, 2)
    monitor.observe_query(SRC, MAC, 2, vlan=10)
    now = 5
    monitor.observe_query("192.168.0.238", MAC, 2)
    assert monitor.status()["subnet_split"] is True

    now = 11
    status = monitor.status()
    assert status["subnet_split"] is False
    assert [row["vlan"] for row in status["by_vlan"]] == [None]


def test_flow_aggregates_by_vlan():
    agg = FlowAggregator()
    analyzer = PacketAnalyzer(load_system_info=False)
    for vlan in (0, 10, 10):
        event, = analyzer.decode_packet_events(frame(udp(), vlan))
        agg.add(event)
    flows = agg.drain(1.0)
    assert len(flows) == 2
    assert {(f["vlan"], f["src_ip"], f["group_ip"], f["proto"], f["packets"]) for f in flows} == {
        (0, SRC, GROUP, "sACN", 1), (10, SRC, GROUP, "sACN", 2),
    }


@pytest.mark.parametrize("is_flow", [False, True])
def test_client_text_filter_matches_vlan_id(is_flow):
    client = ClientState()
    client.set_filter({"text": "VLAN 10"})
    assert client.matches({"vlan": 10}, is_flow=is_flow)
    assert not client.matches({"vlan": 1}, is_flow=is_flow)
    assert not client.matches({"vlan": 100}, is_flow=is_flow)
    assert not client.matches({"vlan": None}, is_flow=is_flow)
    assert not client.matches({}, is_flow=is_flow)


def test_tagged_query_reaches_monitor_and_live_csv(tmp_path):
    app = IGMPFlowApp(log_dir=str(tmp_path), enable_pcap=False)
    app.analyzer = PacketAnalyzer(load_system_info=False)
    app._packet_callback(frame(create_igmp_query(SRC), 10))
    app._packet_callback(frame(create_igmp_join_v2(SRC, GROUP), None))

    assert [(q["ip"], q["vlan"]) for q in app.querier_monitor.status()["queriers"]] == [(SRC, 10)]
    path, = tmp_path.glob("*.csv")
    with path.open(newline="", encoding="utf-8-sig") as stream:
        header, query, join = csv.reader(stream)
    assert header == ["Timestamp", "Event", "Device Name", "IP Address", "MAC Address", "Multicast Group", "VLAN"]
    assert (query[-1], join[-1]) == ("10", "")


def test_live_csv_keeps_legacy_file_separate(tmp_path):
    logger = LoggerManager(log_dir=str(tmp_path))
    legacy = Path(logger._get_current_log_filepath())
    old_contents = "Timestamp,Event,Device Name,IP Address,MAC Address,Multicast Group\n"
    legacy.write_text(old_contents, encoding="utf-8-sig")

    logger = LoggerManager(log_dir=str(tmp_path))
    path = logger.write_log("Join", SRC, MAC, GROUP, vlan=0)
    assert legacy.read_text(encoding="utf-8-sig") == old_contents
    assert path == str(legacy.with_stem(legacy.stem + "_vlan"))
    with open(path, newline="", encoding="utf-8-sig") as stream:
        header, row = csv.reader(stream)
    assert header[-1] == "VLAN"
    assert row[-1] == "0"


@pytest.mark.parametrize("mode", ["aggregate", "raw"])
def test_pcap_csv_keeps_vlan_values_and_counts(tmp_path, mode):
    packets = [frame(udp(), vlan) for vlan in (None, 10, 10, 4095)]
    for packet in packets:
        packet.time = 1_700_000_000.5
    pcap = str(tmp_path / "vlan.pcap")
    output = tmp_path / "vlan.csv"
    wrpcap(pcap, packets)

    export_csv([pcap], str(output), data_mode=mode)
    with output.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        assert reader.fieldnames == [
            "Timestamp", "Event", "Device Name", "IP Address", "MAC Address", "Multicast Group",
            "Protocol", "Packets", "Detail", "Event Code", "VLAN",
        ]
        counts = sorted((row["VLAN"], row["Packets"]) for row in reader)
    tagged_counts = [("10", "2")] if mode == "aggregate" else [("10", "1"), ("10", "1")]
    assert counts == [("", "1"), *tagged_counts, ("4095", "1")]


def test_capture_bpf_accepts_tagged_and_untagged_frames(tmp_path):
    packets = []
    expected = []
    for vlan in (None, 10):
        accepted = [
            frame(create_igmp_query(SRC), vlan),
            frame(udp(), vlan),
            frame(Ether() / ARP(psrc=SRC, hwsrc=MAC), vlan),
        ]
        expected.extend(accepted)
        packets.extend([*accepted, frame(udp(group="192.0.2.21"), vlan)])
    pcap = str(tmp_path / "capture_bpf.pcap")
    wrpcap(pcap, packets)
    if not shutil.which(conf.prog.tcpdump):
        pytest.skip("ScapyのオフラインBPFに必要なtcpdump/WinDumpが見つかりません")
    try:
        matched = sniff(offline=pcap, filter=CAPTURE_BPF)
    except ImportError as exc:
        if "libpcap is not available" not in str(exc):
            raise
        pytest.skip(str(exc))
    assert [bytes(packet) for packet in matched] == [bytes(packet) for packet in expected]
