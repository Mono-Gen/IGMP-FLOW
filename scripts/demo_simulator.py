"""IGMP-FLOW UI demo simulator (demo_simulator.py)

Try the UI without any network hardware, Npcap or administrator rights. The simulator starts the same local UI server and
WebSocket server as the real app, opens the page in your browser, and replays a scenario in a loop: a querier appears,
Dante/AES67 devices join and leave groups, PTPv1/PTPv2 clocks show up, audio streams are reported as 1-second statistics,
and a PTP warning appears. Nothing is captured and nothing is written to disk.

Usage (from the project root):
    python scripts/demo_simulator.py
Stop with Ctrl+C.
"""

import os
import sys
import threading
import time
import webbrowser
from typing import Any, Dict, List

# Allow running as a plain script from anywhere (the project root is not on sys.path otherwise)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.constants import UI_HTTP_PORT  # noqa: E402
from backend.paths import frontend_dir  # noqa: E402
from backend.static_server import start_ui_server  # noqa: E402
from backend.websocket_server import WebSocketServer  # noqa: E402

QUERIER = "192.168.1.254"
NOW = time.time


def ev(proto: str, code: str, label: str, src: str, mac: str, group: str, **extra: Any) -> Dict[str, Any]:
    """Build an event with the same fields the real analyzer produces."""
    data: Dict[str, Any] = {
        "proto": proto, "event": label, "event_code": code, "src_ip": src, "src_mac": mac,
        "group_ip": group, "plane": "control", "frame_len": 80, "ts": NOW(),
    }
    data.update(extra)
    return data


def scenario() -> List[Dict[str, Any]]:
    """Return the steps: {"delay": seconds, "event": {...}} or {"delay": s, "message": {...}} (a status message)."""
    return [
        {"delay": 1.0, "event": ev("IGMP", "igmp_query", "General Query", QUERIER, "00:0d:b9:11:22:33", "0.0.0.0",
                                   version=3, is_querier=True, robustness=2, qqic_s=125, max_resp_time_s=10.0)},
        {"delay": 0.5, "message": {"type": "querier_status", "state": "ok", "elected": QUERIER, "timeout_s": 260,
                                   "queriers": [{"ip": QUERIER, "mac": "00:0d:b9:11:22:33", "version": 3,
                                                 "interval_s": 125.0, "age_s": 1.0}]}},
        {"delay": 1.5, "event": ev("IGMP", "igmp_join", "Join", "192.168.1.10", "00:a0:de:aa:bb:01", "239.255.10.10",
                                   version=3, resolved_name="Console-A.local", sources=[], record_type="CHANGE_TO_EXCLUDE_MODE")},
        {"delay": 1.0, "event": ev("PTP", "ptp_message", "PTP message", "192.168.1.10", "00:a0:de:aa:bb:01", "224.0.1.129",
                                   version=1, filter_key="PTPv1", ptp_msg_type="Sync", domain="_DFLT",
                                   tag="Clock sync (PTPv1 / Dante)", resolved_name="Console-A.local")},
        {"delay": 1.5, "event": ev("IGMP", "igmp_join", "Join", "192.168.1.20", "00:11:05:cc:dd:02", "239.255.10.10",
                                   version=3, resolved_name="Receiver-B.local", sources=[], record_type="CHANGE_TO_EXCLUDE_MODE")},
        {"delay": 1.5, "event": ev("IGMP", "igmp_join", "Join", "192.168.1.30", "00:20:18:ee:ff:03", "239.255.20.20",
                                   version=2, resolved_name="Speaker-C.local")},
        {"delay": 1.0, "message": {"type": "flow_stats", "interval_s": 1.0, "flows": [
            {"proto": "Dante-Audio", "src_ip": "192.168.1.10", "src_mac": "00:a0:de:aa:bb:01", "group_ip": "239.255.10.10",
             "tag": "Dante audio stream", "packets": 4000, "bytes": 4_000_000, "pps": 4000.0, "bps": 32_000_000,
             "resolved_name": "Console-A.local"},
            {"proto": "AES67-Audio", "src_ip": "192.168.1.100", "src_mac": "00:40:94:12:34:56", "group_ip": "239.69.1.1",
             "tag": "AES67 audio stream", "packets": 1000, "bytes": 500_000, "pps": 1000.0, "bps": 4_000_000}]}},
        {"delay": 1.5, "event": ev("PTP", "ptp_message", "PTP message", "192.168.1.100", "00:40:94:12:34:56", "224.0.1.129",
                                   version=2, filter_key="PTPv2", ptp_msg_type="Announce", domain="0",
                                   grandmaster_id="00-40-94-ff-fe-12-34-56", priority1=128, clock_class=248,
                                   tag="Clock sync (PTPv2 / AES67)")},
        {"delay": 1.0, "message": {"type": "ptp_status", "alerts": [
            {"kind": "multiple_gm", "text": "PTPv2 domain 0: multiple grandmasters present (demo)"}],
            "masters": [{"version": 2, "domain": "0", "clock_id": "00-40-94-ff-fe-12-34-56",
                         "gm_id": "00-40-94-ff-fe-12-34-56", "priority1": 128, "priority2": 128, "clock_class": 248}],
            "rows": [{"version": 2, "domain": "0", "clock_id": "00-40-94-ff-fe-12-34-56", "src_ip": "192.168.1.100",
                      "msg_type": "Announce", "count": 5, "measured_s": 1.0, "declared_s": 1.0, "age_s": 0.5},
                     {"version": 1, "domain": "_DFLT", "clock_id": "00-a0-de-aa-bb-01", "src_ip": "192.168.1.10",
                      "msg_type": "Sync", "count": 40, "measured_s": 1.0, "declared_s": None, "age_s": 0.4}]}},
        {"delay": 1.5, "event": ev("SSDP", "discovery", "Discovery / control", "192.168.1.150", "00:15:5d:00:11:22",
                                   "239.255.255.250", tag="Discovery (SSDP/UPnP)")},
        {"delay": 2.5, "event": ev("IGMP", "igmp_leave", "Leave", "192.168.1.20", "00:11:05:cc:dd:02", "239.255.10.10",
                                   version=3, resolved_name="Receiver-B.local")},
    ]


def main() -> int:
    server = WebSocketServer(
        on_get_status=lambda: [{"type": "capture_state", "running": True},
                               {"type": "capture_status", "enabled": True, "packets": 123456, "dropped": 0,
                                "error": None, "disk_warning": False, "sync_warning": False}],
    )
    ui = start_ui_server(frontend_dir(), UI_HTTP_PORT)
    if ui is None:
        print(f"Port {UI_HTTP_PORT} is in use (is IGMP-FLOW already running?). Close it and try again.")
        return 1
    server.start()
    url = f"http://localhost:{UI_HTTP_PORT}/index.html"
    print(f"Demo running. Open {url}  (Ctrl+C to stop)")
    webbrowser.open(url)

    stop = threading.Event()
    try:
        while not stop.is_set():
            for step in scenario():
                time.sleep(step["delay"])
                if "event" in step:
                    server.send_event({**step["event"], "ts": NOW()})
                    print(f"[demo] {step['event']['proto']}: {step['event']['event']}")
                else:
                    server.broadcast(step["message"])
            time.sleep(5.0)
    except KeyboardInterrupt:
        print("\nStopping the demo.")
    finally:
        server.stop()
        ui.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
