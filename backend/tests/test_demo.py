"""デモシミュレータのシナリオが、実アプリと同じ形式のイベントを作ることのテスト (test_demo.py)"""

import importlib.util
import os
import unittest

from backend.paths import app_base_dir

KNOWN_EVENT_CODES = {
    "igmp_join", "igmp_leave", "igmp_query", "igmp_query_group", "igmp_source_update", "igmp_report_unparsed",
    "igmp_unsupported", "ptp_message", "discovery", "dante_conmon", "dante_audio", "sacn", "aes67_audio", "multicast_other",
}
STATUS_TYPES = {"querier_status", "ptp_status", "flow_stats", "capture_status", "capture_state"}


def _load_demo():
    path = os.path.join(app_base_dir(), "scripts", "demo_simulator.py")
    spec = importlib.util.spec_from_file_location("demo_simulator", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDemoScenario(unittest.TestCase):
    def test_events_use_the_real_event_format(self) -> None:
        steps = _load_demo().scenario()
        events = [s["event"] for s in steps if "event" in s]
        messages = [s["message"] for s in steps if "message" in s]
        self.assertTrue(events and messages)
        for e in events:
            self.assertIn(e["event_code"], KNOWN_EVENT_CODES)
            for key in ("proto", "event", "src_ip", "src_mac", "group_ip", "ts", "plane"):
                self.assertIn(key, e)
            if e["proto"] == "PTP":
                self.assertIn(e["filter_key"], ("PTPv1", "PTPv2"))  # v1/v2を別フィルタで扱う
        for m in messages:
            self.assertIn(m["type"], STATUS_TYPES)

    def test_demo_covers_join_leave_query_and_ptp(self) -> None:
        codes = {s["event"]["event_code"] for s in _load_demo().scenario() if "event" in s}
        self.assertTrue({"igmp_join", "igmp_leave", "igmp_query", "ptp_message"} <= codes)


if __name__ == "__main__":
    unittest.main()
