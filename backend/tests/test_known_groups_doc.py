"""既知のマルチキャストグループが、コードとマニュアル(日英)で食い違わないことのテスト (test_known_groups_doc.py)

一覧はコード(frontend/strings.js の multicastLabels、backend/constants.py)とマニュアルの 2 か所にあるため、
片方だけ更新されると、画面とマニュアルで説明が食い違う。ここで機械的に照合する。
"""

import ipaddress
import os
import re
import unittest

from backend.constants import (
    AES67_SAP_MULTICAST_IP,
    DANTE_AUDIO_PORT,
    DANTE_CONMON_IPS,
    LLMNR_MULTICAST_IP,
    MDNS_MULTICAST_IP,
    PTP_MULTICAST_IPS,
    SACN_PORT,
    SSDP_MULTICAST_IP,
)
from backend.paths import app_base_dir

MANUALS = ("docs/manual_EN.md", "docs/manual_JP.md")
SECTION_HEADINGS = {"docs/manual_EN.md": "## 9. Known multicast groups", "docs/manual_JP.md": "## 9. 既知のマルチキャストグループ"}
IP = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"


def _read(rel: str) -> str:
    with open(os.path.join(app_base_dir(), rel), encoding="utf-8") as f:
        return f.read()


def _strings_js_labels() -> set:
    """frontend/strings.js の multicastLabels に載っているアドレス。"""
    js = _read("frontend/strings.js")
    block = js[js.index("multicastLabels: {"):]
    block = block[:block.index("\n    },")]
    return set(re.findall(rf'"({IP})"\s*:', block))


def _doc_addresses(rel: str) -> set:
    """マニュアルの「既知のマルチキャストグループ」節の表の 1 列目に載っているアドレス(範囲は展開する)。"""
    text = _read(rel)
    section = text[text.index(SECTION_HEADINGS[rel]):]
    found = set()
    for line in section.splitlines():
        if not line.startswith("| ") or line.startswith("|---"):
            continue
        first = line.split("|")[1].strip()
        m = re.fullmatch(rf"({IP})\s*[–-]\s*({IP})", first)
        if m:
            lo, hi = int(ipaddress.IPv4Address(m.group(1))), int(ipaddress.IPv4Address(m.group(2)))
            if hi - lo <= 16:  # 個別に名前を付ける小さな範囲だけ展開する(sACN の大きな範囲は対象外)
                found.update(str(ipaddress.IPv4Address(i)) for i in range(lo, hi + 1))
        elif re.fullmatch(IP, first):
            found.add(first)
    return found


class TestKnownGroupsDocumented(unittest.TestCase):
    def test_every_named_address_is_in_both_manuals(self) -> None:
        """画面で名前を付けるアドレスと、バックエンドが既知として扱うアドレスは、日英両方の表に載っている。"""
        expected = _strings_js_labels() | set(DANTE_CONMON_IPS) | set(PTP_MULTICAST_IPS) | {
            MDNS_MULTICAST_IP, AES67_SAP_MULTICAST_IP, SSDP_MULTICAST_IP, LLMNR_MULTICAST_IP,
        }
        self.assertIn("239.254.3.3", expected)  # 照合対象が正しく読めていることの確認
        for rel in MANUALS:
            missing = expected - _doc_addresses(rel)
            self.assertFalse(missing, f"{rel} の表に無いアドレス: {sorted(missing)}")

    def test_manual_lists_nothing_the_app_does_not_name(self) -> None:
        """表に載せた個別アドレスは、すべて画面で名前を付けている(表だけが先行しない)。"""
        named = _strings_js_labels()
        for rel in MANUALS:
            extra = _doc_addresses(rel) - named
            self.assertFalse(extra, f"{rel} の表にあるが画面で名前を付けないアドレス: {sorted(extra)}")

    def test_port_based_ranges_match_the_code(self) -> None:
        """ポートで見分ける範囲の表は、コードのポート番号と一致する。"""
        for rel in MANUALS:
            section = _read(rel)[_read(rel).index(SECTION_HEADINGS[rel]):]
            self.assertIn(f"| {SACN_PORT} |", section, rel)
            self.assertIn(f"| {DANTE_AUDIO_PORT} |", section, rel)


if __name__ == "__main__":
    unittest.main()
