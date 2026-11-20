"""IGMP-FLOW アプリアイコンの生成スクリプト (generate_icon.py)

第三者の画像素材を使わず、幾何学図形(角丸四角・円・線)だけでアイコンを描き、複数サイズのICOとして出力します。
標準ライブラリのみ使用(Pillow等は不要)。図柄は「クエリア(紫)を中心に、グループ(緑)・端末(青)・クロック(橙)が
つながるトポロジ」で、画面の凡例の配色と揃えています。出力物の著作権は本リポジトリ(MIT)に帰属します。

使い方:
    python scripts/generate_icon.py            # assets/icon.ico と frontend/favicon.ico を生成
    python scripts/generate_icon.py out.ico    # 指定先のみ生成
"""

import math
import os
import struct
import sys
import zlib
from typing import List, Tuple

Color = Tuple[float, float, float]

# ICOに含めるサイズ(px)。Windowsのタスクバー/エクスプローラ/ブラウザのタブで使われる代表サイズ
SIZES = (16, 32, 48, 64, 128, 256)

# 配色(画面の凡例と同系統)
BG: Color = (15, 23, 42)
LINE: Color = (148, 163, 184)
HUB: Color = (139, 92, 246)      # クエリア
GROUP: Color = (16, 185, 129)    # マルチキャストグループ
HOST: Color = (59, 130, 246)     # 端末
CLOCK: Color = (245, 158, 11)    # PTPクロック

# 図形定義(0..1の正規化座標)
HUB_POS = (0.5, 0.5)
SATELLITES = [((0.5, 0.2), GROUP), ((0.2, 0.74), HOST), ((0.8, 0.74), CLOCK)]
HUB_R, SAT_R, LINE_W, RING_W = 0.14, 0.08, 0.04, 0.025


def sdf_round_rect(x: float, y: float, half: float, radius: float) -> float:
    """中心(0.5,0.5)の角丸正方形までの符号付き距離(内側が負)。"""
    qx = abs(x - 0.5) - (half - radius)
    qy = abs(y - 0.5) - (half - radius)
    return math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) - radius


def sdf_circle(x: float, y: float, c: Tuple[float, float], r: float) -> float:
    return math.hypot(x - c[0], y - c[1]) - r


def sdf_segment(x: float, y: float, a: Tuple[float, float], b: Tuple[float, float], width: float) -> float:
    """線分(太さwidth, 端は丸い)までの符号付き距離。"""
    px, py = x - a[0], y - a[1]
    dx, dy = b[0] - a[0], b[1] - a[1]
    t = max(0.0, min(1.0, (px * dx + py * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - dx * t, py - dy * t) - width / 2


def over(dst: List[float], color: Color, coverage: float) -> None:
    """dst(R,G,B,A: 0..1の非乗算)へ color を coverage で合成する(source-over)。"""
    if coverage <= 0.0:
        return
    sa = coverage
    da = dst[3]
    out_a = sa + da * (1 - sa)
    for i in range(3):
        dst[i] = (color[i] / 255 * sa + dst[i] * da * (1 - sa)) / out_a if out_a > 0 else 0.0
    dst[3] = out_a


def render(size: int) -> bytes:
    """sizeピクセル四方のRGBA生データ(行優先)を描画して返す。"""
    px = float(size)  # 正規化距離→ピクセル距離の倍率(1pxで覆い率が0→1に変わる幅を作る)
    rows = bytearray()
    for j in range(size):
        rows.append(0)  # PNGのフィルタタイプ(None)
        y = (j + 0.5) / size
        for i in range(size):
            x = (i + 0.5) / size
            px_rgba = [0.0, 0.0, 0.0, 0.0]
            over(px_rgba, BG, max(0.0, min(1.0, 0.5 - sdf_round_rect(x, y, 0.5, 0.22) * px)))
            for pos, _ in SATELLITES:
                over(px_rgba, LINE, 0.9 * max(0.0, min(1.0, 0.5 - sdf_segment(x, y, HUB_POS, pos, LINE_W) * px)))
            nodes = [(HUB_POS, HUB_R, HUB)] + [(pos, SAT_R, col) for pos, col in SATELLITES]
            for pos, r, col in nodes:
                over(px_rgba, BG, max(0.0, min(1.0, 0.5 - sdf_circle(x, y, pos, r + RING_W) * px)))  # 背景色の縁取り
                over(px_rgba, col, max(0.0, min(1.0, 0.5 - sdf_circle(x, y, pos, r) * px)))
            rows += bytes(int(round(max(0.0, min(1.0, v)) * 255)) for v in px_rgba)
    return bytes(rows)


def png_bytes(size: int) -> bytes:
    """sizeピクセル四方のPNG(RGBA)を作る。"""
    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8bit, RGBA
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(render(size), 9)) + chunk(b"IEND", b"")


def build_ico() -> bytes:
    """複数サイズのPNGを格納したICOを組み立てる。"""
    images = [(s, png_bytes(s)) for s in SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for size, data in images:
        dim = 0 if size >= 256 else size  # 256は0で表す(ICOの仕様)
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    return header + entries + blobs


def main(argv: List[str]) -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    outputs = argv or [os.path.join(root, "assets", "icon.ico"), os.path.join(root, "frontend", "favicon.ico")]
    ico = build_ico()
    for path in outputs:
        with open(path, "wb") as f:
            f.write(ico)
        print(f"wrote {path} ({len(ico)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
