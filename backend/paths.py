"""IGMP-FLOW 実行場所に依存しないパス解決 (paths.py)

PCAP/CSV/ログなどの「実データ」の保存先を決めます。方針:
- 実データ(実在のIP/MACアドレスや機器名を含む)は、クラウド同期(OneDrive等)されないユーザー専用の場所に置く。
  Windowsでは %LOCALAPPDATA%(OneDriveの同期対象外・本人以外は既定で読めない)、それ以外はXDGのデータ領域。
- 環境変数 IGMP_FLOW_DATA_DIR で保存先を明示的に変更できる。
- 絶対パスはソースに持たず、実行時に算出する。
"""

import os
import sys
from typing import List

# 保存先を上書きする環境変数
DATA_DIR_ENV = "IGMP_FLOW_DATA_DIR"

# クラウド同期フォルダとみなすパス要素(小文字)。同期されると実データがクラウドへ複製されるため警告に使う
_SYNC_MARKERS = ("onedrive", "dropbox", "google drive", "googledrive", "icloud", "box sync", "pcloud")


def app_base_dir() -> str:
    """アプリの基準ディレクトリを返します。

    PyInstaller実行ファイルでは実行ファイルのあるフォルダ、ソース実行ではプロジェクトのルートです。
    (実データの保存先ではなく、UIファイルなど同梱物の位置を求めるために使う)
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def user_data_root() -> str:
    """実データ(PCAP/CSV/ログ)の保存ルートを返します。クラウド同期されない場所が既定です。"""
    override = os.environ.get(DATA_DIR_ENV)
    if override:
        return os.path.abspath(os.path.expanduser(override))
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(base, "IGMP-FLOW", "data")
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "igmp-flow")


def data_dir(name: str) -> str:
    """実データ保存ルート直下の保存先(例: captures)の絶対パスを返します。"""
    return os.path.join(user_data_root(), name)


def frontend_dir() -> str:
    """UI(HTML/JS/CSS)のディレクトリを返します。実行ファイルではバンドル展開先(_MEIPASS)を使う。"""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "frontend")  # type: ignore[attr-defined]
    return os.path.join(app_base_dir(), "frontend")


def _sync_roots() -> List[str]:
    """環境変数で分かるクラウド同期フォルダのルート(OneDrive)を返します。"""
    roots = [os.environ.get(k) for k in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")]
    return [os.path.normcase(os.path.abspath(r)) for r in roots if r]


def is_cloud_synced_path(path: str) -> bool:
    """パスがクラウド同期フォルダ(OneDrive/Dropbox/Google Drive等)の中にありそうかを判定します。

    判定は推測であり、見逃し得ます(同期設定は環境ごとに異なるため)。警告表示にのみ使うこと。
    """
    full = os.path.normcase(os.path.abspath(path))
    for root in _sync_roots():
        if full == root or full.startswith(root + os.sep):
            return True
    parts = [p.lower() for p in full.replace("/", os.sep).split(os.sep)]
    return any(m in part for part in parts for m in _SYNC_MARKERS)
