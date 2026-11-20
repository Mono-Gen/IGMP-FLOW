"""IGMP-FLOW ブラウザ切断時の終了確認ダイアログ (close_prompt.py)

画面(ブラウザ)をすべて閉じてもアプリは監視・PCAP記録を続けます。気づかないまま動き続けないよう、
ブラウザが閉じられたときにWindows標準のダイアログで「継続/終了」を尋ねます。
標準ライブラリ(ctypes)のみを使い、追加パッケージは不要です。
"""

import logging
import sys

logger = logging.getLogger("IGMP-FLOW.ClosePrompt")

_TITLE = "IGMP-FLOW"
_MESSAGE = (
    "The browser was closed.\n\n"
    "IGMP-FLOW is still monitoring and recording to PCAP.\n"
    "Do you want to exit?\n\n"
    "Yes: stop recording and exit the app\n"
    "No: keep running (launch the app again to reopen the page)"
)

# MessageBoxW のフラグ (winuser.h)
_MB_YESNO = 0x00000004
_MB_ICONQUESTION = 0x00000020
_MB_DEFBUTTON2 = 0x00000100  # 既定は「いいえ」(誤操作で記録を止めない)
_MB_SETFOREGROUND = 0x00010000
_MB_TOPMOST = 0x00040000
_IDYES = 6


def ask_exit_on_close() -> bool:
    """「終了しますか？」を表示し、ユーザーが「はい」を選んだ場合にTrueを返します。

    Windows以外、またはダイアログを出せない場合は False(=継続)を返します。呼び出しはブロックするため、
    専用スレッドから呼ぶこと。
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        flags = _MB_YESNO | _MB_ICONQUESTION | _MB_DEFBUTTON2 | _MB_SETFOREGROUND | _MB_TOPMOST
        return ctypes.windll.user32.MessageBoxW(0, _MESSAGE, _TITLE, flags) == _IDYES
    except Exception as e:  # ダイアログ失敗で記録を止めない(継続を選ぶ)
        logger.warning("終了確認ダイアログを表示できませんでした: %s", e)
        return False
