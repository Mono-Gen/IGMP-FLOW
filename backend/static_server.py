"""IGMP-FLOW UI配信用のローカルHTTPサーバー (static_server.py)

フロントエンド(HTML/JS/CSS)だけを127.0.0.1で配信します。想定する脅威と対策:
- DNSリバインディング: Hostヘッダが localhost/127.0.0.1(自サーバーのポート)以外なら403
- ディレクトリ列挙: 一覧表示を無効化(404)
- パストラバーサル: 配信ディレクトリ外は標準実装が拒否。リンク/`..`も404
- 古いUIのキャッシュ(更新後に画面とサーバーの版が食い違う事故): Cache-Control: no-store
- 想定外の外部読み込み/埋め込み: Content-Security-Policy, X-Content-Type-Options, frame-ancestors
単一スレッドのTCPServerではなくThreadingHTTPServerを使い、1接続の停滞でUIが止まらないようにします。
"""

import http.server
import logging
import threading
from typing import Any, Optional, Set

from backend.constants import UI_HTTP_PORT

logger = logging.getLogger("IGMP-FLOW.StaticServer")

# 許可する外部配信元は、トポロジ描画(vis-network)とアイコンフォントのCDNのみ。
# WebSocketはポート指定(-p)で変わるため、ポートはワイルドカードで許可し、ホストはローカルに限定する
CSP = (
    "default-src 'self'; "
    "script-src 'self' https://unpkg.com; "
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
    "font-src https://cdnjs.cloudflare.com; "
    "img-src 'self' data:; "
    "connect-src 'self' ws://localhost:* ws://127.0.0.1:*; "
    "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class UiRequestHandler(http.server.SimpleHTTPRequestHandler):
    """UI用の静的ファイルハンドラ(読み取り専用・ローカルのみ)。"""

    def _host_allowed(self) -> bool:
        allowed: Set[str] = getattr(self.server, "allowed_hosts", set())
        return (self.headers.get("Host") or "").lower() in allowed

    def do_GET(self) -> None:  # noqa: N802 (標準ライブラリの命名)
        if not self._host_allowed():
            self.send_error(403, "Forbidden host")
            return
        super().do_GET()

    def do_HEAD(self) -> None:  # noqa: N802
        if not self._host_allowed():
            self.send_error(403, "Forbidden host")
            return
        super().do_HEAD()

    def list_directory(self, path: Any) -> None:
        """ディレクトリ一覧は返さない。"""
        self.send_error(404, "Not found")
        return None

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        super().end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        """アクセスログは出さない(コンソールを汚さないため)。"""


class _UiServer(http.server.ThreadingHTTPServer):
    """SO_REUSEADDRを無効にしたサーバー。

    WindowsではSO_REUSEADDRを付けると、使用中のポートへ別プロセスが同時にbindでき(ポート乗っ取り)、
    二重起動の検出も働かなくなる。標準の既定(有効)を明示的に打ち消す。
    """

    allow_reuse_address = False


def start_ui_server(
    directory: str, port: int = UI_HTTP_PORT, host: str = "127.0.0.1"
) -> Optional[http.server.ThreadingHTTPServer]:
    """UI配信サーバーを別スレッドで起動します。

    Args:
        directory (str): 配信するフロントエンドのディレクトリ。
        port (int): 待ち受けポート(0で空きポートを自動割当)。
        host (str): 待ち受けホスト。ローカル以外を指定しないこと。

    Returns:
        Optional[ThreadingHTTPServer]: 起動したサーバー。ポート使用中などで起動できない場合は None。
    """
    handler = lambda *a, **kw: UiRequestHandler(*a, directory=directory, **kw)  # noqa: E731
    try:
        server = _UiServer((host, port), handler)
    except OSError as e:
        logger.warning("UI用HTTPサーバーを起動できませんでした(ポート %s): %s", port, e)
        return None
    server.daemon_threads = True
    actual = server.server_address[1]
    server.allowed_hosts = {f"localhost:{actual}", f"127.0.0.1:{actual}"}  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, name="ui-http", daemon=True).start()
    return server
