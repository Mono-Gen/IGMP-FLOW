"""IGMP-FLOW リアルタイムWebSocketサーバー (websocket_server.py)

バックエンドのパケット解析スレッドから届くイベントを、接続中のブラウザへ非同期で配信します。

UI負荷を抑えつつ全件はPCAPに残す方針のため、配信側で次の制御を行います:
- クライアント別フィルタ (`set_filter`): プロトコル/テキスト一致/データ面の個別配信可否
- データ面(音声等)は個別パケットを送らず、1秒集計の `flow_stats` のみ送る(raw_data指定時のみ個別配信)
- クライアント別レート上限: 超過分は破棄し、件数を `suppressed` 通知で知らせる(IGMPイベントは対象外)
- 「PCAP→CSVエクスポート」「NIC切替」など時間のかかる処理はイベントループを塞がないよう別スレッドで実行
"""

import asyncio
import json
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import websockets
from websockets.server import WebSocketServerProtocol

from backend.constants import (
    FILTER_TEXT_MAX_LEN,
    PLANE_DATA,
    UI_HTTP_PORT,
    UI_MAX_EVENTS_PER_SECOND,
    WS_MAX_MESSAGE_BYTES,
)

# Originヘッダを持たない接続(ブラウザ以外のクライアント/テスト)は許可し、ブラウザからの接続は
# 本ツール自身のUI(localhost/127.0.0.1)のOriginに限定する。ブラウザは必ずOriginを付けるため、
# 他サイトのページ(悪意あるWebサイト)からの接続(Cross-Site WebSocket Hijacking)は拒否される
def default_allowed_origins(http_port: int = UI_HTTP_PORT) -> List[Optional[str]]:
    """WebSocket接続を許可するOriginの既定リスト(None=Originなし)を返します。"""
    return [None, f"http://localhost:{http_port}", f"http://127.0.0.1:{http_port}"]

# デバッグ用ロガー設定 (標準出力)
logger = logging.getLogger("IGMP-FLOW.WebSocket")
logger.setLevel(logging.INFO)

# レート制限の対象外とするプロトコル(状態整合性のため欠落させない)
_RATE_EXEMPT_PROTOS = {"IGMP"}


class ClientState:
    """接続クライアントごとのフィルタ条件とレート制限の状態。"""

    def __init__(self) -> None:
        self.protos: Optional[set] = None  # None=全プロトコル。PTPは "PTPv1"/"PTPv2" で別々に指定する
        self.ptp_types: Optional[set] = None  # PTPのメッセージ種別(Sync/Announce等)。None=全種別
        self.text: str = ""
        self.raw_data: bool = False
        self.tokens: float = float(UI_MAX_EVENTS_PER_SECOND)
        self.last_refill: float = time.monotonic()
        self.suppressed: int = 0

    def set_filter(self, spec: Dict[str, Any]) -> None:
        """UIから届いたフィルタ指定を反映します。"""
        # 外部入力のため型を検証する(文字列以外やリスト以外は無視)。巨大な指定でメモリを使わせないよう長さも制限
        protos = spec.get("protos")
        self.protos = {p for p in protos[:64] if isinstance(p, str)} if isinstance(protos, list) else None
        ptp_types = spec.get("ptp_types")
        self.ptp_types = (
            {p for p in ptp_types[:64] if isinstance(p, str)} if isinstance(ptp_types, list) and ptp_types else None
        )
        self.text = str(spec.get("text", ""))[:FILTER_TEXT_MAX_LEN].strip().lower()
        self.raw_data = bool(spec.get("raw_data", False))

    def matches(self, data: Dict[str, Any], is_flow: bool = False) -> bool:
        """イベント/フロー統計がこのクライアントのフィルタに合致するか判定します。"""
        # filter_key があればそれで判定(PTPv1/PTPv2を区別)。無ければ proto
        if self.protos is not None and data.get("filter_key", data.get("proto")) not in self.protos:
            return False
        if self.ptp_types is not None and data.get("proto") == "PTP" and data.get("ptp_msg_type") not in self.ptp_types:
            return False
        if self.text:
            hay = " ".join(
                str(data.get(k, "")) for k in ("src_ip", "src_mac", "group_ip", "resolved_name", "tag")
            ).lower()
            vlan = data.get("vlan")
            if self.text not in hay and (vlan is None or self.text != f"vlan {vlan}"):
                return False
        return True

    def allow_rate(self, proto: str) -> bool:
        """トークンバケットによる送信可否。IGMPなど対象外プロトコルは常に許可。"""
        if proto in _RATE_EXEMPT_PROTOS:
            return True
        now = time.monotonic()
        self.tokens = min(
            float(UI_MAX_EVENTS_PER_SECOND),
            self.tokens + (now - self.last_refill) * UI_MAX_EVENTS_PER_SECOND,
        )
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        self.suppressed += 1
        return False


class WebSocketServer:
    """非同期WebSocketサーバーを管理し、パケットキャプチャスレッドからフロントエンドUIへデータを中継するクラス。"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8765,
        on_get_nics: Optional[Callable[[], Dict[str, Any]]] = None,
        on_change_nic: Optional[Callable[[int], str]] = None,
        on_export: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        on_get_status: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        on_set_capture: Optional[Callable[[bool], bool]] = None,
        on_reset: Optional[Callable[[], None]] = None,
        on_shutdown: Optional[Callable[[], None]] = None,
        allowed_origins: Optional[List[Optional[str]]] = None,
    ) -> None:
        """WebSocketサーバーの初期化。

        Args:
            host (str): 待ち受けホストIP（デフォルトはローカルホスト）。
            port (int): 待ち受けポート番号。
            on_get_nics: 利用可能なNICリストを取得するコールバック。
            on_change_nic: 指定したインデックスのNICに切り替えるコールバック。
            on_export: CSVエクスポート要求(パラメータ辞書)を処理するコールバック。結果辞書を返す。
            on_get_status: 接続直後に送る状態通知(capture_status / querier_status 等)のリストを返すコールバック。
            on_set_capture: キャプチャの停止/開始要求(True=開始)を処理し、結果の実行状態を返すコールバック。
            on_reset: 監視状態のやり直し(クエリア/PTP監視の初期化・PCAPの新ファイル化)を行うコールバック。
        """
        self.on_set_capture = on_set_capture
        self.on_reset = on_reset
        self.on_shutdown = on_shutdown  # UIの「終了」要求。アプリ全体を停止する
        self.allowed_origins = allowed_origins if allowed_origins is not None else default_allowed_origins()
        self.host = host
        self.port = port
        self.on_get_nics = on_get_nics
        self.on_change_nic = on_change_nic
        self.on_export = on_export
        self.on_get_status = on_get_status
        self._clients: Dict[WebSocketServerProtocol, ClientState] = {}
        self._clients_lock = threading.Lock()

        # 非同期イベントループとバックグラウンドスレッドの制御変数
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._server: Optional[Any] = None

    # ------------------------------------------------------------------
    # クライアント接続ハンドラ
    # ------------------------------------------------------------------

    async def _send_json(self, websocket: WebSocketServerProtocol, payload: Dict[str, Any]) -> None:
        await websocket.send(json.dumps(payload, ensure_ascii=False))

    async def _handle_command(self, websocket: WebSocketServerProtocol, state: ClientState, cmd: Dict[str, Any]) -> None:
        """クライアントからのコマンドを処理します。"""
        action = cmd.get("action")
        loop = asyncio.get_running_loop()

        if action == "set_filter":
            state.set_filter(cmd)
            return

        if action == "set_capture" and self.on_set_capture:
            # 停止待ち(join)でイベントループを塞がないよう別スレッドで実行。結果は呼び出し側がbroadcastする
            try:
                await loop.run_in_executor(None, self.on_set_capture, bool(cmd.get("running")))
            except Exception as e:
                logger.error(f"キャプチャ切替に失敗しました: {e}")
                await self._send_json(websocket, {"type": "capture_error", "error": str(e)})
            return

        if action == "shutdown" and self.on_shutdown:
            logger.info("UIから終了要求を受信しました。")
            self.on_shutdown()
            return

        if action == "reset_state" and self.on_reset:
            await loop.run_in_executor(None, self.on_reset)
            return

        if action == "change_nic" and self.on_change_nic:
            nic_idx = cmd.get("nic_index")
            if nic_idx is None:
                return
            logger.info(f"UIからNIC切り替え要求を受信: インデックス {nic_idx}")
            # 停止待ちでイベントループを塞がないよう別スレッドで実行
            new_name = await loop.run_in_executor(None, self.on_change_nic, nic_idx)
            await self._send_json(websocket, {"type": "nic_changed", "status": "success", "active_nic": new_name})
            return

        if action == "export_csv" and self.on_export:
            try:
                result = await loop.run_in_executor(None, self.on_export, cmd)
                await self._send_json(websocket, {"type": "export_done", "ok": True, **result})
            except Exception as e:
                logger.error(f"CSVエクスポートに失敗しました: {e}")
                await self._send_json(websocket, {"type": "export_done", "ok": False, "error": str(e)})

    async def _handler(self, websocket: WebSocketServerProtocol) -> None:
        """クライアント接続時のハンドラ。クライアントの登録と切断のライフサイクルを管理します。

        Args:
            websocket (WebSocketServerProtocol): 接続されたクライアント。
        """
        state = ClientState()
        with self._clients_lock:
            self._clients[websocket] = state
            count = len(self._clients)
        logger.info(f"新しいUIクライアントが接続されました: {websocket.remote_address} (現在の接続数: {count})")

        # 接続時に、NIC一覧と現在の状態通知(PCAP記録状況/クエリア状態)を自動プッシュ
        loop = asyncio.get_running_loop()
        try:
            if self.on_get_nics:
                nics_info = await loop.run_in_executor(None, self.on_get_nics)
                await self._send_json(websocket, {
                    "type": "nic_list",
                    "nics": nics_info.get("nics", []),
                    "active_index": nics_info.get("active_index", -1),
                })
            if self.on_get_status:
                for msg in self.on_get_status():
                    await self._send_json(websocket, msg)
        except Exception as e:
            logger.error(f"初期状態のフロントエンド送信エラー: {e}")

        try:
            async for message in websocket:
                try:
                    cmd = json.loads(message)
                    if not isinstance(cmd, dict):
                        continue  # コマンドはJSONオブジェクトのみ
                    await self._handle_command(websocket, state, cmd)
                except json.JSONDecodeError:
                    logger.warning("不正なJSONメッセージを受信したため無視しました。")
                except Exception as e:
                    logger.error(f"受信メッセージの処理中に例外が発生しました: {e}")
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            with self._clients_lock:
                self._clients.pop(websocket, None)
                count = len(self._clients)
            logger.info(f"UIクライアントが切断されました: {websocket.remote_address} (現在の接続数: {count})")

    # ------------------------------------------------------------------
    # サーバーのライフサイクル
    # ------------------------------------------------------------------

    def _start_loop(self) -> None:
        """バックグラウンドスレッド用の非同期イベントループを開始し、WebSocketサーバーを起動します。"""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def start_server() -> None:
            self._server = await websockets.serve(
                self._handler, self.host, self.port,
                origins=self.allowed_origins, max_size=WS_MAX_MESSAGE_BYTES,
            )
            logger.info(f"WebSocket サーバーが起動しました: ws://{self.host}:{self.port}")

        self._loop.run_until_complete(start_server())
        try:
            self._loop.run_forever()
        finally:
            # 停止後に残るタスク(accept待ち等)を取り消して完了を待ち、ループを閉じる。
            # これを怠ると終了時に "Task was destroyed but it is pending!" が出る
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self._loop.close()

    def start(self) -> None:
        """WebSocket サーバーをバックグラウンドスレッドで非同期起動します。"""
        self._thread = threading.Thread(target=self._start_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """WebSocket サーバーおよびイベントループを安全に停止します。"""
        if not (self._loop and self._loop.is_running()):
            return

        async def shutdown() -> None:
            # 1. クライアント接続を閉じ、2. サーバーを閉じて完了まで待つ(ループを止める前に済ませる)
            clients = [c for c, _ in self._snapshot_clients()]
            if clients:
                await asyncio.gather(*(c.close() for c in clients), return_exceptions=True)
            if self._server:
                self._server.close()
                await self._server.wait_closed()

        try:
            asyncio.run_coroutine_threadsafe(shutdown(), self._loop).result(timeout=5.0)
        except Exception as e:
            logger.warning(f"WebSocketサーバーの終了処理が完了しませんでした: {e}")

        # 3. ループを止める(残タスクの後始末は _start_loop 側)
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("WebSocket サーバーを正常に停止しました。")

    # ------------------------------------------------------------------
    # 配信 (キャプチャスレッドから呼ばれる。すべてスレッドセーフ)
    # ------------------------------------------------------------------

    def _snapshot_clients(self) -> List[Any]:
        """ロックを保持したままawaitしないよう、クライアント一覧のコピーを取る。"""
        with self._clients_lock:
            return list(self._clients.items())

    async def _safe_send(self, client: WebSocketServerProtocol, message: str) -> None:
        """1クライアントへ送信。失敗(切断済み等)は握りつぶさず debug に残し、接続ハンドラ側の終了処理に任せる。"""
        try:
            await client.send(message)
        except Exception as e:
            logger.debug(f"クライアント送信に失敗しました(切断済みの可能性): {e}")

    async def _async_send_event(self, data: Dict[str, Any]) -> None:
        """パケットイベントを、各クライアントのフィルタ/レート上限を適用して配信します。"""
        message: Optional[str] = None
        hidden_message: Optional[str] = None
        tasks = []
        is_data = data.get("plane") == PLANE_DATA
        for client, state in self._snapshot_clients():
            if is_data and not state.raw_data:
                continue  # データ面は flow_stats で配信
            matched = state.matches(data)
            if not matched and data.get("proto") != "IGMP":
                continue
            if not state.allow_rate(data.get("proto", "")):
                continue
            if matched:
                if message is None:
                    message = json.dumps(data, ensure_ascii=False)
                tasks.append(self._safe_send(client, message))
            else:
                # 図(受信者・グループ)の更新にだけ使い、ログには出さない
                if hidden_message is None:
                    hidden_message = json.dumps({**data, "log": False}, ensure_ascii=False)
                tasks.append(self._safe_send(client, hidden_message))
        if tasks:
            await asyncio.gather(*tasks)

    async def _async_send_stats(self, flows: List[Dict[str, Any]], interval_s: float) -> None:
        """フロー統計を配信し、レート制限で破棄した件数も通知します。

        図は送信元と受信者の全体から描くため全件を送り、各フローにフィルタへの一致(match)を付ける。
        Stream stats の表は match が True のものだけを表示する。
        """
        tasks = []
        for client, state in self._snapshot_clients():
            marked = [{**f, "match": state.matches(f, is_flow=True)} for f in flows]
            payload = json.dumps(
                {"type": "flow_stats", "interval_s": interval_s, "flows": marked}, ensure_ascii=False
            )
            tasks.append(self._safe_send(client, payload))
            if state.suppressed:
                notice = json.dumps({"type": "suppressed", "count": state.suppressed})
                state.suppressed = 0
                tasks.append(self._safe_send(client, notice))
        if tasks:
            await asyncio.gather(*tasks)

    async def _async_broadcast(self, message_str: str) -> None:
        """全クライアントへフィルタなしで一斉送信します(状態通知用)。"""
        tasks = [self._safe_send(c, message_str) for c, _ in self._snapshot_clients()]
        if tasks:
            await asyncio.gather(*tasks)

    def _schedule(self, coro: Any) -> None:
        if not self._loop or not self._loop.is_running():
            coro.close()
            return
        asyncio.run_coroutine_threadsafe(coro, self._loop)

    def send_event(self, data: Dict[str, Any]) -> None:
        """パケット解析スレッドから呼び出し、接続中クライアントへ状態遷移データを安全に送信します（スレッドセーフ）。

        Args:
            data (Dict[str, Any]): フロントエンドに送信する辞書データ。
        """
        self._schedule(self._async_send_event(data))

    def send_flow_stats(self, flows: List[Dict[str, Any]], interval_s: float) -> None:
        """データ面フロー統計(1秒集計)を配信します。"""
        self._schedule(self._async_send_stats(flows, interval_s))

    def broadcast(self, data: Dict[str, Any]) -> None:
        """状態通知(capture_status / querier_status 等)を全クライアントへ送信します。"""
        self._schedule(self._async_broadcast(json.dumps(data, ensure_ascii=False)))

    @property
    def wants_raw_data(self) -> bool:
        """データ面パケットの個別配信を要求しているクライアントが1つでもいるか。"""
        with self._clients_lock:
            return any(s.raw_data for s in self._clients.values())

    @property
    def client_count(self) -> int:
        """現在接続中のクライアント件数を取得します。"""
        with self._clients_lock:
            return len(self._clients)
