"""IGMP-FLOW メイン統合プロセス (main.py)

IGMP-FLOW バックエンドの各パーツ(パケット解析、mDNS解決、PCAP記録、フロー集計、クエリア監視、
CSVロギング、WebSocketサーバー)を統合し、NICの選択・キャプチャ制御・シャットダウンを行う
アプリケーションのエントリーポイントです。

データの流れ:
  パケット → PCAP(全件。データ面はヘッダのみ) ┐
           → 解析 → 制御面: UIへ個別配信 / ライブCSV(IGMPのみ既定) / クエリア監視
                  → データ面: 1秒集計してUIへ配信
全件の証跡はPCAPが担い、CSVは `backend.pcap_export` でPCAPから生成します。
"""

import argparse
import socket
import sys
import time
import threading
import webbrowser
from typing import Any, Dict, List, Optional, Set

# Scapyのインポート確認
try:
    from scapy.all import AsyncSniffer, Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from backend.close_prompt import ask_exit_on_close
from backend.constants import (
    APP_VERSION,
    CLOSE_PROMPT_GRACE_SECONDS,
    DEFAULT_CAPTURE_DIR,
    DEFAULT_EXPORT_DIR,
    DEFAULT_LOG_DIR,
    NPCAP_DOWNLOAD_URL,
    PLANE_DATA,
    UI_AGGREGATE_INTERVAL_SECONDS,
    UI_HTTP_PORT,
)
from backend.dns_resolver import DNSResolver
from backend.flow_aggregator import FlowAggregator
from backend.logger_manager import LoggerManager
from backend.nic_manager import choose_default_nic, choose_nic_interactive, list_nics, own_addresses
from backend.packet_analyzer import PacketAnalyzer, check_npcap_installed
from backend.paths import frontend_dir, is_cloud_synced_path
from backend.pcap_export import export_captures, parse_local_datetime, DATA_MODES
from backend.pcap_recorder import PcapRecorder
from backend.ptp_monitor import PtpMonitor
from backend.querier_monitor import QuerierMonitor
from backend.static_server import start_ui_server
from backend.websocket_server import WebSocketServer

# キャプチャフィルタ(BPF): IGMP、IPv4マルチキャスト全般、ARP(IP-MAC学習用)
# ユニキャストのUDP(Dante音声のユニキャスト等)は本ツールの対象外のため取得しない
CAPTURE_BPF = "igmp or ip multicast or arp"

# 端末が送るIGMP Report由来のイベント(Join/Leave等)。Report可視性の診断に数える
IGMP_REPORT_EVENT_CODES = frozenset({"igmp_join", "igmp_leave", "igmp_source_update", "igmp_report_unparsed"})

# 状態通知(capture_status / querier_status)を定期配信する間隔(秒)
STATUS_BROADCAST_INTERVAL_SECONDS = 5.0

LIVE_CSV_MODES = ("igmp", "all", "off")


class IGMPFlowApp:
    """IGMP-FLOWの各コンポーネントを統合し、ライフサイクル全体を制御するメインアプリケーションクラス。"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        ws_port: int = 8765,
        log_dir: str = DEFAULT_LOG_DIR,
        capture_dir: str = DEFAULT_CAPTURE_DIR,
        export_dir: str = DEFAULT_EXPORT_DIR,
        enable_pcap: bool = True,
        live_csv: str = "igmp",
        close_prompt: bool = True,
    ) -> None:
        """アプリケーション全体の初期化。

        Args:
            host (str): WebSocketサーバーのホストIP。
            ws_port (int): WebSocketサーバーのポート。
            log_dir (str): ライブCSVログの出力先ディレクトリ。
            capture_dir (str): PCAPの保存先ディレクトリ。
            export_dir (str): CSVエクスポートの出力先ディレクトリ。
            enable_pcap (bool): Falseの場合PCAP記録を行わない(全件の証跡が残らないため非推奨)。
            live_csv (str): ライブCSVの対象。"igmp"(IGMPイベントのみ) / "all"(制御面全て) / "off"。
        """
        if live_csv not in LIVE_CSV_MODES:
            raise ValueError(f"live_csv must be one of {LIVE_CSV_MODES}: {live_csv}")

        self.analyzer = PacketAnalyzer()
        self.resolver = DNSResolver()
        self.logger_manager = LoggerManager(log_dir=log_dir)
        self.recorder: Optional[PcapRecorder] = PcapRecorder(capture_dir=capture_dir) if enable_pcap else None
        self.aggregator = FlowAggregator()
        self.querier_monitor = QuerierMonitor()
        self.ptp_monitor = PtpMonitor()
        self.capture_dir = capture_dir
        self.export_dir = export_dir
        self.live_csv = live_csv

        self.active_interface: Optional[str] = None
        self._sniff_running = False
        self._sniffer: Optional[Any] = None
        self._interfaces_cache: List[Dict[str, Any]] = []
        self._state_lock = threading.Lock()

        # WebSocketサーバー初期化 (動的NIC切り替え・エクスポート・状態通知のコールバックをバインド)
        self.ws_server = WebSocketServer(
            host=host,
            port=ws_port,
            on_get_nics=self.get_nics_list_info,
            on_change_nic=self.change_interface_dynamic,
            on_export=self.export_csv_request,
            on_get_status=self.get_status_messages,
            on_set_capture=self.set_capture_running,
            on_reset=self.reset_state,
            on_shutdown=self.request_shutdown,
        )
        self._running = False
        self._ticker_thread: Optional[threading.Thread] = None

        # 終了制御: UIの「終了」/切断ダイアログの「はい」で _stop_event が立つとメインループを抜けて後始末する
        self._stop_event = threading.Event()
        self._shutting_down = False
        # ブラウザ切断時の終了確認(一度でも接続があり、全クライアントが猶予時間を超えて不在のとき1回だけ)
        self.close_prompt = close_prompt
        self._had_client = False
        self._zero_since: Optional[float] = None
        self._prompted = False
        self.ws_port = ws_port

    # ------------------------------------------------------------------
    # NIC管理
    # ------------------------------------------------------------------

    def get_nics_list_info(self) -> Dict[str, Any]:
        """現在利用可能な全NICの情報をスレッド安全に収集し、WebSocketサーバー用に返します。"""
        with self._state_lock:
            try:
                nics, active_idx = list_nics(self.active_interface)
            except Exception as e:
                print(f"[警告] NIC情報の動的取得中にエラーが発生しました: {e}", file=sys.stderr)
                nics, active_idx = [], -1
            self._interfaces_cache = nics
            return {"nics": nics, "active_index": active_idx}

    def change_interface_dynamic(self, nic_index: int) -> str:
        """UIからの切り替え要求を受けて、キャプチャを安全停止 ➔ 各種キャッシュ初期化 ➔ 新NICで再起動します。"""
        with self._state_lock:
            target_nic = next((n for n in self._interfaces_cache if n["index"] == nic_index), None)
            if not target_nic:
                raise ValueError(f"Invalid interface index: {nic_index}")

            target_guid = target_nic["guid"]
            target_name = target_nic["name"]
            print(f"\n[NIC-CHANGE] 監視NICの動的切り替え要求を受信: {target_name}")

            # 1. 現在のキャプチャを安全に停止
            self._stop_sniffing_unlocked()

            # 2. mDNS解決・クエリア監視・集計を初期化し、PCAPも新ファイルへ切り替える(NICごとに証跡を分ける)
            self.resolver.clear_cache()
            self.querier_monitor.reset()
            self.ptp_monitor.reset()
            self.aggregator.drain(1.0)
            if self.recorder:
                self.recorder.rotate()
            print("[NIC-CHANGE] 解決キャッシュ・クエリア監視をクリアしました。")

            # 3. 新インターフェースを設定して再始動
            self.active_interface = target_guid
            self._start_sniffing_unlocked()
            self.ws_server.broadcast(self.capture_state_message())

            return target_name

    def select_default_interface(self) -> str:
        """IPが割り当てられているアクティブNICを、既定のキャプチャ対象として自動選定します。"""
        return choose_default_nic(self.get_nics_list_info().get("nics", []))

    def select_network_interface_interactive(self) -> Optional[str]:
        """NICの一覧を表示し、ユーザーにコンソールで選択させます。"""
        if not SCAPY_AVAILABLE:
            print("[エラー] Scapy が正しくロードされていません。")
            return None
        return choose_nic_interactive(self.get_nics_list_info().get("nics", []))

    # ------------------------------------------------------------------
    # パケット処理
    # ------------------------------------------------------------------

    def _write_live_csv(self, event_data: Dict[str, Any], resolved_name: Optional[str]) -> None:
        """設定に応じてライブCSVへ書き込む(既定はIGMPイベントのみ。全件はPCAPに残る)。"""
        if self.live_csv == "off":
            return
        if self.live_csv == "igmp" and event_data["proto"] != "IGMP":
            return
        self.logger_manager.write_log(
            event=event_data["event"],
            src_ip=event_data["src_ip"],
            src_mac=event_data.get("src_mac", ""),
            group_ip=event_data.get("group_ip", ""),
            resolved_name=resolved_name,
        )

    def _packet_callback(self, packet: Packet) -> None:
        """スニッフィングしたパケットを処理するコールバック関数。

        1. mDNSから機器名を学習  2. 解析  3. PCAPへ全件記録  4. 制御面は個別配信/データ面は集計

        Args:
            packet (Packet): スニフィングされた実パケット。
        """
        try:
            self.resolver.update_from_packet(packet)
            events = self.analyzer.decode_packet_events(packet)

            # 全件記録。データ面(音声等)のみのパケットはヘッダ部分だけを保存して容量を抑える
            if self.recorder:
                truncate = bool(events) and all(e["plane"] == PLANE_DATA for e in events)
                self.recorder.submit(packet, truncate)

            for event_data in events:
                src_ip = event_data.get("src_ip", "")

                if event_data["plane"] == PLANE_DATA:
                    self.aggregator.add(event_data)
                    # 個別配信を要求しているUIクライアントがいる場合のみ送る(無駄なJSON化を避ける)
                    if self.ws_server.wants_raw_data:
                        resolved = self.resolver.resolve(src_ip)
                        if resolved:
                            event_data["resolved_name"] = resolved
                        self.ws_server.send_event(event_data)
                    continue

                resolved_name = self.resolver.resolve(src_ip)
                if resolved_name:
                    event_data["resolved_name"] = resolved_name

                if event_data.get("is_querier"):
                    self.querier_monitor.observe_query(
                        src_ip, event_data.get("src_mac", ""), event_data.get("version", 0),
                        general=event_data.get("event_code") == "igmp_query",
                    )
                elif event_data.get("event_code") in IGMP_REPORT_EVENT_CODES:
                    self.querier_monitor.observe_report(src_ip, event_data.get("src_mac", ""))

                if event_data["proto"] == "PTP":
                    self.ptp_monitor.observe(event_data)

                self._write_live_csv(event_data, resolved_name)
                self.ws_server.send_event(event_data)

                device_display = f"{resolved_name} ({src_ip})" if resolved_name else src_ip
                tag_suffix = f" | Tag: {event_data['tag']}" if "tag" in event_data else ""
                print(f"* [{event_data['proto']}] {event_data['event']} - 機器: {device_display} -> 宛先: {event_data['group_ip']}{tag_suffix}")

        except Exception as e:
            # バックグラウンドスレッドの強制終了を防ぐため、エラーはキャッチして出力のみ
            print(f"[警告] パケット処理エラー: {e}", file=sys.stderr)

    def _start_sniffing_unlocked(self) -> None:
        """キャプチャを開始します（ロック取得済み前提）。"""
        if self._sniff_running:
            return
        # 自分のReportを他の端末のReportと数えないよう、キャプチャNICのアドレスを監視器へ渡す
        self.querier_monitor.set_own_addresses(*own_addresses(self.active_interface))
        self._sniffer = AsyncSniffer(
            iface=self.active_interface,
            prn=self._packet_callback,
            filter=CAPTURE_BPF,
            store=False,
        )
        self._sniffer.start()
        self._sniff_running = True
        print(f"[INFO] キャプチャを開始しました (NIC: {self.active_interface})")

    def _stop_sniffing_unlocked(self) -> None:
        """キャプチャを安全停止します（ロック取得済み前提）。パケットが来ない状態でも停止できます。"""
        if not self._sniff_running:
            return
        self._sniff_running = False
        sniffer, self._sniffer = self._sniffer, None
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as e:
                # 既に停止済み・起動失敗(NIC不正等)の場合にも到達する
                print(f"[警告] キャプチャ停止時の例外: {e}", file=sys.stderr)
        print("[INFO] 旧キャプチャが停止しました。")

    # ------------------------------------------------------------------
    # 状態通知・集計配信・エクスポート
    # ------------------------------------------------------------------

    def request_shutdown(self, delay_s: float = 0.5) -> None:
        """アプリ全体の終了を要求します(UIの「終了」/切断ダイアログの「はい」)。

        UIへ終了予定を通知して再接続ループを止めさせてから、メインループを抜けて通常のシャットダウン
        (キャプチャ停止→PCAPを書き切って閉じる→WebSocket停止)を実行します。

        Args:
            delay_s (float): 通知がUIへ届くのを待つ秒数。
        """
        if self._shutting_down:
            return
        self._shutting_down = True
        self.ws_server.broadcast({"type": "shutting_down"})
        if delay_s > 0:
            threading.Timer(delay_s, self._stop_event.set).start()
        else:
            self._stop_event.set()

    def _run_close_prompt(self) -> None:
        """終了確認ダイアログを表示し、「はい」なら終了を要求します(ブロックするため専用スレッドで実行)。"""
        if ask_exit_on_close():
            self.request_shutdown()

    def _check_close_prompt(self) -> None:
        """ブラウザが全て閉じられた状態が猶予時間を超えたら、終了確認ダイアログを1回だけ出します。"""
        if not self.close_prompt or self._shutting_down:
            return
        if self.ws_server.client_count > 0:
            self._had_client = True
            self._zero_since = None
            self._prompted = False  # 再接続されたら、次に閉じたときにまた確認できるようにする
            return
        if not self._had_client or self._prompted:
            return
        now = time.monotonic()
        if self._zero_since is None:
            self._zero_since = now
            return
        if now - self._zero_since >= CLOSE_PROMPT_GRACE_SECONDS:
            self._prompted = True
            threading.Thread(target=self._run_close_prompt, name="close-prompt", daemon=True).start()

    def _already_running(self) -> bool:
        """同じWebSocketポートで既にIGMP-FLOWが待ち受けているか(二重起動)を判定します。"""
        try:
            with socket.create_connection(("127.0.0.1", self.ws_port), timeout=0.5):
                return True
        except OSError:
            return False

    def capture_state_message(self) -> Dict[str, Any]:
        """キャプチャの実行状態(動作中/停止中)の通知メッセージを返します。"""
        return {"type": "capture_state", "running": self._sniff_running}

    def set_capture_running(self, running: bool) -> bool:
        """キャプチャを停止/開始します(UIの「キャプチャ停止/開始」)。

        停止中も既存のPCAPは保持されます。開始時は、停止中に古くなった監視状態(クエリア/PTP)を
        初期化して誤警告を防ぎ、PCAPを新しいファイルへ切り替えて停止区間の境目を残します。

        Args:
            running (bool): Trueで開始、Falseで停止。

        Returns:
            bool: 処理後にキャプチャが動作中か。
        """
        with self._state_lock:
            if running and not self._sniff_running:
                if self.active_interface is None:
                    raise ValueError("No capture interface is selected.")
                self.querier_monitor.reset()
                self.ptp_monitor.reset()
                if self.recorder:
                    self.recorder.rotate()
                self._start_sniffing_unlocked()
            elif not running and self._sniff_running:
                self._stop_sniffing_unlocked()
            state = self._sniff_running
        self.ws_server.broadcast(self.capture_state_message())
        return state

    def reset_state(self) -> None:
        """監視状態のやり直し(UIの「リセット」)。

        クエリア/PTP監視と集計を初期化し、PCAPを新しいファイルへ切り替えます(記録済みの内容は消しません)。
        mDNSの機器名キャッシュは再学習に時間がかかるため残します。受動監視のため、トポロジは
        以降に届くQuery/Reportから再構築されます。
        """
        self.querier_monitor.reset()
        self.ptp_monitor.reset()
        self.aggregator.drain(1.0)
        if self.recorder:
            self.recorder.rotate()
        for msg in self.get_status_messages():
            self.ws_server.broadcast(msg)

    def get_status_messages(self) -> List[Dict[str, Any]]:
        """UI接続時/定期配信用の状態通知(PCAP記録状況・クエリア状態)を返します。"""
        messages: List[Dict[str, Any]] = [
            self.capture_state_message(), self.querier_monitor.status(), self.ptp_monitor.status(),
        ]
        if self.recorder:
            messages.append(self.recorder.status())
        else:
            messages.append({"type": "capture_status", "enabled": False})
        return messages

    def _ticker_loop(self) -> None:
        """1秒ごとにデータ面フローを集計配信し、状態通知を定期/変化時に配信するスレッド本体。"""
        last_state: Optional[tuple] = None
        last_status_at = 0.0
        while self._running:
            time.sleep(UI_AGGREGATE_INTERVAL_SECONDS)
            try:
                self._check_close_prompt()
                if not self._sniff_running:
                    # 停止中はクエリア/PTPの「途絶」が誤警告になるため状態通知を送らない(停止状態のみ定期通知)
                    if time.monotonic() - last_status_at >= STATUS_BROADCAST_INTERVAL_SECONDS:
                        last_status_at = time.monotonic()
                        self.ws_server.broadcast(self.capture_state_message())
                    continue

                flows = self.aggregator.drain(UI_AGGREGATE_INTERVAL_SECONDS, self.resolver)
                if flows:
                    self.ws_server.send_flow_stats(flows, UI_AGGREGATE_INTERVAL_SECONDS)

                ptp = self.ptp_monitor.status()
                if ptp["rows"] or ptp["alerts"]:
                    self.ws_server.broadcast(ptp)

                querier = self.querier_monitor.status()
                now = time.monotonic()
                # Report可視性の診断が切り替わった時も、定期配信を待たずにすぐ知らせる
                state_key = (querier["state"], querier["reports_hidden"])
                if state_key != last_state or now - last_status_at >= STATUS_BROADCAST_INTERVAL_SECONDS:
                    last_state = state_key
                    last_status_at = now
                    self.ws_server.broadcast(querier)
                    self.ws_server.broadcast(self.capture_state_message())
                    if self.recorder:
                        self.ws_server.broadcast(self.recorder.status())
            except Exception as e:
                print(f"[警告] 集計/状態配信エラー: {e}", file=sys.stderr)

    def export_csv_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """UIからのCSVエクスポート要求を処理します(PCAP→CSV)。

        Args:
            params (Dict[str, Any]): since/until("YYYY-MM-DD HH:MM:SS"・ローカル時刻), protos, group, src, data_mode。

        Returns:
            Dict[str, Any]: 出力ファイル・行数・警告。
        """
        data_mode = params.get("data_mode", "aggregate")
        if data_mode not in DATA_MODES:
            raise ValueError(f"Invalid data_mode: {data_mode}")
        protos: Optional[Set[str]] = set(params["protos"]) if params.get("protos") else None
        result = export_captures(
            capture_dir=self.capture_dir,
            export_dir=self.export_dir,
            since=parse_local_datetime(params.get("since")),
            until=parse_local_datetime(params.get("until")),
            protos=protos,
            group=str(params.get("group", "")),
            src=str(params.get("src", "")),
            text=str(params.get("text", "")),
            ptp_types=set(params["ptp_types"]) if params.get("ptp_types") else None,
            data_mode=data_mode,
        )
        return {"out": result["out"], "rows": result["rows"], "warnings": result["warnings"]}

    # ------------------------------------------------------------------
    # 起動・停止
    # ------------------------------------------------------------------

    def run(self, interface: Optional[str] = None, interactive: bool = False) -> None:
        """メインアプリケーションを起動し、WebSocketサーバーとキャプチャを開始します。"""
        # Npcapの存在チェック (Windows環境)
        if sys.platform == "win32" and not check_npcap_installed():
            print("\n[ERROR] Npcap（キャプチャドライバ）がインストールされていません。")
            print("本ツールの動作には、ミラーポート等からのパケット取得のため Npcap が必須です。")
            print("以下の公式サイトから Npcap をダウンロードし、インストールしてください。")
            print(f"  配布先URL: {NPCAP_DOWNLOAD_URL}")
            print("=======================================================\n")
            sys.exit(1)

        # 二重起動の防止: 既に起動中なら新しい監視は始めず、既存の画面をブラウザで開くだけにする
        if self._already_running():
            print("[INFO] IGMP-FLOW は既に起動しています。既存の画面をブラウザで開きます。")
            webbrowser.open(f"http://localhost:{UI_HTTP_PORT}/index.html")
            return

        # インターフェース選択
        if interface is not None:
            self.active_interface = interface
        elif interactive:
            self.active_interface = self.select_network_interface_interactive()
        else:
            # ヘッドレス（デフォルト自動選択）
            self.active_interface = self.select_default_interface()

        if self.active_interface is None:
            print("[エラー] キャプチャ対象のインターフェースが選択されなかったため、終了します。")
            sys.exit(1)

        # 各サービスの起動
        print("[START] WebSocket サーバーを起動中...")
        self.ws_server.start()

        if self.recorder:
            if self.recorder.start():
                print(f"[PCAP] 全パケットの記録を開始しました: {self.capture_dir} (データ面はヘッダのみ保存)")
            else:
                print("[警告] PCAP記録を開始できませんでした。全件の証跡は残りません。", file=sys.stderr)

        # 実データ(実在のIP/MAC/機器名)の保存先がクラウド同期フォルダなら、複製されることを警告する
        for label, path in (("PCAP", self.capture_dir), ("log", self.logger_manager.log_dir), ("export", self.export_dir)):
            if is_cloud_synced_path(path):
                print(f"[警告] {label} の保存先がクラウド同期フォルダ内にある可能性があります: {path}\n"
                      "       実データがクラウドへ複製されます。--capture-dir 等または環境変数 IGMP_FLOW_DATA_DIR で変更してください。",
                      file=sys.stderr)

        self._running = True
        self._ticker_thread = threading.Thread(target=self._ticker_loop, name="ui-ticker", daemon=True)
        self._ticker_thread.start()

        with self._state_lock:
            self._start_sniffing_unlocked()

        # UI(静的ファイル)をローカルのみで配信する。ポート使用中の場合は別プロセスのページが開き得るため通知する
        if start_ui_server(frontend_dir()) is None:
            print(f"[警告] UI用HTTPサーバー(ポート {UI_HTTP_PORT})を起動できませんでした。", file=sys.stderr)

        # 自動でブラウザを開いて可視化画面にユーザーを導く
        print("[LAUNCH] 自動的にWebブラウザを起動しています...")
        webbrowser.open(f"http://localhost:{UI_HTTP_PORT}/index.html")

        print(f"[INFO] IGMP-FLOW 監視開始 (NIC: {self.active_interface})...")
        print("    ※ 終了するには Ctrl+C を押してください。\n")

        try:
            # メインプロセスを起動維持（シグナル待機）
            while self._running and not self._stop_event.is_set():
                self._stop_event.wait(1.0)
        except KeyboardInterrupt:
            print("\n[情報] ユーザーの操作によりシャットダウンします。")
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        """すべてのサービスをクリーンアップして安全にシャットダウンします。"""
        if self._running:
            self._running = False
            print("[STOP] 安全なシャットダウン処理を実行中...")
            with self._state_lock:
                self._stop_sniffing_unlocked()
            if self.recorder:
                self.recorder.stop()  # キュー内の残りを書き切ってから閉じる
            self.ws_server.stop()
            print("[SUCCESS] すべてのサービスを正常に停止しました。")


# ==============================================================================
# コマンドライン実行エントリー
# ==============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    """コマンドライン引数パーサーを構築します(app.py と共用)。"""
    parser = argparse.ArgumentParser(description="IGMP-FLOW - real-time IGMP/PTP multicast visualizer and recorder")
    parser.add_argument(
        "-i", "--interface", type=str, default=None,
        help="NIC GUID or device name to capture on. Auto-selected if omitted."
    )
    parser.add_argument(
        "--interactive", action="store_true",
        help="Choose the NIC interactively on the console at startup."
    )
    parser.add_argument(
        "-p", "--port", type=int, default=8765,
        help="WebSocket server port (default: 8765)."
    )
    parser.add_argument(
        "--capture-dir", type=str, default=DEFAULT_CAPTURE_DIR,
        help=f"Directory for PCAP files (default: {DEFAULT_CAPTURE_DIR})."
    )
    parser.add_argument(
        "--no-pcap", action="store_true",
        help="Disable PCAP recording (not recommended: full evidence is not kept)."
    )
    parser.add_argument(
        "--live-csv", choices=LIVE_CSV_MODES, default="igmp",
        help="Live CSV content: igmp = IGMP events only (default) / all = all control-plane events / off = none."
    )
    parser.add_argument("--version", action="version", version=f"IGMP-FLOW {APP_VERSION}")
    parser.add_argument(
        "--no-close-prompt", action="store_true",
        help="Do not show the exit confirmation dialog when the browser is closed (for unattended recording)."
    )
    return parser


def main() -> None:
    """CLIエントリーポイント。"""
    args = build_arg_parser().parse_args()
    app = IGMPFlowApp(
        ws_port=args.port,
        capture_dir=args.capture_dir,
        enable_pcap=not args.no_pcap,
        live_csv=args.live_csv,
        close_prompt=not args.no_close_prompt,
    )
    app.run(interface=args.interface, interactive=args.interactive)


if __name__ == "__main__":
    main()
