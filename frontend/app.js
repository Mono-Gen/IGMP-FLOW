/* IGMP-FLOW フロントエンド・アプリケーションロジック (app.js)
 * 
 * バックエンドのWebSocketサーバーとリアルタイム接続し、
 * 受信したパケット情報をビジュアルなトポロジマップ（vis-network）および
 * ストリーミングログとしてレンダリングします。
 */

// ==============================================================================
// 1. グローバル設定 & 状態変数
// ==============================================================================
const WS_URL = `ws://${window.location.hostname || "127.0.0.1"}:8765`;
let socket = null;
let network = null;

// トポロジ用 DataSet (vis.js がリアクティブに監視する接続オブジェクト)
const nodes = new vis.DataSet();
const edges = new vis.DataSet();

// PTP状態管理は各パケットで独立してトポロジ上に描画されるため、アラートバナー監視は不要

// ==============================================================================
// 2. vis-network トポロジの初期構築
// ==============================================================================
function initTopology() {
    const container = document.getElementById("topology-canvas");
    const data = { nodes: nodes, edges: edges };
    
    // vis-network オプション設定 (プレミアムなデザイン & 自然な動きのシミュレーション)
    const options = {
        nodes: {
            font: {
                color: "#f8fafc",
                size: 14,
                face: "Inter, sans-serif"
            },
            borderWidth: 2,
            shadow: {
                enabled: true,
                color: "rgba(0, 0, 0, 0.4)",
                size: 8,
                x: 0,
                y: 4
            }
        },
        edges: {
            width: 2,
            color: {
                color: "rgba(255, 255, 255, 0.15)",
                highlight: "#3b82f6",
                hover: "#3b82f6"
            },
            arrows: {
                to: { enabled: false }
            },
            smooth: {
                enabled: true,
                type: "cubicBezier",
                roundness: 0.5
            }
        },
        physics: {
            solver: "forceAtlas2Based",
            forceAtlas2Based: {
                gravitationalConstant: -100, // ノード同士が適度に押し合う
                centralGravity: 0.015,
                springLength: 130,          // 接続線の基本の長さ
                springConstant: 0.08
            },
            stabilization: {
                iterations: 150,
                updateInterval: 25
            }
        },
        interaction: {
            hover: true,
            tooltipDelay: 200,
            navigationButtons: false
        }
    };

    network = new vis.Network(container, data, options);

    // Webフォントのロード完了時にトポロジを再描画する(アイコンが文字化けして見えるのを防ぐ)
    if (document.fonts) {
        document.fonts.ready.then(() => {
            console.log("[FONTS] FontAwesomeのロード完了を検知。トポロジを再描画します。");
            if (network) {
                network.redraw();
            }
        });
    }
}

// ==============================================================================
// 3. トポロジノード & エッジの動的アップデート
// ==============================================================================

/**
 * 既知のマルチキャストグループIPと用途タグのマッピング(strings.js)。
 * 音響・映像ネットワーク上の主要なマルチキャスト用途をオペレーターが直感的に識別できるようにします。
 */
const MULTICAST_LABELS = STR.multicastLabels;

/**
 * 指定されたマルチキャストIPアドレスの人間フレンドリーな用途表記およびアイコンを解決します。
 */
function getMulticastGroupLabel(ip) {
    if (MULTICAST_LABELS[ip]) {
        const info = MULTICAST_LABELS[ip];
        return `${ip}\n${info.icon} ${info.tag}`;
    }
    
    // Dante 音声・制御ストリーム範囲
    if (ip.startsWith("239.255.")) {
        return `${ip}\n👥 ${STR.groupDante}`;
    }
    
    // 汎用プライベートマルチキャスト範囲
    if (ip.startsWith("239.")) {
        return `${ip}\n👥 ${STR.groupPrivate}`;
    }
    
    return `${ip}\n👥 ${STR.groupGeneric}`;
}

// アイコン定義マッピング (FontAwesome 6 Unicode)
const ICONS = {
    querier: { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf521", color: "#8b5cf6", size: 45 }, // 👑 (Crown)
    group: { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf500", color: "#10b981", size: 40 },   // 👥 (Users)
    host: { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf109", color: "#3b82f6", size: 36 },     // 💻 (Laptop)
    sync: { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf017", color: "#f59e0b", size: 38 }      // ⏰ (Clock)
};

/**
 * ツールチップ用のDOM要素を作る。機器名はネットワーク上の第三者が決められる値のため、
 * 文字列のままvis-networkへ渡さず、textContentで安全にテキストとして表示する(XSS対策)。
 */
function tooltipElement(text) {
    const el = document.createElement("div");
    el.style.whiteSpace = "pre-wrap";
    el.textContent = text;
    return el;
}

/**
 * トポロジ上にノードを追加・または更新します。
 */
function updateNode(id, label, type, subtitle = "") {
    const exists = nodes.get(id);
    let targetType = type;
    let targetLabel = label;

    // IPアドレスが "0.0.0.0" (IP未割り当てのスイッチ) の場合は分かりやすい表記にする
    if (id === "0.0.0.0") {
        if (targetType === "querier") {
            targetLabel = STR.switchNoIp;
        } else {
            targetLabel = STR.deviceNoIp;
        }
        const macPart = subtitle.includes("MAC: ") ? subtitle.split("MAC: ")[1] : STR.unknown;
        subtitle = STR.noIpSubtitle(macPart);
    }

    // 優先度ガード: クエリアやクロックが後発の一般PCパケットで上書きされるのを防ぐ
    if (exists && exists.customType) {
        if ((exists.customType === "querier" || exists.customType === "sync") && type === "host") {
            targetType = exists.customType;
            targetLabel = exists.label; // 王冠や時計の表示ラベルもキープ
        }
    }

    const iconConfig = ICONS[targetType] || ICONS.host;

    const nodeData = {
        id: id,
        label: targetLabel,
        shape: "icon",
        icon: iconConfig,
        title: tooltipElement(subtitle || targetLabel), // ホバーツールチップ
        customType: targetType // 内部仕分け用タグ
    };

    if (exists) {
        // 既存のノード情報をマージ (IP ➔ mDNS解決名 への昇格時などに実行)
        nodes.update(nodeData);
    } else {
        nodes.add(nodeData);
    }
}

/**
 * トポロジ上のエッジ（接続線）を追加します（重複防止）。
 */
function addEdge(fromId, toId, edgeId, label = "") {
    if (!edges.get(edgeId)) {
        edges.add({
            id: edgeId,
            from: fromId,
            to: toId,
            label: label,
            font: { color: "#94a3b8", size: 10, align: "middle" },
            color: { color: "rgba(59, 130, 246, 0.4)" } // 受信中をブルーネオンで表現
        });
    }
}

/**
 * 特定の接続線またはノードを安全に削除します。
 */
function removeEdge(edgeId) {
    if (edges.get(edgeId)) {
        edges.remove(edgeId);
    }
}

/**
 * 孤立したマルチキャストグループノード（誰も受信していないグループ）を自動お掃除。
 */
function cleanupGroupNodes() {
    const activeNodes = nodes.get({
        filter: (item) => item.customType === "group"
    });

    activeNodes.forEach(groupNode => {
        const connectedEdges = edges.get({
            filter: (edge) => edge.from === groupNode.id || edge.to === groupNode.id
        });
        
        // 接続されている端末が0台になったグループはフェードアウト削除
        if (connectedEdges.length === 0) {
            nodes.remove(groupNode.id);
        }
    });
}

// ==============================================================================
// 4. バックエンドから届くイベントのリアルタイム処理 (メイン)
// ==============================================================================
function handleNetworkEvent(data) {
    const srcIp = data.src_ip;
    const groupIp = data.group_ip;
    const deviceName = data.resolved_name || srcIp;
    
    // MACアドレスの表示補填
    const subtitle = `IP: ${srcIp}\nMAC: ${data.src_mac}`;

    // A. プロトコル別のトポロジ分岐処理
    if (data.proto === "IGMP") {
        
        // A-1. 生存確認（クエリ）
        if (data.is_querier) {
            updateNode(srcIp, `${deviceName}\n${STR.querierTag}`, "querier", subtitle);
        }
        
        // A-2. 受信開始（ジョイン）
        else if (data.event_code === "igmp_join") {
            // 受信端末ノードを追加
            updateNode(srcIp, deviceName, "host", subtitle);
            
            // グループノードを追加（すでにクエリアが存在すれば繋ぐ）
            const groupNodeLabel = getMulticastGroupLabel(groupIp);
            updateNode(groupIp, groupNodeLabel, "group", STR.groupTitle(groupIp));
            
            // エッジを繋ぐ (端末 ➔ グループ)
            const edgeId = `${srcIp}_to_${groupIp}`;
            addEdge(srcIp, groupIp, edgeId);
            
            // 近くにいるクエリアとも自動で薄い線でグループを繋ぎトポロジを紐付ける
            const queriers = nodes.get({ filter: (n) => n.customType === "querier" });
            queriers.forEach(q => {
                const qEdgeId = `${q.id}_to_${groupIp}`;
                addEdge(q.id, groupIp, qEdgeId, "Query");
            });
        }
        
        // A-3. 受信停止（リーブ）
        else if (data.event_code === "igmp_leave") {
            const edgeId = `${srcIp}_to_${groupIp}`;
            removeEdge(edgeId);
            
            // 不要なグループノードのお掃除
            cleanupGroupNodes();
        }
    }
    
    // B. クロック同期 (PTPv1/v2) のトポロジ表示処理
    else if (data.proto === "PTP") {
        // PTP送信元クロック端末を追加
        const ptpTag = data.version === 1 ? "PTPv1 / Dante" : "PTPv2 / AES67";
        updateNode(srcIp, `${deviceName}\n${STR.clockTag(ptpTag)}`, "sync", subtitle);
        
        // 共通同期グループにエッジを紐付け
        updateNode(groupIp, getMulticastGroupLabel(groupIp), "group", STR.ptpGroupTitle(groupIp));
        addEdge(srcIp, groupIp, `${srcIp}_to_${groupIp}`);
    }

    // C. 汎用制御（mDNS, ConMon等）のノード追加表示
    else if (data.tag) {
        updateNode(srcIp, deviceName, "host", subtitle);
    }
}

// NOTE: PTPv1とv2の混在はDante/AES67併用環境で日常的なため、混在警告バナーは設けない。

// ==============================================================================
// 5. 画面ストリーミングログへの動的追加
// ==============================================================================
let logPaused = false;
const pendingLogs = [];
const MAX_PENDING_LOGS = 2000; // 一時停止中に溜める上限(超過分は古い方から捨てる。全件はPCAPに残る)

/** ログ行を追加する。一時停止中は表示せずに溜める。 */
function addStreamingLog(data) {
    if (logPaused) {
        pendingLogs.push(data);
        if (pendingLogs.length > MAX_PENDING_LOGS) pendingLogs.shift();
        updatePauseLabel();
        return;
    }
    renderLogRow(data);
}

function updatePauseLabel() {
    const label = document.getElementById("pause-log-label");
    if (label) label.textContent = logPaused ? STR.resumeLog(pendingLogs.length) : STR.pauseLog;
}

/** ログの一時停止/再開。再開時は溜めた分を順に反映する。 */
function setLogPaused(paused) {
    logPaused = paused;
    const icon = document.querySelector("#btn-pause-log i");
    if (icon) icon.className = paused ? "fa-solid fa-play" : "fa-solid fa-pause";
    if (!paused) {
        pendingLogs.splice(0).forEach(renderLogRow);
    }
    updatePauseLabel();
}

/** ログ表示と待機中のログを消去する。 */
function clearLogView() {
    const tbody = document.getElementById("log-list-body");
    if (tbody) tbody.innerHTML = "";
    pendingLogs.length = 0;
    updatePauseLabel();
}

function renderLogRow(data) {
    // ログ以外のタブを見ている間は、未読の件数をバッジで知らせる
    if (activeTab !== "log") {
        unseenLogs += 1;
        setBadge("badge-log", unseenLogs);
    }
    const tbody = document.getElementById("log-list-body");
    const row = document.createElement("tr");

    // 時刻(パケット自体の記録時刻を優先。無ければ受信時刻)
    const tdTime = document.createElement("td");
    const when = data.ts ? new Date(data.ts * 1000) : new Date();
    tdTime.textContent = when.toLocaleTimeString() + "." + String(when.getMilliseconds()).padStart(3, '0');
    row.appendChild(tdTime);

    // プロトコル
    const tdProto = document.createElement("td");
    tdProto.textContent = data.filter_key || data.proto; // PTPは PTPv1/PTPv2 と表示する
    row.appendChild(tdProto);

    // イベント
    const tdEvent = document.createElement("td");
    tdEvent.textContent = data.event;
    
    // イベント種別ごとの文字色クラス付け
    if (data.event_code === "igmp_join") tdEvent.className = "event-join";
    else if (data.event_code === "igmp_leave") tdEvent.className = "event-leave";
    else if (data.event_code === "igmp_query" || data.event_code === "igmp_query_group") tdEvent.className = "event-query";
    else if (data.proto === "PTP") tdEvent.className = "event-ptp";
    
    row.appendChild(tdEvent);

    // 対象ホスト
    const tdHost = document.createElement("td");
    const deviceDisplay = data.resolved_name ? `${data.resolved_name} (${data.src_ip})` : data.src_ip;
    tdHost.textContent = `${deviceDisplay} [${data.src_mac}]`;
    row.appendChild(tdHost);

    // 対象グループ
    const tdGroup = document.createElement("td");
    tdGroup.textContent = data.group_ip || "---";
    row.appendChild(tdGroup);

    // ログテーブルの先頭に挿入（最新を一番上に表示）
    tbody.insertBefore(row, tbody.firstChild);

    // 画面負荷低減のため、蓄積が100行を超えたら古いログ行を削除
    if (tbody.children.length > 100) {
        tbody.removeChild(tbody.lastChild);
    }
}

// ==============================================================================
// 5b. フィルタ送信・集計/状態表示・CSVエクスポート
//     フィルタはサーバー側で適用される(全パケットはPCAPに記録済み)。
// ==============================================================================

/** 現在のフィルタ条件をUI要素から組み立てる。全プロトコル選択時は protos=null(絞り込みなし)。 */
function collectFilter() {
    const boxes = Array.from(document.querySelectorAll("#filter-protos input[type=checkbox]"));
    const checked = boxes.filter(b => b.checked).map(b => b.value);
    const ptpBoxes = Array.from(document.querySelectorAll("#filter-ptp-types input[type=checkbox]"));
    const ptpChecked = ptpBoxes.filter(b => b.checked).map(b => b.value);
    return {
        action: "set_filter",
        protos: checked.length === boxes.length ? null : checked,
        ptp_types: ptpChecked.length === ptpBoxes.length ? null : ptpChecked,
        text: document.getElementById("filter-text").value,
        raw_data: document.getElementById("filter-raw").checked
    };
}

function sendFilter() {
    if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify(collectFilter()));
    }
}

let noticeTimer = null;
/** 一時的な通知(取りこぼし警告・エクスポート結果など)を表示する。 */
function showNotice(text, level = "ok") {
    const el = document.getElementById("ui-notice");
    el.textContent = text;
    el.className = `status-chip ${level}`;
    el.hidden = false;
    clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => { el.hidden = true; }, 8000);
}

/** データ面(音声等)の1秒集計をテーブルに反映する。 */
function renderFlowStats(flows) {
    const tbody = document.getElementById("flow-list-body");
    if (!tbody) return;
    tbody.innerHTML = "";
    setBadge("badge-flow", flows.length || null);
    flows.slice(0, 50).forEach(f => {
        const row = document.createElement("tr");
        const host = f.resolved_name ? `${f.resolved_name} (${f.src_ip})` : f.src_ip;
        [f.proto, host, f.group_ip, f.pps, (f.bps / 1000).toFixed(0) + " kbps"].forEach(v => {
            const td = document.createElement("td");
            td.textContent = v;
            row.appendChild(td);
        });
        tbody.appendChild(row);
        // 音声を流している送信元をトポロジ上にも端末として出す
        updateNode(f.src_ip, f.resolved_name || f.src_ip, "host", `IP: ${f.src_ip}\nMAC: ${f.src_mac}`);
    });
}

// ------------------------------------------------------------------------------
// 下パネル: タブ切替 / 図との境界ドラッグ / 最大化
// ------------------------------------------------------------------------------
const LOG_HEIGHT_KEY = "igmpflow.logHeight";
const MIN_PANEL_PX = 120;
let activeTab = "log";
let unseenLogs = 0;

/** タブのバッジを表示/非表示にする(value が null/0 なら非表示)。 */
function setBadge(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    if (value) {
        el.textContent = value > 99 ? "99+" : String(value);
        el.hidden = false;
    } else {
        el.hidden = true;
    }
}

function showTab(name) {
    activeTab = name;
    document.querySelectorAll(".panel-tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
    ["log", "ptp", "flow"].forEach(n => {
        const pane = document.getElementById(`pane-${n}`);
        if (pane) pane.hidden = n !== name;
    });
    if (name === "log") {
        unseenLogs = 0;
        setBadge("badge-log", null);
    }
}

/** 図のサイズ変更(境界移動・最大化)後に、トポロジの描画領域を追従させる。 */
function refreshTopologySize() {
    if (network) {
        network.setSize("100%", "100%");
        network.redraw();
    }
}

/** 保存済みの高さ(px)を、現在の領域に収まる範囲へ補正して返す。 */
function clampLogHeight(px, container) {
    const max = container.clientHeight - MIN_PANEL_PX - 14;
    return Math.max(MIN_PANEL_PX, Math.min(px, Math.max(MIN_PANEL_PX, max)));
}

function initPanelLayout() {
    const container = document.querySelector(".main-container");
    const logPanel = document.querySelector(".log-panel");
    const splitter = document.getElementById("splitter");

    document.querySelectorAll(".panel-tab").forEach(t => t.addEventListener("click", () => showTab(t.dataset.tab)));

    // 保存済みの高さを復元(ブラウザの保存が使えない環境でも動作する)
    try {
        const saved = parseInt(localStorage.getItem(LOG_HEIGHT_KEY), 10);
        if (!isNaN(saved)) logPanel.style.setProperty("--log-height", `${clampLogHeight(saved, container)}px`);
    } catch (e) { /* 保存領域が使えない場合は既定の高さのまま */ }

    // 境界のドラッグ(マウス/タッチ共通のPointer Events)
    splitter.addEventListener("pointerdown", (ev) => {
        ev.preventDefault();
        splitter.setPointerCapture(ev.pointerId);
        splitter.classList.add("dragging");
        const onMove = (e) => {
            const rect = container.getBoundingClientRect();
            const bottomPadding = parseFloat(getComputedStyle(container).paddingBottom) || 0;
            const px = clampLogHeight(rect.bottom - bottomPadding - e.clientY - 7, container);
            logPanel.style.setProperty("--log-height", `${px}px`);
        };
        const onUp = () => {
            splitter.classList.remove("dragging");
            splitter.removeEventListener("pointermove", onMove);
            splitter.removeEventListener("pointerup", onUp);
            splitter.removeEventListener("pointercancel", onUp);
            try {
                localStorage.setItem(LOG_HEIGHT_KEY, String(parseInt(logPanel.getBoundingClientRect().height, 10)));
            } catch (e) { /* 保存できなくても動作に影響しない */ }
            refreshTopologySize();
        };
        splitter.addEventListener("pointermove", onMove);
        splitter.addEventListener("pointerup", onUp);
        splitter.addEventListener("pointercancel", onUp);
    });

    // ダブルクリックで初期位置へ
    splitter.addEventListener("dblclick", () => {
        logPanel.style.removeProperty("--log-height");
        try { localStorage.removeItem(LOG_HEIGHT_KEY); } catch (e) { /* 無視 */ }
        refreshTopologySize();
    });

    // 最大化/元に戻す
    document.getElementById("btn-maximize-panel").addEventListener("click", () => {
        const maximized = container.classList.toggle("log-maximized");
        document.getElementById("maximize-label").textContent = maximized ? STR.restore : STR.maximize;
        refreshTopologySize();
    });

    // ウィンドウサイズ変更時も、保存済みの高さが収まるよう補正する
    window.addEventListener("resize", () => {
        const cur = parseFloat(logPanel.style.getPropertyValue("--log-height"));
        if (!isNaN(cur)) logPanel.style.setProperty("--log-height", `${clampLogHeight(cur, container)}px`);
        refreshTopologySize();
    });
}

let shuttingDown = false;

/** アプリ終了の通知を受けたとき。再接続を止め、終了済みであることを全画面で知らせる。 */
function handleShuttingDown() {
    shuttingDown = true;
    const overlay = document.createElement("div");
    overlay.className = "shutdown-overlay";
    overlay.innerHTML = STR.shutdownOverlay;
    document.body.appendChild(overlay);
}

let captureRunning = true;

/** キャプチャの動作状態をボタンと状態チップに反映する。 */
function renderCaptureState(running) {
    captureRunning = running;
    const label = document.getElementById("capture-btn-label");
    const icon = document.querySelector("#btn-capture i");
    if (label) label.textContent = running ? STR.captureStop : STR.captureStart;
    if (icon) icon.className = running ? "fa-solid fa-circle-stop" : "fa-solid fa-circle-play";
    if (!running) {
        const chip = document.getElementById("capture-status");
        chip.textContent = STR.captureStopped;
        chip.className = "status-chip warn";
    }
}

/** PTP状態表(実測/宣言間隔・GM情報)と異常を反映する。 */
function renderPtpStatus(s) {
    const tbody = document.getElementById("ptp-list-body");
    const alertsEl = document.getElementById("ptp-alerts");
    const chip = document.getElementById("ptp-status");
    if (!tbody) return;

    // GM情報は (version, domain, clock_id) で引けるようにしておく
    const gm = {};
    (s.masters || []).forEach(m => { gm[`${m.version}|${m.domain}|${m.clock_id}`] = m; });

    tbody.innerHTML = "";
    s.rows.forEach(r => {
        const row = document.createElement("tr");
        const m = gm[`${r.version}|${r.domain}|${r.clock_id}`];
        const gmText = m ? `${m.gm_id}${m.priority1 !== undefined ? ` (P1=${m.priority1}/P2=${m.priority2}/class=${m.clock_class})` : ""}` : "";
        const fmt = v => (v === null || v === undefined) ? "---" : `${Number(v.toPrecision(3))}s`;
        [`v${r.version}`, r.domain, `${r.src_ip} [${r.clock_id}]`, r.msg_type, fmt(r.measured_s), fmt(r.declared_s), gmText].forEach(v => {
            const td = document.createElement("td");
            td.textContent = v;
            row.appendChild(td);
        });
        tbody.appendChild(row);
    });

    setBadge("badge-ptp", s.alerts.length || null); // PTPに異常があれば、別タブを見ていても気づける
    alertsEl.innerHTML = "";
    s.alerts.forEach(a => {
        const div = document.createElement("div");
        div.className = "ptp-alert";
        div.textContent = a.text;
        alertsEl.appendChild(div);
    });

    if (s.alerts.length > 0) {
        chip.textContent = STR.ptpWarnings(s.alerts.length);
        chip.className = "status-chip warn";
    } else if (s.rows.length > 0) {
        chip.textContent = STR.ptpOk;
        chip.className = "status-chip ok";
    } else {
        chip.textContent = "PTP: ---";
        chip.className = "status-chip";
    }
}

/** IGMPクエリアの状態(不在/複数/正常)をチップに反映する。 */
function renderQuerierStatus(s) {
    const el = document.getElementById("querier-status");
    if (s.state === "ok") {
        const q = s.queriers[0];
        el.textContent = STR.querierOk(q.ip, q.version);
        el.className = "status-chip ok";
    } else if (s.state === "multiple") {
        el.textContent = STR.querierMultiple(s.queriers.map(q => q.ip).join(", "), s.elected);
        el.className = "status-chip warn";
    } else if (s.state === "none") {
        el.textContent = STR.querierNone;
        el.className = "status-chip error";
    } else {
        el.textContent = STR.querierChecking;
        el.className = "status-chip";
    }
}

/** PCAP記録の状態(件数・取りこぼし・エラー・容量警告)をチップに反映する。 */
let syncWarned = false;

function renderCaptureStatus(s) {
    const el = document.getElementById("capture-status");
    if (s.sync_warning && !syncWarned) {
        syncWarned = true; // 保存先がクラウド同期フォルダの場合、実データの複製に気づけるよう一度だけ通知する
        showNotice(STR.pcapSynced, "warn");
    }
    if (!captureRunning) return; // 停止中は「停止中」表示を優先する
    if (!s.enabled) {
        el.textContent = STR.pcapDisabled;
        el.className = "status-chip warn";
    } else if (s.error) {
        el.textContent = STR.pcapError(s.error);
        el.className = "status-chip error";
    } else if (s.dropped > 0) {
        el.textContent = STR.pcapDropped(s.packets.toLocaleString(), s.dropped.toLocaleString());
        el.className = "status-chip error";
    } else if (s.disk_warning) {
        el.textContent = STR.pcapLarge(s.packets.toLocaleString());
        el.className = "status-chip warn";
    } else {
        el.textContent = STR.pcapRecording(s.packets.toLocaleString());
        el.className = "status-chip ok";
    }
}

function requestExport() {
    if (!socket || socket.readyState !== WebSocket.OPEN) {
        showNotice(STR.notConnected, "error");
        return;
    }
    const f = collectFilter();
    socket.send(JSON.stringify({
        action: "export_csv",
        since: document.getElementById("export-since").value.trim(),
        until: document.getElementById("export-until").value.trim(),
        protos: f.protos,
        ptp_types: f.ptp_types,
        text: f.text, // UIのテキスト絞り込み(IP/MAC/グループ/機器名の部分一致)をそのまま適用
        data_mode: document.getElementById("export-data-mode").value
    }));
    showNotice(STR.exportRunning, "ok");
}

function handleExportDone(d) {
    if (!d.ok) {
        showNotice(STR.exportFailed(d.error), "error");
        return;
    }
    const warn = d.warnings && d.warnings.length ? STR.exportWarnings(d.warnings.length) : "";
    showNotice(STR.exportDone(d.out, d.rows, warn), warn ? "warn" : "ok");
}

// ==============================================================================
// 6. WebSocket 再接続通信管理
// ==============================================================================
function connectWebSocket() {
    const connDot = document.getElementById("conn-dot");
    const connText = document.getElementById("conn-text");

    socket = new WebSocket(WS_URL);

    socket.onopen = () => {
        connDot.className = "status-dot connected";
        connText.textContent = STR.connected;
        sendFilter(); // 再接続時もフィルタ条件をサーバーへ再送する
    };

    socket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            
            // システムイベントのハンドリング (NIC選択リスト等)
            if (data.type === "nic_list") {
                updateNicDropdown(data.nics, data.active_index);
                return;
            }
            if (data.type === "nic_changed") {
                console.log(`NICの動的切り替え完了: ${data.active_nic}`);
                return;
            }
            // 集計・状態通知・エクスポート結果
            if (data.type === "flow_stats") { renderFlowStats(data.flows); return; }
            if (data.type === "shutting_down") { handleShuttingDown(); return; }
            if (data.type === "capture_state") { renderCaptureState(data.running); return; }
            if (data.type === "capture_error") { showNotice(STR.captureSwitchFailed(data.error), "error"); return; }
            if (data.type === "ptp_status") { renderPtpStatus(data); return; }
            if (data.type === "querier_status") { renderQuerierStatus(data); return; }
            if (data.type === "capture_status") { renderCaptureStatus(data); return; }
            if (data.type === "suppressed") { showNotice(STR.suppressed(data.count), "warn"); return; }
            if (data.type === "export_done") { handleExportDone(data); return; }
            
            // 1. トポロジマップの更新
            handleNetworkEvent(data);
            
            // 2. 画面ログ行の追加
            addStreamingLog(data);
        } catch (e) {
            console.error("メッセージ受信パースエラー:", e);
        }
    };

    socket.onclose = () => {
        connDot.className = "status-dot";
        if (shuttingDown) return; // 終了済みなので再接続しない
        connText.textContent = STR.disconnected;

        // 3秒後に再接続を自動リトライ
        setTimeout(connectWebSocket, 3000);
    };

    socket.onerror = (err) => {
        socket.close();
    };
}

/**
 * 監視可能なNICリストプルダウンを動的に更新します。
 */
function updateNicDropdown(nics, activeIndex) {
    const selector = document.getElementById("nic-selector");
    if (!selector) return;

    selector.innerHTML = "";
    
    if (!nics || nics.length === 0) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = STR.noNics;
        selector.appendChild(opt);
        return;
    }

    nics.forEach(nic => {
        const opt = document.createElement("option");
        opt.value = nic.index;
        opt.textContent = `${nic.name} (${nic.ip})`;
        if (nic.index === activeIndex) {
            opt.selected = true;
        }
        selector.appendChild(opt);
    });
}

// ==============================================================================
// 7. 画面操作系ボタン・初期ロード登録
// ==============================================================================
document.addEventListener("DOMContentLoaded", () => {
    // FontAwesomeのウェブフォントロード完了を確実に待機し、アイコンの「バツ四角形☒」崩れを防ぎます！
    document.fonts.load('900 24px "Font Awesome 6 Free"').then(() => {
        // A. トポロジの初期化
        initTopology();
        
        // B. WebSocket接続の開始
        connectWebSocket();
    }).catch(err => {
        console.warn("FontAwesomeプリロードエラー。フォールバックで起動します:", err);
        initTopology();
        connectWebSocket();
    });

    // C. ボタンイベント設定

    initPanelLayout();

    // フィルタ変更 ➔ サーバーへ送信(テキスト入力は連打を避けるため300msデバウンス)
    let filterTimer = null;
    document.querySelectorAll("#filter-protos input, #filter-raw").forEach(el => el.addEventListener("change", sendFilter));
    document.getElementById("filter-text").addEventListener("input", () => {
        clearTimeout(filterTimer);
        filterTimer = setTimeout(sendFilter, 300);
    });
    document.getElementById("btn-export").addEventListener("click", requestExport);

    // 全体表示フィットボタン
    document.getElementById("btn-fit").addEventListener("click", () => {
        if (network) network.fit({ animation: true });
    });

    // 物理シミュレーション一時停止・固定トグルボタン
    let isFrozen = false;
    const freezeBtn = document.getElementById("btn-freeze");
    freezeBtn.addEventListener("click", () => {
        if (!network) return;
        isFrozen = !isFrozen;
        if (isFrozen) {
            network.setOptions({ physics: { enabled: false } });
            freezeBtn.innerHTML = '<i class="fa-solid fa-play"></i>';
            freezeBtn.title = STR.freezeResume;
        } else {
            network.setOptions({ physics: { enabled: true } });
            freezeBtn.innerHTML = '<i class="fa-solid fa-pause"></i>';
            freezeBtn.title = STR.freezeHold;
        }
    });

    // リセットボタン（画面トポロジの完全クリア）
    document.getElementById("btn-reset").addEventListener("click", () => {
        nodes.clear();
        edges.clear();
        clearLogView();
        ["flow-list-body", "ptp-list-body", "ptp-alerts"].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.innerHTML = "";
        });
        setBadge("badge-ptp", null);
        setBadge("badge-flow", null);
        // サーバー側のクエリア/PTP監視もやり直す(PCAPは新ファイルに切替。記録済みの内容は消えない)
        if (socket && socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ action: "reset_state" }));
        }
    });

    // ログクリアボタン
    document.getElementById("btn-clear-log").addEventListener("click", clearLogView);

    // ログ一時停止/再開ボタン(トポロジ・状態表・PCAP記録は止まらない)
    document.getElementById("btn-pause-log").addEventListener("click", () => setLogPaused(!logPaused));

    // 終了ボタン: 確認のうえサーバーへ終了要求を送る(監視とPCAP記録も止まる)
    document.getElementById("btn-shutdown").addEventListener("click", () => {
        if (!socket || socket.readyState !== WebSocket.OPEN) {
            showNotice(STR.notConnectedStop, "error");
            return;
        }
        if (confirm(STR.shutdownConfirm)) {
            socket.send(JSON.stringify({ action: "shutdown" }));
        }
    });

    // キャプチャ停止/開始ボタン(状態の反映はサーバーからの capture_state 通知で行う)
    document.getElementById("btn-capture").addEventListener("click", () => {
        if (!socket || socket.readyState !== WebSocket.OPEN) {
            showNotice(STR.notConnected, "error");
            return;
        }
        socket.send(JSON.stringify({ action: "set_capture", running: !captureRunning }));
    });

    // D. NICプルダウン変更イベント（動的NIC切り替え ＆ トポロジ自動初期化）
    const nicSelector = document.getElementById("nic-selector");
    if (nicSelector) {
        nicSelector.addEventListener("change", (event) => {
            const selectedIndex = parseInt(event.target.value);
            if (isNaN(selectedIndex)) return;

            // NIC切替時は、旧NICの状態が混ざらないようトポロジとログを初期化する
            nodes.clear();
            edges.clear();
            clearLogView();

            // バックエンドへNIC動的切り替えコマンドを送信
            if (socket && socket.readyState === WebSocket.OPEN) {
                socket.send(JSON.stringify({
                    action: "change_nic",
                    nic_index: selectedIndex
                }));
                console.log(`NIC動的切り替え要求送信: インデックス ${selectedIndex}`);
            }
        });
    }
});
