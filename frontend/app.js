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
            // 選択・マウスを乗せた線は 2 倍の太さにする(色は線ごとの EDGE_STYLES で、元の色のまま)
            selectionWidth: (width) => width * 2,
            hoverWidth: (width) => width * 1.5,
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

    // まとめノードのダブルクリックで展開、展開済みのグループのダブルクリックで畳む
    network.on("doubleClick", (params) => {
        if (params.nodes && params.nodes.length) toggleFamily(params.nodes[0]);
    });

    // ノードのクリックで、つながる線とノードだけを強調し、詳細パネルを開く。空白のクリックで元に戻す
    network.on("click", (params) => {
        const id = params.nodes && params.nodes.length ? params.nodes[0] : null;
        setFocus(id);
        showDetail(id);
    });

    // 利用者が自分で拡大・移動したら、自動の全体表示はやめる(操作を上書きしないため)
    network.on("zoom", () => { autoFitUntil = 0; });
    network.on("dragStart", (params) => { if (!params.nodes || !params.nodes.length) autoFitUntil = 0; });

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
 * グループのキー。VLAN ごとに同じグループアドレスが別に使われ得るため、VLAN が分かるときは IP と VLAN を組にする。
 * タグ無し(VLAN 不明)は IP そのもの(従来と同じ)。
 */
function groupKeyOf(ip, vlan) {
    return vlan === null || vlan === undefined ? ip : `${ip}|v${vlan}`;
}
function ipOf(key) { return String(key).split("|")[0]; }
function vlanOf(key) {
    const m = String(key).match(/\|v(\d+)$/);
    return m ? Number(m[1]) : null;
}

/**
 * 指定されたマルチキャストIPアドレスの人間フレンドリーな用途表記およびアイコンを解決します。
 */
function getMulticastGroupLabel(key) {
    const ip = ipOf(key);
    const vlan = vlanOf(key);
    const vlanText = vlan === null ? "" : `\n${STR.vlanTag(vlan)}`;
    if (MULTICAST_LABELS[ip]) {
        const info = MULTICAST_LABELS[ip];
        return `${ip}\n${info.icon} ${info.tag}${vlanText}`;
    }
    return `${ip}\n${groupKindLabel(key)}${vlanText}`;
}

/**
 * sACN(E1.31)のユニバース番号。ユニバースNは 239.255.(N>>8).(N&0xFF) 宛(有効範囲 1〜63999)。
 * backend/packet_analyzer.py の sacn_universe と同じ式。
 */
function sacnUniverse(ip) {
    const p = ip.split(".").map(Number);
    if (p.length !== 4 || p[0] !== 239 || p[1] !== 255 || p.some(isNaN)) return null;
    const u = (p[2] << 8) | p[3];
    return u >= 1 && u <= 63999 ? u : null;
}

/**
 * グループの種類。データを観測して種類が分かったグループはそれを優先する。
 * IGMP Join にはポート番号が無く、239.255.x.x は sACN と Dante のどちらもあり得るため、
 * 観測前は "sacn-or-dante" とする(Issue #1: 照明の sACN が Dante と表示された)。
 */
function groupKind(key) {
    const ip = ipOf(key);
    const proto = groupProto.get(key);
    if (proto === "sACN") return "sacn";
    if (proto === "Dante-Audio") return "dante";
    if (proto === "AES67-Audio") return "aes67";
    if (proto) return ip.startsWith("239.") ? "private" : "generic"; // データを見て未分類と確定した
    if (sacnUniverse(ip) !== null) return "sacn-or-dante";
    return ip.startsWith("239.") ? "private" : "generic";
}

/** グループの用途表記(種類ごと)。 */
function groupKindLabel(key) {
    const universe = sacnUniverse(ipOf(key));
    switch (groupKind(key)) {
        case "sacn": return universe !== null ? STR.groupSacn(universe) : "sACN";
        case "dante": return STR.groupDante;
        case "aes67": return STR.groupAes67;
        case "sacn-or-dante": return STR.groupSacnOrDante(universe);
        case "private": return STR.groupPrivate;
        default: return STR.groupGeneric;
    }
}

// アイコン定義マッピング (FontAwesome 6 Unicode)
const ICONS = {
    querier: { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf521", color: "#c084fc", size: 45 }, // 👑 (Crown)
    group: { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf519", color: "#4ade80", size: 40 },   // 配信されるストリーム (tower-broadcast)
    family: { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf5fd", color: "#86efac", size: 54 }, // まとめ (layer-group)
    subnet: { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf233", color: "#60a5fa", size: 48 },  // 端末のまとめ (server)
    host: { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf109", color: "#3b82f6", size: 36 },     // 💻 (Laptop)
    sync: { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf017", color: "#e2e8f0", size: 38 }      // ⏰ (Clock)
};

// グループの種類ごとのアイコン。色だけに頼らないよう形も変える(色覚の違いでも区別できるように)
const GROUP_KIND_ICONS = {
    "sacn": { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf0eb", color: "#fde047", size: 40 },          // 照明 (lightbulb)
    "dante": { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf028", color: "#22d3ee", size: 40 },         // 音声 (volume-high)
    "aes67": { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf83e", color: "#f472b6", size: 40 },         // 音声 (wave-square)
    "sacn-or-dante": { face: '"Font Awesome 6 Free"', weight: "900", code: "\uf059", color: "#94a3b8", size: 40 }, // 未確定 (circle-question)
    "private": ICONS.group,
    "generic": ICONS.group
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
            // VLAN 表記(ラベル末尾の " VLAN n")は残す
            const vlanPart = String(label).match(/ VLAN [\d, VLAN]+$/);
            targetLabel = STR.switchNoIp + (vlanPart ? vlanPart[0] : "");
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
        customType: targetType, // 内部仕分け用タグ
        dimmed: false
    };
    // 強調中で、このノードが薄くなっているなら、薄いまま更新する(明るく戻って明滅しないように)
    if (exists && exists.dimmed && focusId !== null) {
        nodeData.dimmed = true;
        nodeData.undimmed = { icon: nodeData.icon };
        nodeData.icon = { ...nodeData.icon, color: DIM_ICON_COLOR };
        nodeData.font = { color: DIM_FONT_COLOR };
    } else {
        nodeData.font = { color: NODE_FONT_COLOR };
    }
    // まとめ表示で隠すのは一般ホストだけ。クエリア/クロックへ昇格したノードは必ず表示に戻す
    if (targetType !== "host" && exists && exists.customType === "host") nodeData.hidden = false;

    if (exists) {
        // 既存のノード情報をマージ (IP ➔ mDNS解決名 への昇格時などに実行)
        if (targetType !== "host") nodeData.physics = true;
        nodes.update(nodeData);
        // 種類が変わった時は、まとめ判定とフィルタの対象が変わるので描き直す
        if (exists.customType !== targetType || exists.label !== nodeData.label) scheduleGroupRender();
    } else {
        nodes.add(nodeData);
        scheduleGroupRender();
    }
}

// ------------------------------------------------------------------------------
// マルチキャストグループのモデルと描画
// グループが大量にある現場(照明の sACN 数百ユニバース、大規模 Dante/AES67 等)でも図が読めるよう、
// グループの総数がしきい値を超えたら、同じ系統(アドレス範囲)のグループを 1 つのまとめノードにする。
// まとめ方は用途に依らない汎用の仕組みにして、照明以外の環境でも同じように効くようにする。
// ------------------------------------------------------------------------------
// グループの総数がこれを超えたら、まとめ表示を始める。
// 根拠: 再現(Issue #1)では 300 グループでラベルが重なり判読不能、既存デモの 10 個前後は問題なし。
// 1 画面でラベルを読める目安として 40 とした。
const GROUP_COLLAPSE_THRESHOLD = 40;
// 系統内のグループがこれ未満なら、まとめても見通しが良くならないので個別に表示する
const GROUP_COLLAPSE_MIN_FAMILY = 5;
// 端末(一般ホスト)の数がこれを超えたら、同じ /24 サブネットの端末を 1 つのまとめノードにする。
// 根拠: 再現(混在環境 60 台)で端末ラベルが重なり判読不能になった。グループのしきい値より小さいのは、
// 端末ノードは名前が長く、1 台あたりの面積が大きいため。
const HOST_COLLAPSE_THRESHOLD = 30;
const HOST_COLLAPSE_MIN_SUBNET = 5;
// イベントが連続して届くたびに描き直すと重いので、まとめて描き直す間隔(ms)
const GROUP_RENDER_DEBOUNCE_MS = 300;

// group_ip -> { title, members: Set<受信側の端末ID>, senders: Map<送信元の端末ID, 最終観測(ms)>,
//               requested: Map<受信側の端末ID, IGMPv3 で指定した送信元IPの配列> }
const groupModel = new Map();
const groupProto = new Map();       // group_ip -> データ面で観測したプロトコル(sACN / Dante-Audio 等)
const expandedFamilies = new Set(); // 利用者が展開したまとめ(系統キー)
let groupRenderTimer = null;

/**
 * グループの系統(まとめる単位)を返す。
 * 239.255.0.1〜239.255.249.255 は sACN/Dante の範囲として 1 系統、224.0.0.x はリンクローカル、それ以外は /16 単位。
 * VLAN が分かるときは VLAN ごとに別の系統にする(別の VLAN のグループを 1 つにまとめない)。
 */
function groupFamily(key) {
    const ip = ipOf(key);
    const vlan = vlanOf(key);
    const p = ip.split(".");
    let fam;
    if (sacnUniverse(ip) !== null) fam = { key: "fam:sacn-dante", label: STR.familySacnDante };
    else if (p[0] === "224" && p[1] === "0" && p[2] === "0") fam = { key: "fam:224.0.0", label: STR.familyLinkLocal };
    else if (p[0] === "239" && p[1] === "255") fam = { key: "fam:239.255-other", label: STR.family239255Other };
    else fam = { key: `fam:${p[0]}.${p[1]}`, label: `${p[0]}.${p[1]}.x.x` };
    if (vlan !== null) fam = { key: `${fam.key}|v${vlan}`, label: `${fam.label} ${STR.vlanTag(vlan)}` };
    return fam;
}

function isGroupDataSeen(groupIp) {
    const last = groupDataLastSeen.get(groupIp);
    return last !== undefined && Date.now() - last <= GROUP_DATA_STALE_MS;
}

// 他の機器の Join(IGMP Report)をこのポートで観測したか。バックエンドが自 PC の Report を除いて数える
// (querier_status.reports_seen。NIC 切替でリセットされる)。受信者のいないストリームの警告は、これが真のときだけ出す
let othersReportsSeen = false;

// 機器ID -> その機器から観測したプロトコル(チェックボックスの値: IGMP / mDNS / sACN / PTPv1 ...)。
// どのグループにもつながらない機器(mDNS だけの機器、送信が止まった送信元など)を、チェックで隠すために使う
const hostProtos = new Map();
function noteHostProto(hostId, key) {
    if (!hostId || !key) return;
    if (!hostProtos.has(hostId)) hostProtos.set(hostId, new Set());
    const set = hostProtos.get(hostId);
    if (!set.has(key)) {
        set.add(key);
        scheduleGroupRender();
    }
}

function ensureGroup(groupIp, title) {
    let g = groupModel.get(groupIp);
    if (!g) {
        g = { title, members: new Set(), senders: new Map(), requested: new Map(), excludeMode: new Set() };
        groupModel.set(groupIp, g);
    }
    if (title) g.title = title;
    return g;
}

/**
 * 端末がグループに参加した(IGMP Join)ことをモデルへ記録する。
 * sources は IGMPv3 で受信機が指定した送信元。指定が無ければ空配列。
 */
function groupJoin(hostId, groupIp, title, sources = [], recordType = "") {
    const g = ensureGroup(groupIp, title);
    g.members.add(hostId);
    if (recordType === "MODE_IS_EXCLUDE" || recordType === "CHANGE_TO_EXCLUDE_MODE") g.excludeMode.add(hostId);
    else if (recordType === "MODE_IS_INCLUDE" || recordType === "CHANGE_TO_INCLUDE_MODE") g.excludeMode.delete(hostId);
    if (recordType === "ALLOW_NEW_SOURCES" && g.excludeMode.has(hostId)) {
        // 除外モードでの ALLOW は、除外の取り消し。受信したい送信元の一覧は変えない
    } else if (recordType === "ALLOW_NEW_SOURCES" && g.requested.has(hostId)) {
        // 追加の指定は、既存の指定に足す
        const merged = new Set([...g.requested.get(hostId), ...sources]);
        g.requested.set(hostId, Array.from(merged).slice(0, 64));
    } else if (sources.length) {
        g.requested.set(hostId, sources.slice(0, 64));
    } else {
        g.requested.delete(hostId);
    }
    scheduleGroupRender();
}

/**
 * Join のうち、受信機が「この送信元から受けたい」と指定した送信元。
 * EXCLUDE 系(MODE_IS_EXCLUDE / CHANGE_TO_EXCLUDE_MODE)の sources は「受けたくない送信元」なので含めない。
 */
function requestedSources(data) {
    const include = ["MODE_IS_INCLUDE", "CHANGE_TO_INCLUDE_MODE", "ALLOW_NEW_SOURCES"];
    return include.includes(data.record_type) && Array.isArray(data.sources) ? data.sources : [];
}

/** IGMPv3 の BLOCK_OLD_SOURCES: 指定していた送信元から外す。 */
function groupBlockSources(hostId, groupIp, sources) {
    const g = groupModel.get(groupIp);
    if (!g || !g.requested.has(hostId)) return;
    const remain = g.requested.get(hostId).filter(s => !sources.includes(s));
    if (remain.length) {
        g.requested.set(hostId, remain);
        scheduleGroupRender();
    } else if (!g.excludeMode.has(hostId)) {
        groupLeave(hostId, groupIp); // INCLUDE{} = 受信停止
    } else {
        g.requested.delete(hostId);
        scheduleGroupRender();
    }
}

/** 端末がグループから離脱した。受信者も送信中の送信元もいなくなったグループは消す。 */
function groupLeave(hostId, groupIp) {
    const g = groupModel.get(groupIp);
    if (!g) return;
    g.members.delete(hostId);
    g.requested.delete(hostId);
    g.excludeMode.delete(hostId);
    deleteGroupIfEmpty(groupIp, g);
    scheduleGroupRender();
}

/** 送信元がグループへデータを送っているのを観測した(フロー統計・PTP)。 */
function recordSender(hostId, groupIp, title) {
    const g = ensureGroup(groupIp, groupModel.has(groupIp) ? null : title);
    const isNew = !isSenderLive(g, hostId);
    g.senders.set(hostId, Date.now());
    if (isNew) scheduleGroupRender();
}

function isSenderLive(g, hostId) {
    const t = g.senders.get(hostId);
    return t !== undefined && Date.now() - t <= GROUP_DATA_STALE_MS;
}

/** 直近に送信を観測した送信元(途絶した送信元は含めない)。 */
function liveSenders(g) {
    const ids = [];
    g.senders.forEach((_, id) => { if (isSenderLive(g, id)) ids.push(id); });
    return ids;
}

function deleteGroupIfEmpty(groupIp, g) {
    if (g.members.size === 0 && liveSenders(g).length === 0) {
        groupModel.delete(groupIp);
        groupProto.delete(groupIp);
        groupDataLastSeen.delete(groupIp);
    }
}

function scheduleGroupRender() {
    if (groupRenderTimer !== null) return;
    groupRenderTimer = setTimeout(() => {
        groupRenderTimer = null;
        renderGroups();
    }, GROUP_RENDER_DEBOUNCE_MS);
}

/** どの系統をまとめて表示するかを決める。 */
function collapsedFamilyKeys(visibleGroups) {
    const keys = new Set();
    if (visibleGroups.length <= GROUP_COLLAPSE_THRESHOLD) return keys;
    const sizes = new Map();
    visibleGroups.forEach((ip) => {
        const k = groupFamily(ip).key;
        sizes.set(k, (sizes.get(k) || 0) + 1);
    });
    sizes.forEach((n, k) => {
        if (n >= GROUP_COLLAPSE_MIN_FAMILY && !expandedFamilies.has(k)) keys.add(k);
    });
    return keys;
}

/** 端末をまとめる単位(/24 サブネット)のキー。IP として読めない ID はまとめない。 */
function hostSubnetKey(id) {
    const p = String(id).split(".");
    if (p.length !== 4 || p.some(x => x === "" || isNaN(Number(x))) || id === "0.0.0.0") return null;
    return `net:${p[0]}.${p[1]}.${p[2]}`;
}

/**
 * まとめて表示する端末を決める。クエリア・PTP クロック・送信中の機器は役割が重要なので常に個別に出す。
 * hidden(フィルタで隠す機器)はしきい値の台数にも含めない。keepIndividual(送信中の機器)は台数には含めるが、まとめない。
 * @returns {Map<string, string>} 端末ID -> サブネットのまとめキー
 */
function collapsedHostMap(hidden, keepIndividual) {
    const result = new Map();
    const hosts = nodes.get({ filter: (n) => n.customType === "host" && !hidden.has(n.id) });
    if (hosts.length <= HOST_COLLAPSE_THRESHOLD) return result;
    const bySubnet = new Map();
    hosts.forEach(h => {
        if (keepIndividual.has(h.id)) return;
        const k = hostSubnetKey(h.id);
        if (!k) return;
        if (!bySubnet.has(k)) bySubnet.set(k, []);
        bySubnet.get(k).push(h.id);
    });
    bySubnet.forEach((ids, k) => {
        if (ids.length >= HOST_COLLAPSE_MIN_SUBNET && !expandedFamilies.has(k)) ids.forEach(id => result.set(id, k));
    });
    return result;
}

/**
 * モデルから、グループ/まとめノードと、それらへ繋がる線を描き直す。
 * 差分だけを DataSet に反映し、残るノードは位置を保つ(物理演算の揺れを抑える)。
 */
function renderGroups() {
    lastSeenSnapshot = seenSnapshot();
    const filter = mapFilter();
    const drawReceivers = filter.protos === null || filter.protos.has("IGMP");

    // 1. フィルタで表示するグループを決める(途絶した送信元しか持たないグループはここで片付ける)
    const visible = [];
    groupModel.forEach((g, ip) => {
        if (g.members.size === 0 && liveSenders(g).length === 0) {
            deleteGroupIfEmpty(ip, g);
            return;
        }
        if (isGroupShownByFilter(ip, g, filter, drawReceivers)) visible.push(ip);
    });

    // 2. 線のつながる端末と、フィルタで隠す端末を決める
    const linkedHosts = new Set();
    visible.forEach(ip => {
        const g = groupModel.get(ip);
        if (drawReceivers) g.members.forEach(h => linkedHosts.add(h));
        liveSenders(g).forEach(h => linkedHosts.add(h));
    });
    // フィルタで隠す端末:
    // - プロトコル: 表示中のグループにつながらず、その端末で観測したプロトコルのチェックもすべて外れている
    //   (mDNS だけの機器や、送信が止まった送信元も、チェックを外せば隠れる)
    // - 文字列: 表示中のグループにつながらず、名前・IP・MAC も一致しない
    const filteredOut = new Set();
    if (filter.active) {
        nodes.get({ filter: (n) => FILTERABLE_TYPES.includes(n.customType) }).forEach(n => {
            const protos = hostProtos.get(n.id);
            const protoTicked = filter.protos === null || (Boolean(protos) && [...protos].some(k => filter.protos.has(k)));
            const byProto = !linkedHosts.has(n.id) && !protoTicked;
            const wantedVlan = vlanQuery(filter.text);
            const querierOfVlan = n.customType === "querier" && wantedVlan !== null
                && (querierVlans.get(n.id) || new Set()).has(wantedVlan);
            const byText = filter.text && !linkedHosts.has(n.id) && !querierOfVlan
                && (wantedVlan !== null || !nodeMatchesText(n, filter.text));
            const byIgmp = n.customType === "querier" && !drawReceivers; // クエリアは IGMP の機器
            if (byProto || byText || byIgmp) filteredOut.add(n.id);
        });
    }
    const collapsed = collapsedFamilyKeys(visible);
    // 送信中の機器は、クエリアやクロックと同じく常に個別に表示する(受信機だけをまとめる)
    const activeSenders = new Set();
    visible.forEach(ip => liveSenders(groupModel.get(ip)).forEach(h => activeSenders.add(h)));
    const hostMap = collapsedHostMap(filteredOut, activeSenders);
    const shown = (h) => hostMap.get(h) || h; // 端末がまとめられていれば、線はまとめノードへ繋ぐ
    const wantNodes = new Map(); // node id -> node data
    const wantEdges = new Map(); // edge id -> { from, to, label, kind }
    const families = new Map();  // 系統キー -> まとめの集計
    const receiversVisible = joinsVisible();
    const warnedKeys = [];

    visible.forEach(ip => {
        const g = groupModel.get(ip);
        const senders = liveSenders(g);
        const status = groupStatus(ip, g, senders, receiversVisible);
        if (status.multi || status.noReceiver) warnedKeys.push(ip);
        const fam = groupFamily(ip);
        if (collapsed.has(fam.key)) {
            let f = families.get(fam.key);
            if (!f) {
                f = { label: fam.label, groups: [], seen: 0, kinds: new Set(), members: new Set(), senders: new Set(),
                      multi: 0, noReceiver: 0 };
                families.set(fam.key, f);
            }
            f.groups.push(ip);
            f.kinds.add(groupKind(ip));
            if (isGroupDataSeen(ip)) f.seen += 1;
            g.members.forEach(h => f.members.add(h));
            senders.forEach(h => f.senders.add(h));
            if (status.multi) f.multi += 1;
            if (status.noReceiver) f.noReceiver += 1;
            return;
        }
        wantNodes.set(ip, groupNodeData(ip, g, senders, status));
        if (drawReceivers) g.members.forEach(h => addReceiverEdge(wantEdges, shown(h), ip));
        senders.forEach(h => wantEdges.set(`${shown(h)}_src_${ip}`, { from: shown(h), to: ip, kind: "sender" }));
    });

    familyGroups.clear();
    families.forEach((f, key) => {
        familyGroups.set(key, f.groups);
        wantNodes.set(key, familyNodeData(key, f));
        if (drawReceivers) f.members.forEach(h => addReceiverEdge(wantEdges, shown(h), key));
        f.senders.forEach(h => wantEdges.set(`${shown(h)}_src_${key}`, { from: shown(h), to: key, kind: "sender" }));
    });

    // クエリアとグループ(まとめ)を薄い線で結び、トポロジを紐付ける
    const queriers = nodes.get({ filter: (n) => n.customType === "querier" });
    if (drawReceivers) {
        wantNodes.forEach((node, id) => {
            if (node.customType !== "group" && node.customType !== "family") return;
            queriersFor(id, node, queriers).forEach(q =>
                wantEdges.set(`${q.id}_to_${id}`, { from: q.id, to: id, kind: "query" }));
        });
    }

    // 端末のまとめノード。まとめた端末は隠す(消すと名前解決などの情報が失われるため)
    const subnets = new Map(); // まとめキー -> 端末ID の配列
    hostMap.forEach((k, id) => {
        if (!subnets.has(k)) subnets.set(k, []);
        subnets.get(k).push(id);
    });
    subnets.forEach((ids, k) => wantNodes.set(k, subnetNodeData(k, ids)));
    // 隠す端末: まとめた端末と、フィルタに合わない端末
    const isHidden = (id) => hostMap.has(id) || filteredOut.has(id);
    const hostVisibility = nodes.get({ filter: (n) => FILTERABLE_TYPES.includes(n.customType) && Boolean(n.hidden) !== isHidden(n.id) })
        .map(n => ({ id: n.id, hidden: isHidden(n.id), physics: !isHidden(n.id) }));
    if (hostVisibility.length) nodes.update(hostVisibility);

    // 不要になったグループ/まとめノードと、その線を消す
    const removeEdgeIds = edges.get({ filter: (e) => e.groupEdge && !wantEdges.has(e.id) }).map(e => e.id);
    if (removeEdgeIds.length) edges.remove(removeEdgeIds);
    const removeNodeIds = nodes.get({ filter: (n) => ["group", "family", "subnet"].includes(n.customType) && !wantNodes.has(n.id) })
        .map(n => n.id);
    if (removeNodeIds.length) nodes.remove(removeNodeIds);

    const changed = [];
    wantNodes.forEach((n, id) => {
        const sig = nodeSignature(n);
        if (renderedSignature.get(id) !== sig || !nodes.get(id)) {
            renderedSignature.set(id, sig);
            changed.push(n);
        }
    });
    renderedSignature.forEach((_, id) => { if (!wantNodes.has(id)) renderedSignature.delete(id); });
    if (changed.length) nodes.update(changed);
    const addEdges = [];
    const widthUpdates = [];
    wantEdges.forEach((e, id) => {
        const width = edgeWidth(e);
        const existing = edges.get(id);
        if (!existing) {
            addEdges.push({ id, from: e.from, to: e.to, label: e.label || "", groupEdge: true, ...EDGE_STYLES[e.kind], width });
        } else if (existing.width !== width) {
            widthUpdates.push({ id, width });
        }
    });
    if (addEdges.length) edges.add(addEdges);
    if (widthUpdates.length) edges.update(widthUpdates);

    renderGroupSummary(families, subnets);
    renderWarnSummary(warnedKeys);
    applyFocus();
    noteLayoutChange();
    refreshDetail();
}

/**
 * グループ(まとめ)ノードと結ぶクエリア。
 * - VLAN が分かるグループ: 同じ VLAN の Query を送ったクエリアだけ。
 * - VLAN が分からないグループ: VLAN 不明のクエリアのうち、受信機・送信元と同じ /24 にいるもの。
 *   1 台も合わなければ、VLAN 不明のクエリア全部(サブネットで推測できない場合は従来どおり)。
 */
function queriersFor(id, node, queriers) {
    const vlan = node.customType === "family" ? vlanOf(id) : vlanOf(id);
    const sameVlan = queriers.filter(q => (querierVlans.get(q.id) || new Set([null])).has(vlan));
    if (vlan !== null || sameVlan.length <= 1) return sameVlan;
    const keys = node.customType === "group" ? [id] : (familyGroups.get(id) || []);
    const subnets = new Set();
    keys.forEach(k => {
        const g = groupModel.get(k);
        if (!g) return;
        [...g.members, ...liveSenders(g)].forEach(h => { const s = hostSubnetKey(h); if (s) subnets.add(s); });
    });
    const matched = sameVlan.filter(q => subnets.has(hostSubnetKey(q.id)));
    return matched.length ? matched : sameVlan;
}

// クエリアID -> そのクエリアが Query を送った VLAN の集合(タグ無しは null)
const querierVlans = new Map();
// まとめノードのキー -> まとめたグループのキー(クエリアの線をサブネットで選ぶため)
const familyGroups = new Map();

// ------------------------------------------------------------------------------
// クリックしたノードの詳細パネル
// ツールチップはマウスを動かすと消えるため、送信元・受信機の一覧を読み比べられるよう固定のパネルに出す。
// 内容は描き直しのたびに更新する(送信が止まった等の変化を追う)。
// ------------------------------------------------------------------------------
const DETAIL_LIST_MAX = 50; // 一覧に出す最大件数(多すぎるとパネルが長くなるため、残りは件数だけ示す)
let detailId = null;

function showDetail(id) {
    detailId = id;
    refreshDetail();
}

function refreshDetail() {
    const panel = document.getElementById("detail-panel");
    if (!panel) return;
    const node = detailId !== null ? nodes.get(detailId) : null;
    if (!node || node.hidden) {
        panel.hidden = true;
        detailId = null;
        return;
    }
    panel.hidden = false;
    const body = document.getElementById("detail-body");
    body.textContent = "";
    const title = document.getElementById("detail-title");
    const firstLine = String(node.label || node.id).replace(/^⚠ /, "").split("\n")[0];
    if (node.customType === "group") {
        title.textContent = `${STR.detailGroup}: ${firstLine}`;
        renderGroupDetail(body, node.id);
    } else if (node.customType === "family") {
        title.textContent = `${STR.detailSummary}: ${firstLine}`;
        renderKeyList(body, STR.detailGroups, familyGroups.get(node.id) || []);
    } else if (node.customType === "subnet") {
        title.textContent = `${STR.detailSummary}: ${firstLine}`;
        const ids = nodes.get({ filter: (n) => n.customType === "host" && hostSubnetKey(n.id) === node.id }).map(n => n.id);
        renderHostList(body, STR.detailDevices, ids);
    } else {
        const kind = node.customType === "querier" ? STR.detailQuerier : node.customType === "sync" ? STR.detailClock : STR.detailDevice;
        title.textContent = `${kind}: ${firstLine}`;
        renderHostDetail(body, node);
    }
}

function addSection(body, heading) {
    const h = document.createElement("h4");
    h.textContent = heading;
    body.appendChild(h);
}

function addLine(body, text, cls = "") {
    const div = document.createElement("div");
    if (cls) div.className = cls;
    div.textContent = text;
    body.appendChild(div);
}

/** コピー用のボタン。クリップボードが使えない環境(権限・古いブラウザ)では何もしない。 */
function copyButton(text) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-btn";
    btn.textContent = STR.copy;
    btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        try {
            await navigator.clipboard.writeText(text);
            btn.textContent = STR.copied;
            setTimeout(() => { btn.textContent = STR.copy; }, 1200);
        } catch (err) {
            console.warn("クリップボードへコピーできませんでした:", err);
        }
    });
    return btn;
}

/** 機器の一覧(名前と IP、IP のコピー)。名前を押すとその機器へ移動する。 */
function renderHostList(body, heading, ids) {
    addSection(body, `${heading} (${ids.length})`);
    if (!ids.length) { addLine(body, STR.detailNone, "muted"); return; }
    const ul = document.createElement("ul");
    ids.slice().sort(compareHostIds).slice(0, DETAIL_LIST_MAX).forEach(id => {
        const li = document.createElement("li");
        li.appendChild(detailLink(hostDisplay(id), id));
        li.appendChild(copyButton(String(id)));
        ul.appendChild(li);
    });
    body.appendChild(ul);
    if (ids.length > DETAIL_LIST_MAX) addLine(body, STR.detailMore(ids.length - DETAIL_LIST_MAX), "muted");
}

/** グループの一覧。名前を押すとそのグループへ移動する(まとめの中なら開く)。 */
function renderKeyList(body, heading, keys) {
    addSection(body, `${heading} (${keys.length})`);
    if (!keys.length) { addLine(body, STR.detailNone, "muted"); return; }
    const ul = document.createElement("ul");
    keys.slice().sort((a, b) => compareIp(ipOf(a), ipOf(b))).slice(0, DETAIL_LIST_MAX).forEach(key => {
        const li = document.createElement("li");
        li.appendChild(detailLink(getMulticastGroupLabel(key).replace(/\n/g, " · "), key));
        li.appendChild(copyButton(ipOf(key)));
        ul.appendChild(li);
    });
    body.appendChild(ul);
    if (keys.length > DETAIL_LIST_MAX) addLine(body, STR.detailMore(keys.length - DETAIL_LIST_MAX), "muted");
}

function detailLink(text, id) {
    const a = document.createElement("button");
    a.type = "button";
    a.className = "detail-link name";
    a.textContent = text;
    a.addEventListener("click", () => goToNode(id));
    return a;
}

/** 一覧から選んだノードへ移動する。まとめの中にあれば開く。 */
function goToNode(id) {
    if (!network) return;
    if (!nodes.get(id) || nodes.get(id).hidden) {
        const fam = groupModel.has(id) ? groupFamily(id).key : hostSubnetKey(id);
        if (fam) {
            expandedFamilies.add(fam);
            renderGroups();
        }
    }
    const n = nodes.get(id);
    if (!n || n.hidden) return;
    autoFitUntil = 0;
    network.focus(id, { scale: 1.2, animation: { duration: 400 } });
    network.selectNodes([id]);
    setFocus(id);
    showDetail(id);
}

function compareHostIds(a, b) {
    const ipLike = (x) => /^\d+\.\d+\.\d+\.\d+$/.test(String(x));
    if (ipLike(a) && ipLike(b)) return compareIp(String(a), String(b));
    return String(a).localeCompare(String(b));
}

function renderGroupDetail(body, key) {
    const g = groupModel.get(key);
    if (!g) return;
    const vlan = vlanOf(key);
    addLine(body, `${STR.detailKind}: ${groupKindLabel(key)}`);
    if (vlan !== null) addLine(body, `${STR.detailVlan}: ${vlan}`);
    addLine(body, `${STR.detailData}: ${isGroupDataSeen(key) ? STR.detailDataSeen : STR.detailDataNotSeen}`);
    const senders = liveSenders(g);
    const status = groupStatus(key, g, senders, joinsVisible());
    if (status.multi) addLine(body, STR.groupMultiSender, "warn-line");
    if (status.noReceiver) addLine(body, STR.groupNoReceiver, "warn-line");
    if (senders.length) renderHostList(body, STR.detailSenders, senders);
    else { addSection(body, STR.detailSenders); addLine(body, STR.detailSendersUnknown, "muted"); }
    renderHostList(body, STR.detailReceivers, [...g.members]);
    const requested = new Set();
    g.requested.forEach(list => list.forEach(x => requested.add(x)));
    if (requested.size) {
        addSection(body, STR.detailRequested);
        addLine(body, Array.from(requested).sort(compareIp).join(", "));
    }
}

function renderHostDetail(body, node) {
    const receives = [];
    const sends = [];
    groupModel.forEach((g, key) => {
        if (g.members.has(node.id)) receives.push(key);
        if (liveSenders(g).includes(node.id)) sends.push(key);
    });
    const title = node.title && node.title.textContent !== undefined ? node.title.textContent : "";
    title.split("\n").filter(Boolean).forEach(line => addLine(body, line, "muted"));
    if (node.customType === "querier") {
        const vlans = [...(querierVlans.get(node.id) || [])].map(v => v === null ? "untagged" : String(v));
        addLine(body, `${STR.detailVlans}: ${vlans.join(", ") || STR.detailNone}`);
    }
    const protos = hostProtos.get(node.id);
    if (protos && protos.size) addLine(body, `${STR.detailProtocols}: ${[...protos].sort().join(", ")}`);
    renderKeyList(body, STR.detailSends, sends);
    renderKeyList(body, STR.detailReceives, receives);
}

// ------------------------------------------------------------------------------
// 自動で全体を表示する
// 最初のデータは一気に届き、ノードが画面外に散らばる。届き始めてからしばらくは、図の構成が変わるたびに
// (少し待って配置が落ち着いてから)全体を表示する。利用者が拡大・移動したら、それ以降は自動ではしない。
// ------------------------------------------------------------------------------
const AUTO_FIT_WINDOW_MS = 10000; // 最初のデータから全体表示を続ける時間
const AUTO_FIT_DELAY_MS = 800;    // 構成が変わってから全体表示するまでの待ち(配置の物理演算が落ち着くのを待つ)
let autoFitUntil = -1;            // -1: まだデータが来ていない / 0: 自動の全体表示はしない / それ以外: この時刻まで
let autoFitTimer = null;
let lastNodeCount = 0;

function noteLayoutChange(force = false) {
    const count = nodes.get({ filter: (n) => !n.hidden }).length;
    const changed = count !== lastNodeCount;
    lastNodeCount = count;
    if (autoFitUntil === -1 && count > 0) autoFitUntil = Date.now() + AUTO_FIT_WINDOW_MS;
    if (!force && !(changed && autoFitUntil > Date.now())) return;
    clearTimeout(autoFitTimer);
    autoFitTimer = setTimeout(() => { if (network) network.fit({ animation: { duration: 400 } }); }, AUTO_FIT_DELAY_MS);
}

// フィルタで隠す対象になるノードの種類(グループとまとめノードは renderGroups が作り直す)
const FILTERABLE_TYPES = ["host", "querier", "sync"];

// 配色(2026-11-23 見直し): 送信矢印のオレンジ、sACN の黄、PTP クロックの白銀を分け、Dante はエラーの赤と紛れないシアンにした。
// どの色も地図の背景(#0f1521)に対してコントラスト比 3:1 以上(非テキストの WCAG 基準)。
// 線の種類ごとの見た目。送信(データ)は矢印付きのオレンジで、受信(Join)の青と見分けられるようにする。
// クエリアとグループの線は補助情報なので、細い紫(クエリアの王冠と同じ色)の点線にする
// 選択・マウスを乗せた線は、色を変えずに(色は送信/受信/クエリアの意味を持つため)不透明にし、太さで示す
function lineColor(normal, emphasized) {
    return { color: normal, highlight: emphasized, hover: emphasized };
}

const EDGE_STYLES = {
    receiver: { color: lineColor("rgba(96, 165, 250, 0.6)", "#60a5fa") },
    query: { color: lineColor("rgba(192, 132, 252, 0.85)", "#c084fc"), dashes: [6, 4] },
    sender: {
        color: lineColor("rgba(249, 115, 22, 0.92)", "#f97316"),
        arrows: { to: { enabled: true, scaleFactor: 0.7 } }
    }
};

// 線の太さ。受信線は、まとめノードが何台分の受信機を表すかに応じて太くする(1 台=2、50 台≒7、上限 8)。
// 対数にしたのは、台数がそのまま太さになると数十台で他の線が見えなくなるため
const EDGE_WIDTH_BASE = 2;
const EDGE_WIDTH_MAX = 8;
function edgeWidth(e) {
    if (e.kind === "query") return 1.5; // 細すぎると点線が背景に溶ける(1 では VLAN ごとの担当が追えなかった)
    if (e.kind === "sender") return 2.5;
    const n = e.count || 1;
    return Math.min(EDGE_WIDTH_MAX, EDGE_WIDTH_BASE + Math.log2(n) * 1.3);
}

/** 受信線を 1 本にまとめ、何台分かを数える(同じまとめノードの複数台は 1 本の線になる)。 */
function addReceiverEdge(wantEdges, from, to) {
    const id = `${from}_to_${to}`;
    const e = wantEdges.get(id);
    if (e) e.count += 1;
    else wantEdges.set(id, { from, to, kind: "receiver", count: 1 });
}

/**
 * グループの警告状態。
 * multi: 送信元が 2 台以上(アドレスの重複設定の疑い)。
 * noReceiver: データは届いているが受信者の Join が無い。ミラーではないポートでは他の機器の Join が
 *   見えないのが普通なので、Join が見える環境(他の機器の Join を観測済みで、見えない警告が出ていない)でだけ判定する。
 */
function groupStatus(key, g, senders, receiversVisible) {
    const ip = ipOf(key);
    // 名前付きのアドレス(PTP・mDNS 等)とリンクローカル(224.0.0.x)は、複数の送信元や Join 無しが正常なので対象外
    if (KNOWN_GROUP_FILTER_KEYS[ip] || ip.startsWith("224.0.0.")) return { multi: false, noReceiver: false };
    return {
        multi: senders.length > 1,
        noReceiver: receiversVisible && senders.length > 0 && g.members.size === 0
    };
}

function joinsVisible() {
    const hint = document.getElementById("report-visibility");
    return othersReportsSeen && (!hint || hint.hidden);
}

/** 送信元などの端末の表示名(ノードのラベルの 1 行目と IP)。 */
function hostDisplay(id) {
    const n = nodes.get(id);
    const name = n && n.label ? String(n.label).split("\n")[0] : id;
    return name === id ? id : `${name} (${id})`;
}

/** 一覧を最大 8 件で表示し、残りは件数だけ出す(ツールチップが長くなりすぎないように)。 */
function listForTooltip(items) {
    const head = items.slice(0, 8).join(", ");
    return items.length > 8 ? `${head} ${STR.andMore(items.length - 8)}` : head;
}

/** 端末のまとめノード。 */
function subnetNodeData(key, ids) {
    const subnet = `${key.slice(4)}.0/24`;
    return {
        id: key,
        label: STR.subnetLabel(subnet, ids.length),
        shape: "icon",
        icon: ICONS.subnet,
        title: tooltipElement(STR.subnetTitle(subnet, ids.length)),
        customType: "subnet",
        dimmed: false, font: { color: NODE_FONT_COLOR }
    };
}

/** 種類ごとのアイコン。観測が無いグループは種類に関係なく灰色にする。 */
function groupIcon(kind, seen) {
    const base = GROUP_KIND_ICONS[kind] || ICONS.group;
    return { ...base, color: seen ? base.color : GROUP_COLOR_NO_DATA };
}

/** 個別のグループノード。データ面の観測状態をツールチップと色で示す。 */
function groupNodeData(key, g, senders, status) {
    const ip = ipOf(key);
    const vlan = vlanOf(key);
    const seen = isGroupDataSeen(key);
    const lines = [g.title || STR.groupTitle(ip), seen ? STR.groupDataSeen : STR.groupDataNotSeen];
    if (vlan !== null) lines.splice(1, 0, STR.vlanTag(vlan));
    // 送信元: データを観測した時だけ分かる。見えないときは「不明」と書き、「いない」とは書かない
    lines.push(senders.length ? STR.groupSenders(listForTooltip(senders.map(hostDisplay))) : STR.groupSendersUnknown);
    const requested = new Set();
    g.requested.forEach(list => list.forEach(s => requested.add(s)));
    if (requested.size) lines.push(STR.groupRequestedSources(listForTooltip(Array.from(requested).sort(compareIp))));
    lines.push(STR.groupReceivers(g.members.size));
    if (status.multi) lines.push(STR.groupMultiSender);
    if (status.noReceiver) lines.push(STR.groupNoReceiver);
    const fam = groupFamily(key);
    if (expandedFamilies.has(fam.key)) lines.push(STR.familyCollapseHint);
    const kind = MULTICAST_LABELS[ip] ? "generic" : groupKind(key);
    const warn = status.multi || status.noReceiver;
    return {
        id: key,
        label: (warn ? STR.warnMark : "") + getMulticastGroupLabel(key),
        shape: "icon",
        icon: groupIcon(kind, seen),
        title: tooltipElement(lines.join("\n")),
        customType: "group",
        dimmed: false, font: { color: NODE_FONT_COLOR },
        familyKey: fam.key
    };
}

/** 系統ごとのまとめノード。データを観測したグループが 1 つでもあれば色付きにする。 */
function familyNodeData(key, f) {
    const sorted = f.groups.map(ipOf).sort(compareIp);
    const range = `${sorted[0]} – ${sorted[sorted.length - 1]}`;
    // 系統内の種類が 1 つに決まればその色、混在ならまとめ用の色
    const kind = f.kinds.size === 1 ? Array.from(f.kinds)[0] : null;
    const color = kind && GROUP_KIND_ICONS[kind] ? GROUP_KIND_ICONS[kind].color : ICONS.family.color;
    const lines = [STR.familyTitle(f.label, f.groups.length, f.seen, f.members.size, range)];
    lines.push(f.senders.size ? STR.familySenders(f.senders.size) : STR.groupSendersUnknown);
    if (f.multi) lines.push(STR.familyMultiSender(f.multi));
    if (f.noReceiver) lines.push(STR.familyNoReceiver(f.noReceiver));
    const warn = f.multi > 0 || f.noReceiver > 0;
    return {
        id: key,
        label: (warn ? STR.warnMark : "") + STR.familyLabel(f.label, f.groups.length, f.seen),
        shape: "icon",
        icon: { ...ICONS.family, color: f.seen > 0 ? color : GROUP_COLOR_NO_DATA },
        title: tooltipElement(lines.join("\n")),
        customType: "family",
        dimmed: false, font: { color: NODE_FONT_COLOR }
    };
}

/** ノードの見た目の要約。前回の描画と同じなら DataSet を更新しない(大量グループ時の負荷対策)。 */
const renderedSignature = new Map();
function nodeSignature(n) {
    const title = n.title && n.title.textContent !== undefined ? n.title.textContent : String(n.title);
    return `${n.label}|${n.icon.code}|${n.icon.color}|${title}`;
}

/** 「データを観測中」のグループの集合。変わった時だけ描き直す(秒数表示の更新は描き直しの時に追随する)。 */
let lastSeenSnapshot = "";
function seenSnapshot() {
    const seen = [];
    groupDataLastSeen.forEach((_, ip) => { if (isGroupDataSeen(ip)) seen.push(ip); });
    groupModel.forEach((g, ip) => liveSenders(g).forEach(h => seen.push(`${ip}<${h}`)));
    return seen.sort().join(",");
}

function compareIp(a, b) {
    const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
    for (let i = 0; i < 4; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
    return 0;
}

// ------------------------------------------------------------------------------
// ⚠ の付いたグループの件数。押すと次のグループへ移動して強調し、詳細を開く(まとめの中なら開く)
// ------------------------------------------------------------------------------
let warnedGroups = [];
let warnCursor = 0;

function renderWarnSummary(keys) {
    warnedGroups = keys.slice().sort();
    const chip = document.getElementById("warn-summary");
    if (!chip) return;
    chip.hidden = warnedGroups.length === 0;
    chip.textContent = warnedGroups.length ? STR.warnSummary(warnedGroups.length) : "";
}

function goToNextWarning() {
    if (!warnedGroups.length || !network) return;
    const key = warnedGroups[warnCursor % warnedGroups.length];
    warnCursor += 1;
    // まとめノードの中にあれば、その系統を開いてから移動する
    const fam = groupFamily(key);
    if (!nodes.get(key) && nodes.get(fam.key)) {
        expandedFamilies.add(fam.key);
        renderGroups();
    }
    if (!nodes.get(key)) return;
    autoFitUntil = 0; // 移動した位置を自動の全体表示で上書きしない
    network.focus(key, { scale: 1.2, animation: { duration: 400 } });
    network.selectNodes([key]);
    setFocus(key);
    showDetail(key);
}

/** 状態バーに「N グループをまとめて表示中」を出す。 */
function renderGroupSummary(families, subnets = new Map()) {
    const chip = document.getElementById("group-summary");
    if (!chip) return;
    let groups = 0;
    families.forEach(f => { groups += f.groups.length; });
    let hosts = 0;
    subnets.forEach(ids => { hosts += ids.length; });
    const parts = [];
    if (groups) parts.push(STR.groupSummary(groups, families.size));
    if (hosts) parts.push(STR.hostSummary(hosts, subnets.size));
    chip.hidden = parts.length === 0;
    chip.textContent = parts.length ? `${parts.join(" / ")} — ${STR.summaryExpandHint}` : "";
}

/** まとめノードのダブルクリックで展開し、展開済みの系統/サブネットのノードのダブルクリックで畳む。 */
function toggleFamily(nodeId) {
    const node = nodes.get(nodeId);
    if (!node) return;
    const subnetKey = node.customType === "host" ? hostSubnetKey(node.id) : null;
    if (node.customType === "family" || node.customType === "subnet") {
        expandedFamilies.add(node.id);
    } else if (node.customType === "group" && expandedFamilies.has(node.familyKey)) {
        expandedFamilies.delete(node.familyKey);
    } else if (subnetKey && expandedFamilies.has(subnetKey)) {
        expandedFamilies.delete(subnetKey);
    } else {
        return;
    }
    renderGroups();
    noteLayoutChange(true);
}

/** 画面の初期化(リセット/NIC切替)でグループの状態も捨てる。 */
function resetGroupModel() {
    groupModel.clear();
    groupProto.clear();
    expandedFamilies.clear();
    groupDataLastSeen.clear();
    renderedSignature.clear();
    lastSeenSnapshot = "";
    othersReportsSeen = false;
    hostProtos.clear();
    querierVlans.clear();
    autoFitUntil = -1;
    lastNodeCount = 0;
    warnCursor = 0;
    showDetail(null);
    familyGroups.clear();
    focusId = null;
    dimmedEdges.clear();
    renderGroupSummary(new Map());
}

// ------------------------------------------------------------------------------
// 上部のフィルタを図にも反映する
// ログとフロー統計の絞り込みはサーバー側で行い(collectFilter → set_filter)、図はここで同じ条件に合わせる。
// ------------------------------------------------------------------------------
// 名前の付いたアドレスが、どのチェックボックスに属するか。どれか 1 つでも入っていれば表示する
const KNOWN_GROUP_FILTER_KEYS = {
    "224.0.0.1": ["IGMP"], "224.0.0.2": ["IGMP"], "224.0.0.22": ["IGMP"],
    "224.0.0.107": ["PTPv1", "PTPv2"], "224.0.1.129": ["PTPv1", "PTPv2"], "224.0.1.130": ["PTPv1", "PTPv2"],
    "224.0.1.131": ["PTPv1", "PTPv2"], "224.0.1.132": ["PTPv1", "PTPv2"],
    "224.0.0.230": ["Dante-ConMon"], "224.0.0.231": ["Dante-ConMon"], "224.0.0.232": ["Dante-ConMon"],
    "224.0.0.233": ["Dante-ConMon"],
    "224.0.0.251": ["mDNS"], "224.0.0.252": ["LLMNR"], "239.255.255.250": ["SSDP"], "239.255.255.255": ["SAP"],
    "239.254.3.3": ["Multicast-Other"] // Dante の PTP ログはポート 9998 で、バックエンドは未分類として扱う
};
// グループの種類ごとのチェックボックス。「sACN or Dante」は両方外したときだけ隠す
const KIND_FILTER_KEYS = {
    "sacn": ["sACN"], "dante": ["Dante-Audio"], "aes67": ["AES67-Audio"],
    "sacn-or-dante": ["sACN", "Dante-Audio"], "private": ["Multicast-Other"], "generic": ["Multicast-Other"]
};

/** 図に使うフィルタ条件。protos が null なら全種類を表示する。 */
function mapFilter() {
    const f = collectFilter();
    const protos = f.protos === null ? null : new Set(f.protos);
    const text = (f.text || "").trim().toLowerCase();
    return { protos, text, active: protos !== null || text !== "" };
}

/** 絞り込み文字列が「vlan 10」の形なら、その VLAN 番号。そうでなければ null(サーバー側と同じく完全一致で扱う)。 */
function vlanQuery(text) {
    const m = String(text || "").trim().toLowerCase().match(/^vlan\s+(\d+)$/);
    return m ? Number(m[1]) : null;
}

function nodeMatchesText(node, text) {
    const title = node.title && node.title.textContent !== undefined ? node.title.textContent : String(node.title || "");
    return [node.id, node.label, title].some(v => String(v || "").toLowerCase().includes(text));
}

function isGroupShownByFilter(key, g, filter, drawReceivers) {
    const ip = ipOf(key);
    // IGMP を外すと受信側(Join)の線を描かないので、送信を観測していないグループは何も表示する物が無い
    if (!drawReceivers && liveSenders(g).length === 0) return false;
    if (filter.protos !== null) {
        const keys = KNOWN_GROUP_FILTER_KEYS[ip] || KIND_FILTER_KEYS[groupKind(key)] || ["Multicast-Other"];
        if (!keys.some(k => filter.protos.has(k))) return false;
    }
    if (filter.text) {
        // 「vlan 10」でも探せるように、ラベル(VLAN 表記を含む)とあわせて照合する
        const vlan = vlanOf(key);
        const wanted = vlanQuery(filter.text);
        if (wanted !== null) return vlan === wanted;
        const groupText = `${ip} ${getMulticastGroupLabel(key)}`.toLowerCase();
        if (groupText.includes(filter.text)) return true;
        const hostIds = [...(drawReceivers ? g.members : []), ...liveSenders(g)];
        return hostIds.some(h => {
            const n = nodes.get(h);
            return n ? nodeMatchesText(n, filter.text) : String(h).includes(filter.text);
        });
    }
    return true;
}

// ------------------------------------------------------------------------------
// ノードを選ぶと、つながる線とノードだけを強調し、ほかを薄くする
// ------------------------------------------------------------------------------
// 薄くした時の色。vis-network 9 はアイコン形のノードに opacity を効かせないため、色そのものを暗くする
const DIM_ICON_COLOR = "rgba(100, 116, 139, 0.38)";
const DIM_FONT_COLOR = "rgba(248, 250, 252, 0.28)";
const DIM_EDGE_COLOR = "rgba(148, 163, 184, 0.14)";
const NODE_FONT_COLOR = "#f8fafc"; // initTopology の nodes.font.color と同じ
let focusId = null;
const dimmedEdges = new Map(); // edge id -> 薄くする前の color

function setFocus(nodeId) {
    focusId = nodeId;
    applyFocus();
}

/**
 * 強調の状態を DataSet に反映する。描き直しの後にも呼ぶ。
 * 描き直しで作り直したノードは dimmed:false になるので、ここで必要なら薄くし直す。
 */
function applyFocus() {
    if (!network) return;
    const focused = focusId !== null ? nodes.get(focusId) : null;
    if (focusId !== null && (!focused || focused.hidden)) focusId = null; // 選んでいたノードが消えた/隠れた
    const keepNodes = new Set();
    const keepEdges = new Set();
    if (focusId !== null) {
        keepNodes.add(focusId);
        network.getConnectedNodes(focusId).forEach(id => keepNodes.add(id));
        network.getConnectedEdges(focusId).forEach(id => keepEdges.add(id));
    }
    const nodeUpdates = [];
    nodes.forEach(n => {
        const dim = focusId !== null && !keepNodes.has(n.id);
        if (dim && !n.dimmed) {
            nodeUpdates.push({
                id: n.id, dimmed: true, undimmed: { icon: n.icon },
                icon: { ...n.icon, color: DIM_ICON_COLOR }, font: { color: DIM_FONT_COLOR }
            });
        } else if (!dim && n.dimmed && n.undimmed) {
            nodeUpdates.push({ id: n.id, dimmed: false, icon: n.undimmed.icon, font: { color: NODE_FONT_COLOR } });
        }
    });
    const edgeUpdates = [];
    edges.forEach(e => {
        const dim = focusId !== null && !keepEdges.has(e.id);
        if (dim && !dimmedEdges.has(e.id)) {
            dimmedEdges.set(e.id, e.color);
            edgeUpdates.push({ id: e.id, color: { color: DIM_EDGE_COLOR } });
        } else if (!dim && dimmedEdges.has(e.id)) {
            edgeUpdates.push({ id: e.id, color: dimmedEdges.get(e.id) });
            dimmedEdges.delete(e.id);
        }
    });
    dimmedEdges.forEach((_, id) => { if (!edges.get(id)) dimmedEdges.delete(id); });
    if (nodeUpdates.length) nodes.update(nodeUpdates);
    if (edgeUpdates.length) edges.update(edgeUpdates);
}

// ------------------------------------------------------------------------------
// グループごとのデータ面観測状態
// このPCはJoinしないため、Snooping環境ではストリームがこのポートに届かないのが正常。
// 「流れていない」と誤解させないよう、「このポートで観測したか」だけを区別して表示する。
// ------------------------------------------------------------------------------
// 集計は1秒間隔(UI_AGGREGATE_INTERVAL_SECONDS)。数回の取りこぼしで表示が揺れないよう余裕を持たせる
const GROUP_DATA_STALE_MS = 5000;
const groupDataLastSeen = new Map(); // group_ip -> 最後にデータ面パケットを観測した時刻(ms)
const GROUP_COLOR_NO_DATA = "#94a3b8"; // 未観測は異常ではないので赤・黄ではなく灰色にする

function markGroupDataSeen(groupIp, proto) {
    if (!groupIp) return;
    const wasSeen = isGroupDataSeen(groupIp);
    const protoChanged = Boolean(proto) && groupProto.get(groupIp) !== proto;
    groupDataLastSeen.set(groupIp, Date.now());
    if (proto) groupProto.set(groupIp, proto);
    if (!wasSeen || protoChanged) scheduleGroupRender();
}

// flow_stats はフローがある時しか届かないため、途絶したグループを定期的に「未観測」へ戻す
setInterval(() => {
    if (seenSnapshot() !== lastSeenSnapshot) scheduleGroupRender();
}, 1000);

// ==============================================================================
// 4. バックエンドから届くイベントのリアルタイム処理 (メイン)
// ==============================================================================
function handleNetworkEvent(data) {
    const srcIp = data.src_ip;
    noteHostProto(srcIp, data.filter_key || data.proto);
    const groupIp = data.group_ip;
    const groupKey = groupKeyOf(groupIp, data.vlan); // VLAN ごとに別のグループとして扱う
    const deviceName = data.resolved_name || srcIp;
    
    // MACアドレスの表示補填
    const subtitle = `IP: ${srcIp}\nMAC: ${data.src_mac}`;

    // A. プロトコル別のトポロジ分岐処理
    if (data.proto === "IGMP") {
        
        // A-1. 生存確認（クエリ）
        if (data.is_querier) {
            const vlan = data.vlan === undefined ? null : data.vlan;
            if (!querierVlans.has(srcIp)) querierVlans.set(srcIp, new Set());
            const vlans = querierVlans.get(srcIp);
            if (!vlans.has(vlan)) {
                vlans.add(vlan);
                scheduleGroupRender(); // このクエリアと結ぶグループが増える
            }
            const tagged = [...vlans].filter(v => v !== null).sort((a, b) => a - b);
            const vlanText = tagged.length ? ` ${tagged.map(v => STR.vlanTag(v)).join(", ")}` : "";
            updateNode(srcIp, `${deviceName}\n${STR.querierTag}${vlanText}`, "querier", subtitle);
        }
        
        // A-2. 受信開始（ジョイン）
        else if (data.event_code === "igmp_join") {
            // 受信端末ノードを追加
            updateNode(srcIp, deviceName, "host", subtitle);
            
            // グループへの参加をモデルに記録(グループ/まとめノードと線は renderGroups が描く)
            groupJoin(srcIp, groupKey, STR.groupTitle(groupIp), requestedSources(data), data.record_type);
        }

        // A-3. 受信停止（リーブ）
        else if (data.event_code === "igmp_leave") {
            groupLeave(srcIp, groupKey);
        }

        // A-4. IGMPv3 の送信元の取り消し(BLOCK_OLD_SOURCES)
        else if (data.event_code === "igmp_source_update" && data.record_type === "BLOCK_OLD_SOURCES") {
            groupBlockSources(srcIp, groupKey, data.sources || []);
        }
    }

    // B. クロック同期 (PTPv1/v2) のトポロジ表示処理
    else if (data.proto === "PTP") {
        // PTP送信元クロック端末を追加
        const ptpTag = data.version === 1 ? "PTPv1 / Dante" : "PTPv2 / AES67";
        updateNode(srcIp, `${deviceName}\n${STR.clockTag(ptpTag)}`, "sync", subtitle);
        
        // 共通同期グループにエッジを紐付け
        // PTPメッセージ自体がこのグループ宛てのデータ面パケットなので「観測あり」とする
        // PTP クロックはこのグループへ送信しているので、送信元として記録する
        recordSender(srcIp, groupKey, STR.ptpGroupTitle(groupIp));
        markGroupDataSeen(groupKey);
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
    // 表はフィルタに合うフローだけ(図は全件から描く)
    const shownFlows = flows.filter(f => f.match !== false);
    setBadge("badge-flow", shownFlows.length || null);
    shownFlows.slice(0, 50).forEach(f => {
        const row = document.createElement("tr");
        const host = f.resolved_name ? `${f.resolved_name} (${f.src_ip})` : f.src_ip;
        [f.proto, host, f.group_ip, f.pps, (f.bps / 1000).toFixed(0) + " kbps"].forEach(v => {
            const td = document.createElement("td");
            td.textContent = v;
            row.appendChild(td);
        });
        tbody.appendChild(row);
    });
    // 表示上限(50件)に関係なく、届いた全フローで送信元とグループの観測状態を更新する
    flows.forEach(f => {
        // 送信元をトポロジ上にも端末として出す(毎秒の更新で揺らさないよう、未登録の時だけ追加する)
        const existing = nodes.get(f.src_ip);
        const nameKnownLater = existing && existing.customType === "host" && f.resolved_name
            && !String(existing.label).startsWith(f.resolved_name);
        if (!existing || nameKnownLater) {
            updateNode(f.src_ip, f.resolved_name || f.src_ip, "host", `IP: ${f.src_ip}\nMAC: ${f.src_mac}`);
        }
        noteHostProto(f.src_ip, f.proto);
        const key = groupKeyOf(f.group_ip, f.vlan);
        recordSender(f.src_ip, key, STR.groupTitle(f.group_ip));
        markGroupDataSeen(key, f.proto);
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
    document.querySelectorAll(".panel-tab").forEach(t => {
        t.classList.toggle("active", t.dataset.tab === name);
        t.setAttribute("aria-selected", String(t.dataset.tab === name));
    });
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
    // ?tab=ptp|flow|log で開くタブを指定できる(ドキュメント用のスクリーンショット撮影などに使う)
    const initialTab = new URLSearchParams(location.search).get("tab");
    if (["log", "ptp", "flow"].includes(initialTab)) showTab(initialTab);

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
    const byVlan = Array.isArray(s.by_vlan) ? s.by_vlan : [];
    if (s.state === "ok" && byVlan.length > 1 && byVlan.some(v => v.vlan !== null && v.vlan !== undefined)) {
        // VLAN ごとにクエリアがいるのは正常。VLAN ごとの選出結果を並べる
        el.textContent = STR.querierPerVlan(byVlan.map(v => STR.querierVlanItem(v.vlan, v.elected, v.subnet)).join(" / "));
        el.className = "status-chip ok";
    } else if (s.state === "ok" && s.subnet_split) {
        // タグは見えないが、別のサブネットのクエリアが見えている(NIC がタグを外している可能性)
        el.textContent = STR.querierSubnetSplit(s.queriers.map(q => q.ip).join(", "));
        el.className = "status-chip ok";
    } else if (s.state === "ok") {
        const q = s.queriers[0];
        el.textContent = STR.querierOk(q.ip, q.version);
        el.className = "status-chip ok";
    } else if (s.state === "multiple") {
        // 競合しているのは同じ VLAN(タグ無しは同じ /24)の中だけ。その VLAN のクエリアと選出結果を示す
        const clash = byVlan.filter(v => v.state === "multiple");
        el.textContent = clash.length
            ? clash.map(v => (v.vlan === null || v.vlan === undefined ? (v.subnet ? `${v.subnet}: ` : "") : `${STR.vlanTag(v.vlan)}: `)
                + STR.querierMultiple(v.queriers.map(q => q.ip).join(", "), v.elected)).join(" / ")
            : STR.querierMultiple(s.queriers.map(q => q.ip).join(", "), s.elected);
        el.className = "status-chip warn";
    } else if (s.state === "none") {
        el.textContent = STR.querierNone;
        el.className = "status-chip error";
    } else {
        el.textContent = STR.querierChecking;
        el.className = "status-chip";
    }
    el.title = el.textContent; // 長いとき(VLAN が多い等)は省略されるので、全文をツールチップに出す
    // Queryは届くのに他の端末のReportが届かない: ミラーではない通常ポートの可能性を知らせる
    const hint = document.getElementById("report-visibility");
    const seenOthers = (s.reports_seen || 0) > 0;
    if ((hint && hint.hidden !== !s.reports_hidden) || seenOthers !== othersReportsSeen) {
        if (hint) hint.hidden = !s.reports_hidden;
        othersReportsSeen = seenOthers;
        scheduleGroupRender(); // 受信者なしの警告は、Join が見えるかどうかで出し分けている
    }
    // 常設のPassive注記も、診断が出ている間だけ黄色にして原因(Joinしない受動監視)と結び付ける
    const passive = document.getElementById("passive-status");
    if (passive) passive.classList.toggle("warn", !!s.reports_hidden);
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
            
            // 2. 画面ログ行の追加(フィルタに合わない IGMP は図の更新用に届くだけなのでログに出さない)
            if (data.log !== false) addStreamingLog(data);
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
    document.querySelectorAll("#filter-protos input, #filter-raw").forEach(el => el.addEventListener("change", () => {
        sendFilter();
        scheduleGroupRender(); // 図も同じ条件に合わせる
    }));
    document.getElementById("filter-text").addEventListener("input", () => {
        clearTimeout(filterTimer);
        filterTimer = setTimeout(() => {
            sendFilter();
            scheduleGroupRender();
        }, 300);
    });
    document.getElementById("btn-export").addEventListener("click", requestExport);

    // プロトコルのチェックの一括操作(全部外してから必要なものだけ入れる、という使い方のため)
    const setAllProtos = (checked) => {
        document.querySelectorAll("#filter-protos input[type=checkbox]").forEach(b => { b.checked = checked; });
        sendFilter();
        scheduleGroupRender();
    };
    document.getElementById("btn-protos-all").addEventListener("click", () => setAllProtos(true));
    document.getElementById("btn-protos-none").addEventListener("click", () => setAllProtos(false));

    // ⚠ の付いたグループへ順に移動する
    document.getElementById("warn-summary").addEventListener("click", goToNextWarning);

    // 詳細パネルを閉じる(ボタン / Esc)
    const closeDetail = () => {
        showDetail(null);
        setFocus(null);
        if (network) network.unselectAll();
    };
    document.getElementById("detail-close").addEventListener("click", closeDetail);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && detailId !== null) closeDetail(); });

    // 凡例の折りたたみ(状態はこのブラウザに覚える。保存できない環境でも動作は変わらない)
    const LEGEND_KEY = "igmpflow.legendCollapsed";
    const legendCard = document.getElementById("map-legend-card");
    const legendBtn = document.getElementById("legend-toggle");
    const applyLegend = (collapsed) => {
        legendCard.classList.toggle("collapsed", collapsed);
        legendBtn.setAttribute("aria-expanded", String(!collapsed));
    };
    const LEGEND_AUTO_COLLAPSE_PX = 1100; // これより狭いと凡例が図の左側を大きく隠す(900px で左端のノードが欠けた)
    let savedLegend = null;
    try { savedLegend = localStorage.getItem(LEGEND_KEY); } catch (e) { savedLegend = null; }
    applyLegend(savedLegend === null ? window.innerWidth < LEGEND_AUTO_COLLAPSE_PX : savedLegend === "1");
    legendBtn.addEventListener("click", () => {
        const collapsed = !legendCard.classList.contains("collapsed");
        applyLegend(collapsed);
        try { localStorage.setItem(LEGEND_KEY, collapsed ? "1" : "0"); } catch (e) { /* 保存できなくても表示は切り替わる */ }
    });

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
            freezeBtn.classList.add("active");
        } else {
            network.setOptions({ physics: { enabled: true } });
            freezeBtn.innerHTML = '<i class="fa-solid fa-pause"></i>';
            freezeBtn.title = STR.freezeHold;
            freezeBtn.classList.remove("active");
        }
    });

    // リセットボタン（画面トポロジの完全クリア）
    document.getElementById("btn-reset").addEventListener("click", () => {
        nodes.clear();
        edges.clear();
        resetGroupModel();
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
            resetGroupModel();
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
