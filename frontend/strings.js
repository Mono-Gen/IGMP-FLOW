/* IGMP-FLOW UI strings (strings.js)
 *
 * All user-facing text that app.js generates at runtime lives here, so wording can be reviewed
 * (and, if needed, translated) in one place. Static text in index.html is plain English.
 * Logic must never branch on these strings: the backend sends a language-independent
 * `event_code` (e.g. "igmp_join") for that purpose.
 */
const STR = {
    // Known multicast groups shown on topology group nodes
    // Keep this list in step with "Known multicast groups" in docs/manual_EN.md and manual_JP.md
    // (backend/tests/test_known_groups_doc.py checks it).
    multicastLabels: {
        "224.0.1.129": { tag: "PTP clock sync (Dante/AES67)", icon: "⏰" },
        "224.0.1.130": { tag: "PTP clock sync (alternate domain)", icon: "⏰" },
        "224.0.1.131": { tag: "PTP clock sync (alternate domain)", icon: "⏰" },
        "224.0.1.132": { tag: "PTP clock sync (alternate domain)", icon: "⏰" },
        "224.0.0.107": { tag: "PTP peer delay", icon: "⏰" },
        "239.254.3.3": { tag: "Dante PTP logging (if enabled)", icon: "⏰" },
        "224.0.0.230": { tag: "Dante control & monitoring", icon: "👥" },
        "224.0.0.231": { tag: "Dante control & monitoring", icon: "👥" },
        "224.0.0.232": { tag: "Dante control & monitoring", icon: "👥" },
        "224.0.0.233": { tag: "Dante control & monitoring", icon: "👥" },
        "224.0.0.251": { tag: "mDNS (Bonjour)", icon: "👥" },
        "239.255.255.255": { tag: "SAP (AES67 session announcements)", icon: "👥" },
        "239.255.255.250": { tag: "SSDP (UPnP)", icon: "👥" },
        "224.0.0.252": { tag: "LLMNR (Windows)", icon: "👥" },
        "224.0.0.1": { tag: "All Hosts (general query)", icon: "👥" },
        "224.0.0.2": { tag: "All Routers", icon: "👥" },
        "224.0.0.22": { tag: "IGMPv3 Reports", icon: "👥" }
    },
    // Group kinds. 239.255.x.x is used by both sACN (lighting) and Dante audio; an IGMP Join carries
    // no port, so until stream data is seen the label shows both possibilities.
    groupDante: "Dante audio",
    groupAes67: "AES67 audio",
    groupSacn: (u) => `sACN universe ${u}`,
    groupSacnOrDante: (u) => `sACN universe ${u} or Dante`,
    groupPrivate: "Private stream",
    groupGeneric: "Group",

    // Summary nodes that stand for many groups of one address family
    familySacnDante: "sACN / Dante (239.255.x.x)",
    familyLinkLocal: "Link-local (224.0.0.x)",
    family239255Other: "239.255.x.x outside sACN/Dante (SSDP, SAP, ...)",
    familyLabel: (name, n, seen) => `${name}\n${n} groups` + (seen ? ` (${seen} with data)` : ""),
    familyTitle: (name, n, seen, hosts, range) =>
        `${name}: ${n} groups (${range})\n` +
        `Joined by ${hosts} device(s). Stream data seen on this port: ${seen} group(s).\n` +
        `Shown as one node because there are many groups. Double-click to show each group.`,
    familyCollapseHint: "Double-click to group these again.",
    // Senders and receivers of a group. Senders are known only when stream data reaches this port.
    groupSenders: (list) => `Senders (stream data seen): ${list}`,
    groupSendersUnknown: "Senders: unknown on this port (stream data does not reach it)",
    groupRequestedSources: (list) => `Sources requested by receivers (IGMPv3): ${list}`,
    groupReceivers: (n) => `Receivers (Join seen): ${n}`,
    groupMultiSender: "⚠ More than one sender: check for a duplicate multicast address",
    groupNoReceiver: "⚠ Stream data arrives, but no receiver's Join is seen",
    familySenders: (n) => `Senders (stream data seen): ${n} device(s)`,
    familyMultiSender: (n) => `⚠ ${n} group(s) with more than one sender`,
    familyNoReceiver: (n) => `⚠ ${n} group(s) with stream data but no receiver's Join`,
    andMore: (n) => `and ${n} more`,
    warnMark: "⚠ ",
    // Summary nodes that stand for many devices in one /24 subnet
    subnetLabel: (subnet, n) => `${subnet}\n${n} devices`,
    subnetTitle: (subnet, n) =>
        `${n} devices in ${subnet}\n` +
        `Shown as one node because there are many devices. Double-click to show each device.\n` +
        `Queriers, PTP clocks and devices sending stream data are always shown individually.`,
    groupSummary: (n, f) => `${n} groups in ${f} summary node(s)`,
    hostSummary: (n, f) => `${n} devices in ${f} summary node(s)`,
    summaryExpandHint: "double-click one to expand",

    // Topology nodes
    switchNoIp: "Switch without IP\n[Querier]",
    deviceNoIp: "Device without IP",
    unknown: "unknown",
    noIpSubtitle: (mac) => `IP: 0.0.0.0 (unassigned)\nMAC: ${mac}`,
    querierTag: "[Querier]",
    clockTag: (ptp) => `[Clock - ${ptp}]`,
    groupTitle: (ip) => `Multicast group IP: ${ip}`,
    ptpGroupTitle: (ip) => `PTP multicast IP: ${ip}`,
    // Data-plane observation state of a group (this PC never joins, so "not seen" is not "not flowing")
    groupDataSeen: "Stream data: seen on this port in the last few seconds",
    groupDataNotSeen: "Stream data: not seen on this port.\nThis PC does not join groups; with IGMP snooping the stream\nreaches only joined ports or a mirror (SPAN) port.\nThis does not mean the stream is not flowing.",

    // Connection
    connected: "Live monitoring (connected)",
    disconnected: "Disconnected (reconnecting...)",
    notConnected: "Not connected to the server",
    notConnectedStop: "Not connected. To stop the app, end IGMP-FLOW in Task Manager.",
    noNics: "No capture interface found",

    // Log panel
    pauseLog: "Pause log",
    resumeLog: (n) => `Resume log (${n} queued)`,
    maximize: "Maximize",
    restore: "Restore",
    freezeResume: "Resume topology layout",
    freezeHold: "Freeze topology layout (monitoring is not paused)",
    suppressed: (n) => `${n} entries hidden to reduce load (already recorded in PCAP)`,

    // Capture / PCAP
    captureStop: "Stop capture",
    captureStart: "Start capture",
    captureStopped: "Capture stopped (nothing is written to PCAP)",
    captureSwitchFailed: (e) => `Failed to switch capture: ${e}`,
    pcapDisabled: "PCAP: disabled (not all packets are recorded)",
    pcapError: (e) => `PCAP error: ${e}`,
    pcapDropped: (p, d) => `PCAP: ${p} pkts / ${d} dropped`,
    pcapLarge: (p) => `PCAP: ${p} pkts / capture folder is large (no auto-delete)`,
    pcapRecording: (p) => `PCAP recording: ${p} pkts`,
    pcapSynced: "Warning: the capture folder looks cloud-synced (OneDrive etc.); real IP/MAC data may be uploaded. Change the data folder.",

    // PTP / querier status
    ptpWarnings: (n) => `PTP warnings: ${n}`,
    ptpOk: "PTP: OK",
    ptpNone: "PTP: ---",
    querierOk: (ip, v) => `Querier: ${ip} (IGMPv${v})`,
    querierMultiple: (ips, elected) => `Multiple queriers: ${ips} (should be ${elected})`,
    // VLANs: one querier per VLAN is normal
    vlanTag: (v) => `VLAN ${v}`,
    querierPerVlan: (items) => `Queriers: ${items}`,
    querierVlanItem: (vlan, ip, subnet) => vlan === null || vlan === undefined
        ? `${subnet || "untagged"} ${ip}` : `VLAN ${vlan} ${ip}`,
    querierSubnetSplit: (ips) => `Queriers in different subnets: ${ips} (probably separate VLANs; VLAN tags not visible)`,
    querierNone: "No querier! (IGMP snooping may not work)",
    querierChecking: "Querier: checking",

    // CSV export
    exportRunning: "Generating CSV...",
    exportFailed: (e) => `CSV export failed: ${e}`,
    exportWarnings: (n) => ` (${n} warnings)`,
    exportDone: (out, rows, warn) => `CSV written: ${out} (${rows} rows)${warn}`,

    // Shutdown
    shutdownConfirm: "Exit IGMP-FLOW?\nMonitoring and PCAP recording will stop.",
    shutdownOverlay: "IGMP-FLOW has exited.<br>Monitoring and PCAP recording are stopped.<br>You can close this tab."
};
