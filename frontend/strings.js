/* IGMP-FLOW UI strings (strings.js)
 *
 * All user-facing text that app.js generates at runtime lives here, so wording can be reviewed
 * (and, if needed, translated) in one place. Static text in index.html is plain English.
 * Logic must never branch on these strings: the backend sends a language-independent
 * `event_code` (e.g. "igmp_join") for that purpose.
 */
const STR = {
    // Known multicast groups shown on topology group nodes
    multicastLabels: {
        "224.0.1.129": { tag: "PTP clock sync (Dante/AES67)", icon: "⏰" },
        "224.0.0.251": { tag: "mDNS (Bonjour)", icon: "👥" },
        "239.255.255.250": { tag: "SSDP (UPnP)", icon: "👥" },
        "224.0.0.252": { tag: "LLMNR (Windows)", icon: "👥" },
        "224.0.0.1": { tag: "All Hosts (general query)", icon: "👥" },
        "224.0.0.2": { tag: "All Routers", icon: "👥" },
        "224.0.0.22": { tag: "IGMPv3 Reports", icon: "👥" }
    },
    groupDante: "Dante audio/control",
    groupPrivate: "Private stream",
    groupGeneric: "Group",

    // Topology nodes
    switchNoIp: "Switch without IP\n[Querier]",
    deviceNoIp: "Device without IP",
    unknown: "unknown",
    noIpSubtitle: (mac) => `IP: 0.0.0.0 (unassigned)\nMAC: ${mac}`,
    querierTag: "[Querier]",
    clockTag: (ptp) => `[Clock - ${ptp}]`,
    groupTitle: (ip) => `Multicast group IP: ${ip}`,
    ptpGroupTitle: (ip) => `PTP multicast IP: ${ip}`,

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
