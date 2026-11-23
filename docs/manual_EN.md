# IGMP-FLOW User Manual

This manual explains what you need to install, how to connect the PC to your network, how to read the screen, and how to
troubleshoot. For a short overview see [README.md](../README.md). Japanese version: [manual_JP.md](manual_JP.md).

## 1. What you need

### 1.1 Hardware and network

| Item | Why |
|---|---|
| A Windows 10/11 PC with a wired network port (NIC) | Runs IGMP-FLOW and captures packets |
| A **managed switch with port mirroring (SPAN)** | Lets the PC see traffic of other devices. Without it you only see this PC's own traffic and a little broadcast/multicast |
| Optional: a USB/second NIC | Keep the monitoring port separate from your normal network connection |

Port mirroring is configured on the switch (vendor specific): choose the ports or VLAN to watch as the *source* and the port
the PC is plugged into as the *destination*. To see IGMP Reports and Queries, mirror the uplink to the querier and the ports of
the devices you care about. Virtual adapters (for example Hyper-V or VPN adapters) only see the host's own traffic.

### 1.2 Software to install

| Software | Required? | Notes |
|---|---|---|
| **Npcap** | **Yes (Windows)** | The packet-capture driver. Download it from <https://npcap.com/> and install it with the default options. It is *not* bundled with IGMP-FLOW and has its own license (the free edition has usage limits and no redistribution; large or commercial deployments may need the paid OEM license). If capture fails after a default install, reinstall Npcap and tick **"Install Npcap in WinPcap API-compatible Mode"** |
| A modern web browser (Edge, Chrome, Firefox) | Yes | The UI runs in the browser. The PC showing the UI needs internet access, because two UI libraries (vis-network and Font Awesome) are loaded from public CDNs |
| Python 3.12 | Only if you run from source | Not needed for `IGMP-FLOW.exe` |
| Python packages `scapy`, `websockets` | Only if you run from source | `python -m pip install -r requirements.txt` |
| Wireshark | Optional | Handy for opening the `.pcap` files IGMP-FLOW writes. Not required |

You do **not** need to install a database, a web server, or any other service. Nothing listens outside your own PC
(the UI and WebSocket servers bind to `127.0.0.1` only).

### 1.3 Permissions

Capturing may require **administrator rights**, depending on how Npcap was installed (for example when "Restrict Npcap driver's
access to Administrators only" was selected). If the interface list is empty or capture does not start, run IGMP-FLOW as
administrator (right-click -> *Run as administrator*).

`IGMP-FLOW.exe` is not code-signed, so Windows SmartScreen may show a warning the first time. Only run builds you obtained
from a source you trust, or run from source.

## 2. Starting and stopping

1. Connect the PC to the mirror port and make sure the NIC has an IP address (it can be any address; a link-local one is fine).
2. Start `IGMP-FLOW.exe` (or `python app.py` in a terminal opened in the project folder).
3. Your browser opens `http://localhost:8000`. The status at the top right should read **Live monitoring (connected)**.
4. Pick the NIC connected to the mirror port in the drop-down at the top (the app auto-selects one; check it is the right one).

To stop: click **Exit** (top bar) and confirm. Closing the browser tab does **not** stop the app; monitoring and PCAP recording
continue. After you close the browser a dialog asks whether to exit (start with `--no-close-prompt` to disable it for unattended
recording). Starting the app a second time only re-opens the page.

Try the UI without any hardware: `python scripts/demo_simulator.py` replays a sample scenario.

## 3. The screen

### 3.1 Top bar

- **All / None** buttons tick or untick every protocol at once (untick all, then tick only what you want to see).
- **Protocol check boxes** (IGMP, PTPv1, PTPv2, mDNS, SSDP, SAP, LLMNR, Dante ConMon, Dante audio, sACN, AES67 audio, Other multicast):
  choose what is shown in the log, Stream stats and the map. Filters are applied by the program itself; **everything is
  still recorded to PCAP**. On the map, unticking a kind hides its groups (a 239.255.x.x group not yet known to be sACN
  or Dante is hidden only when both are unticked), and unticking *IGMP* hides the receiver (Join) lines. A device is hidden
  when none of the protocols it was seen using is ticked and none of the groups it is connected to is shown.
- **PTP types**: show only some PTP message types (for example only Announce).
- **Filter box**: shows only traffic whose IP, MAC, group or device name contains the text. The map shows only the
  matching groups and devices and what they are connected to.
- **Show data plane per packet**: audio streams are normally summarized once per second; tick this to see each packet
  (use it together with a narrow filter).
- **Export CSV** with optional time range (`YYYY-MM-DD HH:MM:SS`, local time) and the audio handling option.
- **Stop capture / Start capture**, **Exit**.
- **Status chips**: *Querier* (who is the IGMP querier; red when none is seen), *PTP* (warnings), *PCAP* (packets recorded, drops).
- **No Join/Leave seen** (yellow chip): Queries arrive, but no IGMP Report from any other device has been seen for 30 s after a
  General Query. With IGMP snooping, Reports go only to the switch's router (querier) port, so this usually means the PC is on a
  normal port, not a mirror (SPAN) port. It also appears when no device has joined any group. Reports sent by this PC itself are
  not counted. The chip clears once a Report from another device is seen, and is re-evaluated after Reset or a NIC change.

### 3.2 Topology map (upper area)

- Purple crown: the IGMP **querier**. Green people icon: a multicast **group**. Blue laptop: a **device**. Orange clock: a
  **PTP clock** source.
- A line from a device to a group means the device joined that group; the line disappears when it leaves.
- Buttons at the bottom right: fit to window, freeze/resume the layout (monitoring is not paused), and **restart** (clears the map,
  log and monitors and starts a new PCAP file; the map is rebuilt from Queries/Reports that arrive afterwards, typically within the
  query interval of about 125 s).
- Drag the bar between the map and the lower panel to resize; double-click it to reset; use **Maximize** to enlarge the lower panel.

### 3.3 Lower panel tabs

- **Log**: one row per event (time, protocol, event, host, group). **Pause log** only stops adding rows to this view.
- **PTP status**: for each clock and message type, the *measured* interval and the interval the clock *declares*, plus grandmaster
  ID and priorities. Warnings appear for a lost Announce, several grandmasters in one domain, and interval mismatches.
- **Stream stats**: stream data (Dante audio, sACN, AES67 audio, other multicast) as packets/s and bit/s, refreshed every second.
  Only streams that reach this port are listed. IGMP-FLOW never joins a group (see the *Passive* chip at the top), so with IGMP
  snooping a stream is visible only on a mirror (SPAN) port or a switch that floods multicast.
- **Group colour on the map**: coloured = stream data seen on this port in the last few seconds; grey = not seen on this port.
  Grey is not an error and does not mean the stream has stopped.
- **Group icons**: a light bulb is sACN (lighting), a speaker is Dante audio, a wave is AES67 audio. sACN and Dante both use
  239.255.x.x, and an IGMP Join carries no port number, so a 239.255.x.x group shows a question mark
  ("sACN universe N or Dante") until its stream data is seen on this port.
- **Summary nodes**: when there are more than 40 groups, groups in the same address range (for example the sACN/Dante range of 239.255.x.x)
  are drawn as one node that shows how many groups it holds and how many have stream data. When there are more than
  30 devices, devices in the same /24 subnet are drawn as one node. Queriers, PTP clocks and devices that are sending stream
  data are always shown on their own, so you can see who sends.
  Double-click a summary node to show what it contains; double-click one of those nodes to put them back together.
  The status bar says how many groups and devices are summarised.
- **Senders**: an orange arrow from a device to a group means stream data from that device to the group was seen on this
  port in the last few seconds. Blue lines without arrows are receivers (IGMP Join). Senders are known only when the stream
  reaches this port (a mirror port); otherwise the group's tooltip says "Senders: unknown on this port", which does not mean
  there is no sender. When a receiver asks for specific sources (IGMPv3), the tooltip lists them too.
- **⚠ on a group**: more than one sender to the same group (check for a duplicate multicast address), or stream data with
  no receiver's Join. The second check is made only when other devices' Joins are visible on this port (not while the
  *No Join/Leave seen* chip is shown). Hover over the group for which one applies.
- **Click a node** to highlight it and what it is connected to; everything else is dimmed. A panel on the right lists the
  details (senders, receivers, VLAN, warning reasons, groups a device sends to or receives) with buttons to copy IP
  addresses; click a name in the panel to move to it. Click an empty area, the × button or press Esc to clear.
- **⚠ chip in the status bar**: shows how many groups are marked ⚠; click it to move to the next one (a summary node is
  opened if needed).
- **Legend**: click its title to hide or show it (remembered in this browser).
- The map is fitted to the window automatically while data arrives and the layout settles, and after a summary node is
  opened or closed. It stops doing so once you zoom or move the map yourself.

## 4. Typical tasks

- **Who joined which group?** Look at the map, or filter the log to *IGMP* and type the group address in the filter box.
- **Is there an IGMP querier?** Check the *Querier* chip. "No querier!" means IGMP snooping on the switches may fail; "Multiple
  queriers" means more than one querier in the same VLAN and shows which one should win (the lowest IP); one querier
  per VLAN is normal (section 10). Query version (v1/v2/v3), robustness and interval are
  shown in the log detail and CSV.
- **Am I seeing everything?** Check that the yellow *No Join/Leave seen* chip is not shown and that the groups you care about are
  coloured, not grey. If not, the PC is probably on a normal port of a snooping switch: move it to a mirror (SPAN) port (see section 1).
- **Is the clock healthy?** Open *PTP status*. Dante uses PTPv1; AES67/ST 2110 use PTPv2. Both can coexist. Check that one grandmaster
  announces per domain and that measured intervals match the declared ones.
- **Find unwanted traffic:** tick only *SSDP*, *LLMNR* and *Other multicast* to see office-network or unknown multicast on the audio network.
- **Record for hours or days:** leave the app running (use `--no-close-prompt`). Everything goes to PCAP; PCAP files are never deleted
  automatically, so watch the disk space (the PCAP chip warns when the folder is large).
- **Analyse afterwards:** use **Export CSV**, or open the `.pcap` files in Wireshark.

## 5. Files and where they are

| What | Where |
|---|---|
| PCAP recordings, CSV exports, logs | `%LOCALAPPDATA%\IGMP-FLOW\data\` (`captures`, `exports`, `logs`). Change with the environment variable `IGMP_FLOW_DATA_DIR` |
| CSV columns | Timestamp, Event, Device Name, IP Address, MAC Address, Multicast Group, Protocol, Packets, Detail, Event Code, VLAN (empty when untagged) |

PCAP files keep audio packets as headers only (first 128 bytes) to save space; control traffic (IGMP, PTP, mDNS and so on) is stored in full.
These files contain real IP/MAC addresses and device names, so treat them as confidential and do not upload them to public places.

Command line export:

```
python -m backend.pcap_export <file.pcap> -o out.csv --proto IGMP --proto PTPv2 --ptp-type Announce --since "2026-01-01 10:00:00"
```

Command line options of the app: `-i/--interface`, `--interactive`, `-p/--port`, `--capture-dir`, `--no-pcap`, `--live-csv igmp|all|off`,
`--no-close-prompt`.

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "Npcap is not installed" at start | Install Npcap (section 1.2) and restart |
| NIC list empty, or nothing is captured | Run as administrator; check Npcap is installed; select the NIC connected to the mirror port; confirm the mirror is configured on the switch |
| The map is a dense ball of labels | Update to 0.2.2 or later: many groups and devices are then drawn as summary nodes |
| "Multiple queriers" on a network with several VLANs | Since 0.2.2 this appears only for more than one querier in the same VLAN (or, without VLAN tags, the same /24). See section 10 |
| A lighting (sACN) network shows "Dante" | Fixed in 0.2.2: sACN and Dante are told apart by UDP port. A group seen only by its Join shows "sACN universe N or Dante" |
| A group is on the map but grey / missing from Stream stats | Normal on a non-mirror port with IGMP snooping: IGMP-FLOW does not join, so the switch does not forward the stream here. Use a mirror (SPAN) port to see the stream itself |
| "No Join/Leave seen" chip | The PC is on a normal port of a snooping switch. Mirror the uplink to the querier (or the devices' ports) to this PC's port |
| Only this PC's traffic is visible | The port is not a mirror (SPAN) port, or the NIC is a virtual adapter |
| No Join/Leave appear for devices | Joins are only sent when a device starts or refreshes a subscription (typically after a Query); wait for the next Query (about 125 s) or reconnect a device |
| The screen shows "Disconnected (reconnecting...)" | The app is not running or a different instance uses port 8765; start the app (or close the other one) |
| Page opens but the map or icons are missing | The PC has no internet access (CDN libraries cannot load) |
| Old screen or English/Japanese mix after an update | Restart the app completely (the old process keeps running after the browser is closed) and reload with Ctrl+F5 |
| "UI HTTP server could not start (port 8000)" | Another program uses port 8000; close it |
| Text such as `'=...` appears in CSV names | Intentional: names starting with `=`, `+`, `-` or `@` get a leading apostrophe so spreadsheets do not run them as formulas |
| The app does not stop | Use **Exit**. If the app was started before an update it may ignore the button; end `IGMP-FLOW` in Task Manager |

## 7. Uninstall

Delete the program folder (or `IGMP-FLOW.exe`) and the data folder `%LOCALAPPDATA%\IGMP-FLOW`. Npcap is a separate program and is removed from
*Settings -> Apps*.

## 8. Privacy and security in short

IGMP-FLOW is passive (it never transmits), listens only on `127.0.0.1`, rejects connections from other web pages, and treats network
data as untrusted. It has no login: do not expose ports 8000/8765 outside the PC. Details are in the README.

## 9. Known multicast groups

IGMP-FLOW gives these addresses a name on the map and in the log. Use the table to look up an address you see.
An address that is not listed can still be normal: other software on the same PC or device (lighting, control or AV
software) may join its own groups. The *Source* column names where each entry was checked.

| Address | Port (UDP) | Protocol / use | Shown in IGMP-FLOW as | Source |
|---|---|---|---|---|
| 224.0.0.1 | – | IGMP: all hosts (General Query destination) | All Hosts | IANA multicast registry |
| 224.0.0.2 | – | IGMP: all routers (IGMPv2 Leave destination) | All Routers | IANA multicast registry |
| 224.0.0.22 | – | IGMPv3 membership reports | IGMPv3 Reports | IANA multicast registry |
| 224.0.0.107 | 319, 320 | PTP peer delay | PTP peer delay | IANA multicast registry |
| 224.0.1.129 | 319, 320 | PTP clock sync (default domain; Dante PTPv1, AES67 PTPv2) | PTP clock sync | IANA, Audinate |
| 224.0.1.130 – 224.0.1.132 | 319, 320 | PTP clock sync (other domains) | PTP clock sync (alternate domain) | IANA, Audinate |
| 224.0.0.230 – 224.0.0.233 | 8700 – 8708 | Dante control and monitoring (ConMon) | Dante control & monitoring | Audinate |
| 224.0.0.251 | 5353 | mDNS (Bonjour): device discovery, used by Dante Controller | mDNS | IANA, Audinate |
| 224.0.0.252 | 5355 | LLMNR (Windows name resolution); not needed on an AV network | LLMNR | RFC 4795 |
| 239.254.3.3 | 9998 | Dante PTP logging (only when enabled) | Dante PTP logging | Audinate |
| 239.255.255.250 | 1900 | SSDP / UPnP discovery (office devices, Windows) | SSDP | UPnP Device Architecture |
| 239.255.255.255 | 9875 | SAP: AES67 stream announcements | SAP | RFC 2974 |

Ranges that IGMP-FLOW recognises by address **and port**:

| Address range | Port (UDP) | Protocol / use | Shown in IGMP-FLOW as | Source |
|---|---|---|---|---|
| 239.255.0.0 – 239.255.249.255 | 5568 | sACN (ANSI E1.31) lighting data; universe N uses 239.255.(N÷256).(N mod 256) | sACN universe N | ANSI E1.31 (via lighting vendors' manuals) |
| 239.255.0.0/16 | 4321 | Dante multicast audio/video | Dante audio | Audinate |
| any 239.x.x.x | 5004 | AES67 (RTP) audio; 239.69.x.x is a common default but each device can be set differently | AES67 audio | AES67 vendors' guides |

sACN and Dante share 239.255.x.x. An IGMP Join carries no port number, so a 239.255.x.x group seen only by its Join is shown
as "sACN universe N or Dante" until its stream data is seen on this port.

Sources: IANA *IPv4 Multicast Address Space Registry*; Audinate *Dante Information for Network Administrators*;
RFC 2974 (SAP); RFC 4795 (LLMNR); UPnP Device Architecture (SSDP); ANSI E1.31 (sACN).

## 10. Networks split into VLANs

Audio, lighting, video and control are often kept in separate VLANs, each with its own IGMP querier. IGMP works per VLAN,
so one querier per VLAN is normal.

- **To see several VLANs at once**, mirror a trunk port (or several VLANs) to the PC's port. A normal access port shows only
  its own VLAN.
- **When VLAN tags are visible**, IGMP-FLOW records the VLAN ID of each event (CSV: last column *VLAN*). The map shows the
  same group address in two VLANs as two nodes labelled *VLAN n*, links each querier only to the groups of its own VLAN, and
  the *Querier* chip lists the elected querier per VLAN. "Multiple queriers" is reported only when one VLAN has more than one.
  Type `vlan 10` in the filter box to show one VLAN.
- **On Windows, the tags are often not visible**: many network adapter drivers remove the 802.1Q tag before capture software
  sees the frame. Some adapters have a driver or registry setting that keeps the tags (Intel documents one for its adapters);
  check your adapter's documentation. Without tags, IGMP-FLOW cannot tell VLANs apart: the same group address in two VLANs is
  shown as one node. It then links each group to the querier in the same /24 subnet as its devices, and if it sees queriers
  in different subnets, the chip says so ("probably separate VLANs") instead of warning about multiple queriers.

Sources: Wireshark wiki *CaptureSetup/VLAN*; Intel support article 000005498 (keeping VLAN tags on Intel adapters).
