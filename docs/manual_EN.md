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

- **Protocol check boxes** (IGMP, PTPv1, PTPv2, mDNS, SSDP, SAP, LLMNR, Dante ConMon, Dante audio, AES67 audio, Other multicast):
  choose what is sent to the screen. Filters are applied by the program itself; **everything is still recorded to PCAP**.
- **PTP types**: show only some PTP message types (for example only Announce).
- **Filter box**: shows only traffic whose IP, MAC, group or device name contains the text.
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
- **Stream stats**: audio streams (Dante audio, AES67 audio, other multicast) as packets/s and bit/s, refreshed every second.
  Only streams that reach this port are listed. IGMP-FLOW never joins a group (see the *Passive* chip at the top), so with IGMP
  snooping a stream is visible only on a mirror (SPAN) port or a switch that floods multicast.
- **Group colour on the map**: green = stream data seen on this port in the last few seconds; grey = not seen on this port.
  Grey is not an error and does not mean the stream has stopped.

## 4. Typical tasks

- **Who joined which group?** Look at the map, or filter the log to *IGMP* and type the group address in the filter box.
- **Is there an IGMP querier?** Check the *Querier* chip. "No querier!" means IGMP snooping on the switches may fail; "Multiple
  queriers" shows all of them and which one should win (the lowest IP). Query version (v1/v2/v3), robustness and interval are
  shown in the log detail and CSV.
- **Am I seeing everything?** Check that the yellow *No Join/Leave seen* chip is not shown and that the groups you care about are
  green. If not, the PC is probably on a normal port of a snooping switch: move it to a mirror (SPAN) port (see section 1).
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
| CSV columns | Timestamp, Event, Device Name, IP Address, MAC Address, Multicast Group, Protocol, Packets, Detail, Event Code |

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
