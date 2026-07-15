# Fire Wall
Fire Wall is a small Python network monitor with a desktop interface. It captures
packets, checks simple traffic and detection rules, saves security events to JSON,
and can block high-risk public source IPs with Windows Firewall.

## What it does

- Captures a fixed number of packets or runs continuously
- Shows packet, alert, flag, block, and event counters
- Detects TCP SYN scans, UDP sweeps, traffic bursts, and unusual traffic patterns
- Reads rules and settings from JSON files
- Saves detected events to `json/events.json`
- Adds a real Windows Firewall rule for high-risk public source IPs

## Installation

Clone the project:

```powershell
git clone https://github.com/arielushka/fire-wall.git
cd fire-wall
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
```

Install the dependency:

```powershell
pip install -r requirements.txt
```

## Run the project

Start the GUI:

```powershell
python gui.py
```

Choose a network adapter before starting a capture.

- If you use Wi-Fi, choose the adapter with `Wi-Fi`, `Wireless`, or the wireless
  card name, for example `Intel(R) Wi-Fi`.
- If you use a network cable, choose the physical `Ethernet` controller.
- `WAN Miniport` entries are Windows connection adapters.
- `Wi-Fi Direct` is used for direct wireless device connections.
- `VirtualBox` is a virtual-machine adapter.
- `Tailscale` is a VPN adapter.
- `Loopback` only sees traffic that stays inside your computer.

The main adapter is normally the physical Wi-Fi or Ethernet adapter that currently
has internet access. If all counters stay at zero, select the other physical
adapter and open a website to create traffic.

## Capture controls

- **Start** captures the number entered in the **Packets** box.
- **Continuous** keeps capturing until you press **Stop**.
- **Stop** ends either capture mode, even when the network is idle.

## Dashboard

- **Packets** is the total number of captured packets.
- **Allowed** means no traffic rule matched.
- **Flagged** means a packet matched a rule that should be reviewed.
- **Blocked IPs** counts source IPs with a real Windows Firewall rule.
- **Alerts** counts lower-priority firewall alerts.
- **Events** counts all saved security events from the current capture.

The **Events** tab shows event details. The **Rules** tab shows the JSON settings
currently used by the application.

## How blocking works

Automatic blocking is deliberately simple. A packet must be flagged as `HIGH` or
`CRITICAL`, and its source must be a public IP address. The program then adds an
inbound Windows Firewall rule named:

```text
Fire Wall - Block <IP>
```

The packet that caused the detection has already arrived. The new rule blocks
later inbound traffic from the same IP. Run the GUI with administrator permission
when you want Windows Firewall rules to be created.

To keep detection enabled without changing Windows Firewall, edit
`json/app_settings.json`:

```json
"os_blocking_enabled": false
```

## Configuration files

- `json/app_settings.json` contains general application settings.
- `json/firewall_rules.json` contains rules that flag or alert on traffic.
- `json/detection_rules.json` contains scan, burst, and warning thresholds.
- `json/services.json` maps common ports to service names and severities.
- `json/events.json` is created automatically and stores captured events.

## Project structure

```text
gui.py                 starts the desktop application
code/gui_app.py        builds the GUI and controls packet capture
code/sniffer_app.py    processes each captured packet
code/firewall_manager.py checks traffic rules
code/os_firewall.py    creates Windows Firewall rules
code/threat_detector.py detects scans, sweeps, and bursts
code/stats_manager.py  counts traffic and creates statistical warnings
code/event_manager.py  saves security events to JSON
code/packet_parser.py  converts Scapy packets into simple dictionaries
json/                  stores settings, rules, services, and events
```
