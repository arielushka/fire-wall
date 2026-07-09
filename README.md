# Anti Virus Network Firewall v1.0

A professionalized Python network-monitoring firewall simulator built with Scapy.
It captures live packets, evaluates configurable firewall rules, detects suspicious
traffic patterns, and writes structured JSON security events.

This project is a monitoring and decision layer. It does not install operating
system firewall rules or replace a production EDR/IDS product.

## Version 1.0 Highlights

- Split configuration into JSON files under `config/`.
- Moved packet parsing into `packet_parser.py`.
- Added `ThreatDetector` for TCP SYN scans, UDP sweeps, and burst traffic.
- Added richer firewall rules for high-risk remote admin, Windows, database, and exposed service ports.
- Added structured event output metadata with app name and version.
- Added CLI flags for packet count, summary interval, and event output path.
- Reduced duplicate code by centralizing service metadata and stats updates.
- Added a small unittest suite for core firewall and scan behavior.

## Project Structure

- `sniffer.py` - main CLI entry point and application orchestration.
- `FirewallManager.py` - configurable firewall rule engine.
- `threat_detector.py` - higher-level threat detection coordinator.
- `scan_detector.py` - reusable port-scan/sweep detector.
- `packet_parser.py` - Scapy packet to plain dictionary parser.
- `stats_manager.py` - traffic statistics and statistical warning events.
- `event_manager.py` - security event storage, summary, and JSON persistence.
- `security_event.py` - validated event model.
- `firewall_decision.py` - validated firewall decision model.
- `config/app_settings.json` - app version, packet count, summary interval, output file.
- `config/firewall_rules.json` - firewall ports, protocols, sensitive services, flow rules.
- `config/detection_rules.json` - scan, sweep, burst, and stats warning thresholds.
- `config/services.json` - shared service/port metadata.
- `tests/test_firewall_v1.py` - core behavior tests.
- `VERSION` - current project version.

## Requirements

- Python 3.9 or newer.
- Scapy.
- Administrator/root privileges may be required for live capture.
- Npcap is usually required on Windows for Scapy sniffing.

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Run

Default run:

```powershell
python sniffer.py
```

Capture 50 packets and save events to a custom file:

```powershell
python sniffer.py --count 50 --summary-interval 25 --events-file data/lab_events.json
```

By default, events are written to:

```text
data/events.json
```

## Configure Firewall Rules

Edit `config/firewall_rules.json`.

Important fields:

- `blocked_protocols` blocks complete protocols such as `ICMP`.
- `blocked_dst_ports` blocks risky destination ports.
- `alert_dst_ports` creates an alert but still allows analysis to continue.
- `sensitive_public_dst_ports` blocks public TCP sources that try to reach sensitive services.
- `blocked_flow_rules` supports exact source IP to destination IP and destination port blocks.
- `max_packet_size` alerts on oversized packets.

Example flow rule:

```json
{
    "src_ip": "203.0.113.10",
    "dst_ip": "192.168.1.20",
    "dst_port": 445
}
```

## Detection Rules

Edit `config/detection_rules.json`.

Current detections:

- TCP SYN port scan.
- UDP port sweep.
- Per-source packet burst.
- Traffic concentration.
- High ICMP or Non-IP ratio.
- Repeated unknown port activity.

## Test

Run the local test suite:

```powershell
python -m unittest discover -s tests
```

## Notes

- `BLOCK` means the monitor recorded a firewall decision. It does not drop the packet at OS level.
- The old root-level `data_events.json` file is left untouched for historical runs.
- The default v1.0 event output is `data/events.json`.
