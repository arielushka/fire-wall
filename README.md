# Anti Virus Network Monitor

A simple Python network monitoring project built with Scapy. It captures live packets, summarizes traffic, applies basic firewall-style rules, and raises security events for suspicious activity such as TCP port scans.

This project is educational and local-monitoring focused. It does not install a system firewall rule, drop packets from the operating system, or replace a real antivirus/IDS product.

## Features

- Captures live packets with Scapy.
- Parses IP, TCP, UDP, and ICMP traffic into a shared packet dictionary.
- Tracks traffic statistics by protocol, source IP, destination IP, source port, destination port, and packet size.
- Applies configurable firewall checks before scan detection.
- Blocks or alerts on common risky destination ports such as Telnet, SMB, RDP, RPC, NetBIOS, and FTP.
- Blocks ICMP by default.
- Blocks public TCP sources that try to access sensitive services on ports `445` or `3389`.
- Detects possible TCP SYN port scans across many destination ports in a short time window.
- Prints readable summaries and security events to the terminal.

## Project Files

- `sniffer.py` - main entry point. Captures packets, parses them, updates stats, runs firewall checks, runs scan detection, and prints final summaries.
- `FirewallManager.py` - contains firewall rule storage, packet evaluation logic, counters, and firewall summaries.
- `stats_manager.py` - tracks protocol, IP, port, packet-size statistics, and warning patterns.
- `scan_detector.py` - detects possible TCP SYN port scans by tracking unique destination ports per source/destination pair.
- `event_manager.py` - stores and prints firewall and scan security events.
- `AI_readme` - detailed implementation notes for AI agents or future maintainers.

## Requirements

- Python 3.9 or newer recommended.
- Scapy.
- Administrator/root privileges may be required for live packet capture.
- Npcap is usually required on Windows for Scapy sniffing.

Install Python dependencies:

```powershell
pip install scapy
```

## Run

From the project directory:

```powershell
python sniffer.py
```

By default, `sniffer.py` captures `200` packets and prints a summary every `200` packets. Press `Ctrl+C` to stop early.

The default capture settings are defined near the top of `sniffer.py`:

```python
PACKET_COUNT = 200
SUMMARY_INTERVAL = 200
```

## How It Works

1. `sniffer.py` starts Scapy with `sniff(prn=handle_packet, store=False, count=PACKET_COUNT)`.
2. Each captured packet is converted into a plain dictionary by `parse_packet`.
3. `StatsManager` updates traffic counters for every packet, including packets later marked as blocked.
4. `FirewallManager` evaluates the packet.
5. Blocked packets are recorded as firewall events and are not used for port-scan detection.
6. Alerted and allowed TCP SYN packets are passed to `ScanDetector`.
7. `EventManager` stores and immediately prints each security event.
8. When capture ends, the app prints stats, firewall, and event summaries.

## Default Firewall Behavior

`FirewallManager.load_default_rules()` enables these rules:

- Block destination ports:
  - `21` FTP
  - `23` Telnet
  - `135` RPC
  - `139` NetBIOS
  - `445` SMB
  - `3389` RDP
- Block protocol:
  - `ICMP`
- Block public TCP source IPs trying to reach sensitive destination ports:
  - `445` SMB
  - `3389` RDP

Firewall decisions are returned as dictionaries:

```python
{
    "action": "ALLOW" | "ALERT" | "BLOCK",
    "reason": "...",
    "severity": "LOW" | "MEDIUM" | "HIGH",
}
```

## Port Scan Detection

`ScanDetector` looks only at TCP SYN packets without ACK. A source/destination pair is considered suspicious when it tries at least `8` different destination ports within `10` seconds.

These defaults are set in `scan_detector.py`:

```python
ScanDetector(port_threshold=8, time_window=10)
```

Each pair alerts only once per program run.

## Notes

- The project currently prints output to the console only.
- Events are stored in memory and are not written to disk.
- There is no command-line interface yet.
- There are no automated tests yet.
- The firewall is a software decision layer inside the monitor. It records `BLOCK` events but does not stop traffic at the OS/network level.

