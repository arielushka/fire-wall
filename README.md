# Anti Virus Network Sniffer

Simple Python packet sniffer that uses Scapy to capture traffic, summarize packet statistics, and flag possible TCP port scans.

## Files

- `sniffer.py` starts packet capture and routes packets to the analysis classes.
- `stats_manager.py` tracks protocol, IP, and port statistics.
- `scan_detector.py` detects possible port scans from repeated SYN packets across multiple destination ports.
- `event_manager.py` stores security events and prints them in a readable format.

## Requirements

- Python 3
- Scapy

Install dependencies:

```powershell
pip install scapy
```

Run:

```powershell
python sniffer.py
```
