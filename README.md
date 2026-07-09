# Fire Wall

Fire Wall is a simple Python program I built to learn how network traffic works.
It can capture packets, check basic firewall rules, show results in a small GUI, and save events to JSON.

## Features

- Basic desktop GUI
- CLI packet capture mode
- JSON firewall rules
- JSON detection settings
- Security events saved to `json/events.json`
- TCP SYN scan detection
- UDP sweep detection
- Packet burst detection

## Project Structure

```text
code/      Python source code
json/      settings, rules, services, and event output
git/       project git notes
gui.py     GUI launcher
sniffer.py CLI launcher
```

## Requirements

- Python 3.9 or newer
- Scapy
- Npcap on Windows
- Administrator/root permissions may be required for packet capture

Npcap download:

```text
https://npcap.com/
```

## Installation

```powershell
git clone https://github.com/arielushka/fire-wall.git
cd fire-wall
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Run GUI

```powershell
python gui.py
```

## Run CLI

```powershell
python sniffer.py --count 200
```

## JSON Files

- `json/app_settings.json` - app settings
- `json/firewall_rules.json` - firewall rules
- `json/detection_rules.json` - detection thresholds
- `json/services.json` - known services and ports
- `json/events.json` - generated events

## Note

`BLOCK` is a decision inside this monitor. It does not change Windows Firewall rules and does not drop packets at the operating-system level.
