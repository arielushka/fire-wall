# Anti Virus Network Firewall

A simple Python network firewall monitor with a basic GUI, CLI mode, and JSON-based rules.

The project captures packets with Scapy, checks them against firewall rules, detects suspicious traffic, and saves security events to JSON.

Current version: `1.0.0`

## Features

- Simple desktop GUI with dashboard, events, and rules tabs.
- CLI mode for quick packet capture.
- JSON firewall configuration.
- JSON detection thresholds.
- Security event output in `json/events.json`.
- TCP SYN port-scan detection.
- UDP sweep detection.
- Packet burst detection.
- Basic traffic statistics and suspicious pattern warnings.

## Project Structure

```text
anti_virus/
  code/        Python source code
  json/        settings, firewall rules, detection rules, services, event output
  git/         project git notes/history files
  gui.py       starts the GUI
  sniffer.py   starts the CLI capture
```

## Requirements

- Python 3.9 or newer
- Scapy
- Npcap on Windows for packet capture
- Administrator/root permissions may be required for live sniffing

Download Npcap for Windows:

```text
https://npcap.com/
```

## Installation

Clone the project:

```powershell
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Run the GUI

```powershell
python gui.py
```

In the GUI:

- Set the packet count.
- Click `Start`.
- Watch packet counts, firewall actions, and events.
- Open the `Rules` tab to see the active JSON configuration.

## Run the CLI

Capture the default amount of packets:

```powershell
python sniffer.py
```

Capture 200 packets:

```powershell
python sniffer.py --count 200
```

Save events to another JSON file:

```powershell
python sniffer.py --events-file json/lab_events.json
```

## JSON Files

- `json/app_settings.json` - app name, version, packet count, summary interval, and event output file.
- `json/firewall_rules.json` - blocked ports, alert ports, protocols, sensitive services, and flow rules.
- `json/detection_rules.json` - thresholds for scan detection, UDP sweep detection, burst detection, and stats warnings.
- `json/services.json` - known ports, service names, categories, and default severities.
- `json/events.json` - generated security events from the latest run.
- `json/data_events.json` - older saved event data.

## Push to GitHub

After editing the project, commit and push it:

```powershell
git add .
git commit -m "Add basic firewall GUI"
git push
```

If this is a new GitHub repository:

```powershell
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
git branch -M main
git push -u origin main
```

## Important Note

`BLOCK` means the project recorded a firewall decision inside the monitor. It does not install Windows firewall rules and does not drop packets at the operating-system level.
