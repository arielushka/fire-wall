# Fire Wall

Fire Wall is a simple Python network traffic monitor. It captures packets, checks
them against detection rules, shows the results in a small GUI, and saves security
events to JSON.

## Features

- Basic desktop GUI
- JSON traffic rules
- JSON detection settings
- Security events saved to `json/events.json`
- TCP SYN scan detection
- UDP sweep detection
- Packet burst detection

## Project Structure

```text
code/      Python source code
json/      settings, rules, services, and event output
gui.py     GUI launcher
```

## Installation

```powershell
git clone https://github.com/arielushka/fire-wall.git
cd fire-wall
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Run the project

Start the graphical interface:

```powershell
python gui.py
```

Enter the number of packets to capture, click **Start**, and use **Stop** to end
the capture after the next packet arrives. The dashboard shows allowed, flagged,
and alert counts. Flagged means that a packet matched a configured traffic rule;
it does not mean the operating system dropped the packet.

## JSON Files

- `json/app_settings.json` - app settings
- `json/firewall_rules.json` - rules used to flag or alert on traffic
- `json/detection_rules.json` - detection thresholds
- `json/services.json` - known services and ports
- `json/events.json` - generated events

## Traffic decisions

- `ALLOW` means no configured rule matched.
- `ALERT` means the packet matched a lower-priority warning rule.
- `FLAG` means the packet matched a traffic rule that should be reviewed.

The project is a monitor and detector. It does not create operating-system
firewall rules or claim that flagged packets were blocked.
