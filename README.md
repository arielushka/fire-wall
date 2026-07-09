# Fire Wall

Fire Wall is a small Python project I made to learn how network traffic works.
It can sniff packets, apply simple firewall rules, and show the results in a basic GUI.

## Run

Install Scapy first:

```powershell
pip install -r requirements.txt
```

Start the GUI:

```powershell
python gui.py
```

Or run from the terminal:

```powershell
python sniffer.py --count 200
```

## Files

- `gui.py` starts the GUI.
- `sniffer.py` starts the CLI version.
- `code/firewall.py` has the packet parsing, rules, detections, and event saving.
- `json/` has the rules and output files.

## Note

This is a learning project. It does not change Windows Firewall rules and does not block packets at the operating-system level.
