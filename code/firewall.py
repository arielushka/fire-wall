import json
import time
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid4

from scapy.all import ICMP, IP, TCP, UDP

ROOT = Path(__file__).resolve().parent.parent
JSON_DIR = ROOT / "json"


def load_json(name):
    with (JSON_DIR / name).open("r", encoding="utf-8") as file:
        return json.load(file)


def save_json(name, data):
    with (JSON_DIR / name).open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


def now():
    return datetime.now().isoformat(timespec="seconds")


def is_public_ip(value):
    try:
        return ip_address(value).is_global
    except (TypeError, ValueError):
        return False


def parse_packet(packet):
    info = {
        "protocol": "Non-IP",
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "flags": "",
        "size": len(packet),
    }

    if IP not in packet:
        return info

    info["src_ip"] = packet[IP].src
    info["dst_ip"] = packet[IP].dst
    info["protocol"] = "Other IP"

    if TCP in packet:
        info["protocol"] = "TCP"
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
        info["flags"] = str(packet[TCP].flags)
    elif UDP in packet:
        info["protocol"] = "UDP"
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport
    elif ICMP in packet:
        info["protocol"] = "ICMP"

    return info


class FirewallMonitor:
    def __init__(self):
        self.settings = load_json("app_settings.json")
        self.rules = load_json("firewall_rules.json")
        self.detection = load_json("detection_rules.json")

        self.packet_count = 0
        self.allowed = 0
        self.blocked = 0
        self.alerts = 0
        self.events = []
        self.protocols = {}
        self.scan_ports = {}
        self.scan_alerted = set()
        self.burst_times = {}
        self.burst_alerted = set()

        self.save_events()

    def handle_packet(self, packet):
        info = parse_packet(packet)
        self.packet_count += 1
        self.protocols[info["protocol"]] = self.protocols.get(info["protocol"], 0) + 1

        action, reason, severity = self.check_firewall(info)
        if action == "BLOCK":
            self.blocked += 1
            self.add_event("Firewall Block", severity, action, reason, info)
            self.save_events()
            return

        if action == "ALERT":
            self.alerts += 1
            self.add_event("Firewall Alert", severity, action, reason, info)
        else:
            self.allowed += 1

        self.check_scan(info)
        self.check_burst(info)
        self.save_events()

    def check_firewall(self, info):
        protocol = info["protocol"]
        src_ip = info["src_ip"]
        dst_port = info["dst_port"]

        if protocol in self.rules.get("blocked_protocols", []):
            return "BLOCK", f"Blocked protocol: {protocol}", "LOW"

        if info["size"] > self.rules.get("max_packet_size", 1500):
            return "ALERT", "Large packet", "MEDIUM"

        if dst_port in self.rules.get("blocked_dst_ports", []):
            return "BLOCK", f"Blocked destination port: {dst_port}", "HIGH"

        sensitive_ports = self.rules.get("sensitive_public_dst_ports", [])
        if protocol == "TCP" and dst_port in sensitive_ports and is_public_ip(src_ip):
            return "BLOCK", f"Public IP tried sensitive port: {dst_port}", "HIGH"

        if dst_port in self.rules.get("alert_dst_ports", []):
            return "ALERT", f"Watched destination port: {dst_port}", "LOW"

        return "ALLOW", "Allowed", "LOW"

    def check_scan(self, info):
        if not info["src_ip"] or not info["dst_ip"] or info["dst_port"] is None:
            return

        if info["protocol"] == "TCP" and "S" not in info["flags"]:
            return
        if info["protocol"] not in ("TCP", "UDP"):
            return

        rules = self.detection.get("scan_detection", {})
        key = (info["protocol"], info["src_ip"], info["dst_ip"])
        ports = self.scan_ports.setdefault(key, {})
        ports[info["dst_port"]] = time.time()

        if info["protocol"] == "UDP":
            window = rules.get("udp_time_window_seconds", 10)
            threshold = rules.get("udp_port_threshold", 12)
        else:
            window = rules.get("tcp_syn_time_window_seconds", 10)
            threshold = rules.get("tcp_syn_port_threshold", 8)

        cutoff = time.time() - window
        for port, seen_at in list(ports.items()):
            if seen_at < cutoff:
                del ports[port]

        if len(ports) >= threshold and key not in self.scan_alerted:
            self.scan_alerted.add(key)
            self.add_event(
                "Port Scan",
                "HIGH",
                "ALERT",
                f"{info['src_ip']} tried many ports on {info['dst_ip']}",
                info,
            )

    def check_burst(self, info):
        src_ip = info["src_ip"]
        if not src_ip:
            return

        rules = self.detection.get("burst_detection", {})
        if not rules.get("enabled", True):
            return

        window = rules.get("time_window_seconds", 5)
        threshold = rules.get("packet_threshold", 40)
        times = self.burst_times.setdefault(src_ip, [])
        times.append(time.time())

        cutoff = time.time() - window
        self.burst_times[src_ip] = [value for value in times if value >= cutoff]

        if len(self.burst_times[src_ip]) >= threshold and src_ip not in self.burst_alerted:
            self.burst_alerted.add(src_ip)
            self.add_event("Traffic Burst", "MEDIUM", "INVESTIGATE", f"Many packets from {src_ip}", info)

    def add_event(self, event_type, severity, action, message, info):
        self.events.append(
            {
                "id": str(uuid4()),
                "time": now(),
                "type": event_type,
                "severity": severity,
                "action": action,
                "src_ip": info["src_ip"],
                "dst_ip": info["dst_ip"],
                "message": message,
                "details": {
                    "protocol": info["protocol"],
                    "src_port": info["src_port"],
                    "dst_port": info["dst_port"],
                    "size": info["size"],
                },
            }
        )

    def save_events(self):
        summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for event in self.events:
            summary[event["severity"]] = summary.get(event["severity"], 0) + 1

        save_json(
            "events.json",
            {
                "app_name": self.settings.get("app_name", "Fire Wall"),
                "generated_at": now(),
                "event_count": len(self.events),
                "severity_summary": summary,
                "events": self.events,
            },
        )

    def summary_text(self):
        lines = [
            f"Packets: {self.packet_count}",
            f"Allowed: {self.allowed}",
            f"Blocked: {self.blocked}",
            f"Alerts: {self.alerts}",
            "",
            "Protocols:",
        ]

        if not self.protocols:
            lines.append("No packets yet.")
        else:
            for protocol, count in sorted(self.protocols.items()):
                lines.append(f"{protocol}: {count}")

        return "\n".join(lines)
