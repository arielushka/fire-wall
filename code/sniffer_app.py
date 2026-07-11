from config_loader import load_json_config, resolve_project_path
from event_manager import EventManager
from firewall_manager import FirewallManager
from os_firewall import WindowsFirewallBlocker
from packet_parser import parse_packet
from security_event import SecurityEvent
from stats_manager import StatsManager
from threat_detector import ThreatDetector


def load_services():
    services = load_json_config("services.json")
    return {int(port): info for port, info in services.items()}


class NetworkFirewallApp:
    def __init__(self, settings):
        self.services = load_services()
        detection_rules = load_json_config("detection_rules.json")

        self.stats = StatsManager(
            services=self.services,
            warning_config=detection_rules.get("stats_warnings", {}),
        )
        self.firewall = FirewallManager(services=self.services)
        self.os_firewall = WindowsFirewallBlocker(
            enabled=settings.get("os_blocking_enabled", True)
        )
        self.threat_detector = ThreatDetector(detection_rules)
        self.events = EventManager(
            output_file=resolve_project_path(settings["event_output_file"]),
            app_name=settings["app_name"],
        )

    def handle_packet(self, packet):
        packet_info = parse_packet(packet)
        self.update_stats(packet_info)

        firewall_result = self.firewall.check_packet(packet_info)
        new_events = self.find_events(packet_info, firewall_result)
        block_event = self.try_os_block(packet_info, firewall_result)
        if block_event:
            new_events.append(block_event)
        self.events.add_events(new_events)

    def try_os_block(self, packet_info, firewall_result):
        src_ip = packet_info["src_ip"]
        if firewall_result.action != "FLAG":
            return None
        if firewall_result.severity not in ("HIGH", "CRITICAL"):
            return None
        if src_ip in self.os_firewall.blocked_ips:
            return None
        if not self.os_firewall.block_ip(src_ip):
            return None

        return SecurityEvent(
            event_type="OS Firewall Block",
            severity=firewall_result.severity,
            source="windows_firewall",
            action="BLOCK",
            src_ip=src_ip,
            dst_ip=packet_info["dst_ip"],
            message=f"Windows Firewall is blocking inbound traffic from {src_ip}",
            details={"rule_name": self.os_firewall.rule_name(src_ip)},
        )

    def update_stats(self, packet_info):
        self.stats.update_protocol(packet_info["protocol"])
        if packet_info["src_ip"] and packet_info["dst_ip"]:
            self.stats.update_ip_counts(packet_info["src_ip"], packet_info["dst_ip"])

        if packet_info["src_port"] is not None:
            self.stats.update_src_port(packet_info["src_port"])

        if packet_info["dst_port"] is not None:
            self.stats.update_dst_port(packet_info["dst_port"])

    def find_events(self, packet_info, firewall_result):
        events = []

        if firewall_result.action in ("FLAG", "ALERT"):
            events.append(self.build_firewall_event(packet_info, firewall_result))

        if firewall_result.action != "FLAG":
            events.extend(self.threat_detector.analyze_packet(packet_info))

        events.extend(self.stats.build_warning_events())
        return events

    def build_firewall_event(self, packet_info, firewall_result):
        return SecurityEvent(
            event_type=f"Firewall {firewall_result.action.title()}",
            severity=firewall_result.severity,
            source="firewall_manager",
            action=firewall_result.action,
            src_ip=packet_info["src_ip"],
            dst_ip=packet_info["dst_ip"],
            message=firewall_result.reason,
            details={
                "protocol": packet_info["protocol"],
                "src_port": packet_info["src_port"],
                "dst_port": packet_info["dst_port"],
                "packet_size": packet_info["packet_size"],
            },
        )
