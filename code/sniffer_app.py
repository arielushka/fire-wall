from config_loader import load_json_config, resolve_project_path
from event_manager import EventManager
from FirewallManager import FirewallManager
from packet_parser import parse_packet
from security_event import SecurityEvent
from stats_manager import StatsManager
from threat_detector import ThreatDetector


def load_services():
    services = load_json_config("services.json")
    return {int(port): info for port, info in services.items()}


class NetworkFirewallApp:
    def __init__(self, settings):
        self.settings = settings
        self.services = load_services()
        self.detection_rules = load_json_config("detection_rules.json")

        self.stats = StatsManager(
            services=self.services,
            warning_config=self.detection_rules.get("stats_warnings", {}),
        )
        self.firewall = FirewallManager(services=self.services)
        self.threat_detector = ThreatDetector(self.detection_rules)
        self.events = EventManager(
            output_file=resolve_project_path(settings["event_output_file"]),
            app_name=settings["app_name"],
        )

        self.firewall.load_default_rules()

    def handle_packet(self, packet):
        packet_info = parse_packet(packet)
        self.update_stats(packet_info)

        firewall_result = self.firewall.check_packet(packet_info)
        new_events = self.find_events(packet_info, firewall_result)
        self.events.add_events(new_events)

    def update_stats(self, packet_info):
        self.stats.update_protocol(packet_info["protocol"])
        self.stats.update_packet_size(packet_info["packet_size"])

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
