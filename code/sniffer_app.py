import argparse

from scapy.all import sniff

from config_loader import load_app_settings, load_json_config, resolve_project_path
from event_manager import EventManager
from FirewallManager import FirewallManager
from packet_parser import parse_packet
from security_event import SecurityEvent
from stats_manager import StatsManager
from threat_detector import ThreatDetector


def load_services():
    raw_services = load_json_config("services.json")
    return {int(port): info for port, info in raw_services.items()}


class NetworkFirewallApp:
    def __init__(self, settings):
        self.settings = settings
        self.services = load_services()
        self.detection_config = load_json_config("detection_rules.json")

        self.stats = StatsManager(
            services=self.services,
            warning_config=self.detection_config.get("stats_warnings", {}),
        )
        self.threat_detector = ThreatDetector(self.detection_config)
        self.events = EventManager(
            output_file=resolve_project_path(settings["event_output_file"]),
            app_name=settings["app_name"],
        )
        self.firewall = FirewallManager(services=self.services)
        self.firewall.load_default_rules()

    def run(self):
        self.print_banner()
        try:
            sniff(
                prn=self.handle_packet,
                store=False,
                count=self.settings["packet_count"],
            )
        except KeyboardInterrupt:
            print()
            print("Capture stopped by user.")

        self.print_finished()

    def handle_packet(self, packet):
        packet_info = parse_packet(packet)
        self.update_stats(packet_info)

        firewall_result = self.firewall.check_packet(packet_info)
        security_events = self.detect_security_events(packet_info, firewall_result)
        self.events.add_events(security_events)

        summary_interval = self.settings["summary_interval"]
        if summary_interval > 0 and self.stats.get_total_packets() % summary_interval == 0:
            self.stats.print_summary()

    def update_stats(self, packet_info):
        self.stats.update_protocol(packet_info["protocol"])
        self.stats.update_packet_size(packet_info["packet_size"])

        if packet_info["src_ip"] and packet_info["dst_ip"]:
            self.stats.update_ip_counts(packet_info["src_ip"], packet_info["dst_ip"])

        self.update_optional_port(packet_info["src_port"], self.stats.update_src_port)
        self.update_optional_port(packet_info["dst_port"], self.stats.update_dst_port)

    def update_optional_port(self, port, update_callback):
        if port is not None:
            update_callback(port)

    def detect_security_events(self, packet_info, firewall_result):
        events_found = []

        if firewall_result.action in ("BLOCK", "ALERT"):
            events_found.append(self.build_firewall_event(packet_info, firewall_result))

        if firewall_result.action != "BLOCK":
            events_found.extend(self.threat_detector.analyze_packet(packet_info))

        events_found.extend(self.stats.build_warning_events())
        return events_found

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

    def print_banner(self):
        print("=" * 64)
        print(self.settings["app_name"])
        print("=" * 64)
        print(f"Capturing {self.settings['packet_count']} packets. Press Ctrl+C to stop.")
        print(f"Summary prints every {self.settings['summary_interval']} packets.")
        print(f"Events file: {self.settings['event_output_file']}")

    def print_finished(self):
        print()
        print("=" * 64)
        print("Capture Finished")
        print("=" * 64)

        total_packets = self.stats.get_total_packets()
        summary_interval = self.settings["summary_interval"]
        summary_already_printed = (
            summary_interval > 0
            and total_packets > 0
            and total_packets % summary_interval == 0
        )

        if not summary_already_printed:
            self.stats.print_summary()

        self.firewall.print_summary()
        self.events.print_events()
        self.events.print_severity_summary()


def parse_args():
    settings = load_app_settings()
    parser = argparse.ArgumentParser(
        description="Fire Wall packet monitor"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=settings["packet_count"],
        help="number of packets to capture",
    )
    parser.add_argument(
        "--summary-interval",
        type=int,
        default=settings["summary_interval"],
        help="print a traffic summary every N packets",
    )
    parser.add_argument(
        "--events-file",
        default=settings["event_output_file"],
        help="JSON file path for saved security events",
    )
    return parser.parse_args(), settings


def main():
    args, settings = parse_args()
    settings["packet_count"] = args.count
    settings["summary_interval"] = args.summary_interval
    settings["event_output_file"] = args.events_file

    app = NetworkFirewallApp(settings)
    app.run()


if __name__ == "__main__":
    main()
