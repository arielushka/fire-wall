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

    def run(self):
        self.print_start_message()
        try:
            sniff(
                prn=self.handle_packet,
                store=False,
                count=self.settings["packet_count"],
            )
        except KeyboardInterrupt:
            print("\nCapture stopped by user.")

        self.print_final_report()

    def handle_packet(self, packet):
        packet_info = parse_packet(packet)
        self.update_stats(packet_info)

        firewall_result = self.firewall.check_packet(packet_info)
        new_events = self.find_events(packet_info, firewall_result)
        self.events.add_events(new_events)

        if self.should_print_summary():
            self.stats.print_summary()

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

        if firewall_result.action in ("BLOCK", "ALERT"):
            events.append(self.build_firewall_event(packet_info, firewall_result))

        if firewall_result.action != "BLOCK":
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

    def should_print_summary(self):
        interval = self.settings["summary_interval"]
        total_packets = self.stats.get_total_packets()
        return interval > 0 and total_packets % interval == 0

    def print_start_message(self):
        print("=" * 64)
        print(self.settings["app_name"])
        print("=" * 64)
        print(f"Capturing {self.settings['packet_count']} packets. Press Ctrl+C to stop.")
        print(f"Summary prints every {self.settings['summary_interval']} packets.")
        print(f"Events file: {self.settings['event_output_file']}")

    def print_final_report(self):
        print("\n" + "=" * 64)
        print("Capture Finished")
        print("=" * 64)

        if not self.summary_was_just_printed():
            self.stats.print_summary()

        self.firewall.print_summary()
        self.events.print_events()
        self.events.print_severity_summary()

    def summary_was_just_printed(self):
        interval = self.settings["summary_interval"]
        total_packets = self.stats.get_total_packets()
        return interval > 0 and total_packets > 0 and total_packets % interval == 0


def parse_args():
    settings = load_app_settings()
    parser = argparse.ArgumentParser(description="Fire Wall packet monitor")
    parser.add_argument("--count", type=int, default=settings["packet_count"])
    parser.add_argument("--summary-interval", type=int, default=settings["summary_interval"])
    parser.add_argument("--events-file", default=settings["event_output_file"])
    args = parser.parse_args()
    return args, settings


def main():
    args, settings = parse_args()
    settings["packet_count"] = args.count
    settings["summary_interval"] = args.summary_interval
    settings["event_output_file"] = args.events_file

    app = NetworkFirewallApp(settings)
    app.run()


if __name__ == "__main__":
    main()
