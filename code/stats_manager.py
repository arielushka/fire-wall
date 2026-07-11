from config_loader import load_json_config
from security_event import SecurityEvent


class StatsManager:
    PROTOCOLS = ("TCP", "UDP", "ICMP", "Other IP", "Non-IP")

    def __init__(self, services=None, warning_config=None):
        if not services:
            services = load_json_config("services.json")
            services = {int(port): info for port, info in services.items()}

        if not warning_config:
            rules = load_json_config("detection_rules.json")
            warning_config = rules.get("stats_warnings", {})

        self.services = services
        self.warning_config = warning_config
        self.src_counts = {}
        self.dst_counts = {}
        self.src_port_counts = {}
        self.dst_port_counts = {}
        self.protocol_counts = {name: 0 for name in self.PROTOCOLS}
        self.protocol_counts["Total"] = 0
        self.reported_warnings = set()

    def update_protocol(self, protocol):
        if protocol not in self.PROTOCOLS:
            protocol = "Other IP"
        self.protocol_counts[protocol] += 1
        self.protocol_counts["Total"] += 1

    def update_ip_counts(self, src_ip, dst_ip):
        self.src_counts[src_ip] = self.src_counts.get(src_ip, 0) + 1
        self.dst_counts[dst_ip] = self.dst_counts.get(dst_ip, 0) + 1

    def update_src_port(self, port):
        self.src_port_counts[port] = self.src_port_counts.get(port, 0) + 1

    def update_dst_port(self, port):
        self.dst_port_counts[port] = self.dst_port_counts.get(port, 0) + 1

    def get_total_packets(self):
        return self.protocol_counts["Total"]

    def build_warning_events(self):
        total = self.get_total_packets()
        if total == 0:
            return []

        events = []
        events.extend(self.traffic_concentration_events(total))
        events.extend(self.protocol_events(total))
        events.extend(self.unknown_port_events(total))
        return events

    def traffic_concentration_events(self, total):
        events = []
        minimum = self.warning_config.get("traffic_concentration_min_packets", 20)
        ratio = self.warning_config.get("traffic_concentration_ratio", 0.5)

        for direction, counts in (
            ("source", self.src_counts),
            ("destination", self.dst_counts),
        ):
            for ip, count in counts.items():
                warning_key = ("traffic_concentration", direction, ip)
                if count < minimum or count / total <= ratio:
                    continue
                if not self.first_report(warning_key):
                    continue

                events.append(
                    SecurityEvent(
                        event_type="Traffic Concentration",
                        severity="MEDIUM",
                        source="stats_manager",
                        action="INVESTIGATE",
                        src_ip=ip if direction == "source" else None,
                        dst_ip=ip if direction == "destination" else None,
                        message=(
                            f"High {direction} traffic concentration for {ip}: "
                            f"{count} packets ({self.percent(count)})"
                        ),
                        details={
                            "direction": direction,
                            "packet_count": count,
                            "total_packets": total,
                        },
                    )
                )

        return events

    def protocol_events(self, total):
        events = []
        checks = [
            (
                "Non-IP",
                self.warning_config.get("non_ip_ratio", 0.3),
                "LOW",
                "Large amount of Non-IP traffic",
            ),
            (
                "ICMP",
                self.warning_config.get("icmp_ratio", 0.3),
                "MEDIUM",
                "High ICMP traffic, possible ping sweep or flood",
            ),
        ]

        for protocol, limit, severity, message in checks:
            count = self.protocol_counts[protocol]
            warning_key = ("protocol_ratio", protocol)
            if count / total <= limit or not self.first_report(warning_key):
                continue

            events.append(
                SecurityEvent(
                    event_type="Protocol Anomaly",
                    severity=severity,
                    source="stats_manager",
                    action="INVESTIGATE",
                    message=message,
                    details={
                        "protocol": protocol,
                        "packet_count": count,
                        "total_packets": total,
                        "ratio": self.percent(count),
                    },
                )
            )

        return events

    def unknown_port_events(self, total):
        events = []
        minimum = self.warning_config.get("unknown_port_min_count", 4)

        for direction, counts in (
            ("source", self.src_port_counts),
            ("destination", self.dst_port_counts),
        ):
            for port, count in counts.items():
                warning_key = ("unknown_port_activity", direction, port)
                is_known = port in self.services

                if is_known or count < minimum or not self.first_report(warning_key):
                    continue

                events.append(
                    SecurityEvent(
                        event_type="Unknown Port Activity",
                        severity="LOW",
                        source="stats_manager",
                        action="INVESTIGATE",
                        message=(
                            f"Repeated traffic on unknown {direction} port "
                            f"{port}: {count} packets"
                        ),
                        details={
                            "direction": direction,
                            "port": port,
                            "packet_count": count,
                            "total_packets": total,
                        },
                    )
                )

        return events

    def first_report(self, warning_key):
        if warning_key in self.reported_warnings:
            return False
        self.reported_warnings.add(warning_key)
        return True

    def percent(self, count):
        total = self.get_total_packets()
        return "0.0%" if total == 0 else f"{count * 100.0 / total:5.1f}%"
