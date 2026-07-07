from security_event import SecurityEvent


class StatsManager:
    # A small service list makes the port output easier to read.
    SERVICES = {
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        135: "RPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
    }

    PROTOCOLS = ("TCP", "UDP", "ICMP", "Other IP", "Non-IP")

    def __init__(self):
        # Dictionaries make it easy to count new IPs and ports as they appear.
        self.src_counts = {}
        self.dst_counts = {}
        self.src_port_counts = {}
        self.dst_port_counts = {}
        self.protocol_counts = {protocol: 0 for protocol in self.PROTOCOLS}
        self.protocol_counts["Total"] = 0
        self.total_bytes = 0
        self.smallest_packet = None
        self.largest_packet = None
        self.alerted_warning_keys = set()

    def update_ip_counts(self, src_ip, dst_ip):
        self.src_counts[src_ip] = self.src_counts.get(src_ip, 0) + 1
        self.dst_counts[dst_ip] = self.dst_counts.get(dst_ip, 0) + 1

    def update_src_port(self, src_port):
        old_count = self.src_port_counts.get(src_port, 0)
        self.src_port_counts[src_port] = old_count + 1

    def update_dst_port(self, dst_port):
        old_count = self.dst_port_counts.get(dst_port, 0)
        self.dst_port_counts[dst_port] = old_count + 1

    def update_packet_size(self, packet_size):
        self.total_bytes += packet_size

        # The first packet becomes both the smallest and largest at first.
        if self.smallest_packet is None or packet_size < self.smallest_packet:
            self.smallest_packet = packet_size

        if self.largest_packet is None or packet_size > self.largest_packet:
            self.largest_packet = packet_size

    def update_protocol(self, protocol):
        if protocol not in self.protocol_counts:
            protocol = "Other IP"

        self.protocol_counts[protocol] += 1
        self.protocol_counts["Total"] += 1

    def get_service_name(self, port):
        return self.SERVICES.get(port, "Unknown")

    def get_total_packets(self):
        return self.protocol_counts["Total"]

    def average_packet_size(self):
        total = self.get_total_packets()
        if total == 0:
            return 0.0
        return self.total_bytes / total

    def top_items(self, data, limit=5):
        return sorted(data.items(), key=lambda item: item[1], reverse=True)[:limit]

    def build_warning_events(self):
        total = self.get_total_packets()

        if total == 0:
            return []

        warning_events = []
        warning_events.extend(self.build_traffic_concentration_events(total))
        warning_events.extend(self.build_protocol_anomaly_events(total))
        warning_events.extend(self.build_unknown_port_events(total))

        return warning_events

    def build_traffic_concentration_events(self, total):
        traffic_events = []

        # If one IP owns most of the traffic, it may be noisy or suspicious.
        for direction, ip_counts in (
            ("source", self.src_counts),
            ("destination", self.dst_counts),
        ):
            for ip, count in ip_counts.items():
                is_concentrated = count / total > 0.5
                alert_key = ("traffic_concentration", direction, ip)

                if is_concentrated and self.should_report(alert_key):
                    traffic_events.append(
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

        return traffic_events

    def build_protocol_anomaly_events(self, total):
        protocol_events = []

        non_ip_count = self.protocol_counts["Non-IP"]
        non_ip_key = ("protocol_ratio", "Non-IP")
        if non_ip_count / total > 0.3 and self.should_report(non_ip_key):
            protocol_events.append(
                SecurityEvent(
                    event_type="Protocol Anomaly",
                    severity="LOW",
                    source="stats_manager",
                    action="INVESTIGATE",
                    message="Large amount of Non-IP traffic",
                    details={
                        "protocol": "Non-IP",
                        "packet_count": non_ip_count,
                        "total_packets": total,
                        "ratio": self.percent(non_ip_count),
                    },
                )
            )

        icmp_count = self.protocol_counts["ICMP"]
        icmp_key = ("protocol_ratio", "ICMP")
        if icmp_count / total > 0.3 and self.should_report(icmp_key):
            protocol_events.append(
                SecurityEvent(
                    event_type="Protocol Anomaly",
                    severity="MEDIUM",
                    source="stats_manager",
                    action="INVESTIGATE",
                    message="High ICMP traffic, possible ping sweep or flood",
                    details={
                        "protocol": "ICMP",
                        "packet_count": icmp_count,
                        "total_packets": total,
                        "ratio": self.percent(icmp_count),
                    },
                )
            )

        return protocol_events

    def build_unknown_port_events(self, total):
        port_events = []

        for direction, port_counts in (
            ("source", self.src_port_counts),
            ("destination", self.dst_port_counts),
        ):
            for port, count in port_counts.items():
                is_unknown_port = self.get_service_name(port) == "Unknown"
                alert_key = ("unknown_port_activity", direction, port)

                if is_unknown_port and count > 3 and self.should_report(alert_key):
                    port_events.append(
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

        return port_events

    def should_report(self, alert_key):
        if alert_key in self.alerted_warning_keys:
            return False

        self.alerted_warning_keys.add(alert_key)
        return True

    def percent(self, count):
        total = self.get_total_packets()
        if total == 0:
            return "0.0%"
        return f"{count * 100.0 / total:5.1f}%"

    def print_summary(self):
        total = self.get_total_packets()

        # Keep the terminal output split into predictable sections.
        print()
        print("=" * 64)
        print("Network Traffic Summary")
        print("=" * 64)

        if total == 0:
            print("No packets captured yet.")
            return

        print(f"Total packets: {total}")
        self.print_packet_sizes()

        self.print_protocols()
        self.print_ip_table("Top Source IPs", self.src_counts)
        self.print_ip_table("Top Destination IPs", self.dst_counts)
        self.print_ports("Top Source Ports", self.src_port_counts)
        self.print_ports("Top Destination Ports", self.dst_port_counts)

    def print_packet_sizes(self):
        print(
            "Packet bytes : "
            f"total={self.total_bytes}, "
            f"avg={self.average_packet_size():.1f}, "
            f"min={self.smallest_packet}, "
            f"max={self.largest_packet}"
        )

    def print_protocols(self):
        print()
        print("Protocols")
        print("-" * 64)

        for protocol in self.PROTOCOLS:
            count = self.protocol_counts[protocol]
            print(f"{protocol:<10} {count:>6}  {self.percent(count)}")

    def print_ip_table(self, title, data):
        print()
        print(title)
        print("-" * 64)

        if not data:
            print("No data yet.")
            return

        for ip, count in self.top_items(data):
            print(f"{ip:<22} {count:>6}  {self.percent(count)}")

    def print_ports(self, title, port_counts):
        print()
        print(title)
        print("-" * 64)

        if not port_counts:
            print("No ports captured.")
            return

        for port, count in self.top_items(port_counts, limit=10):
            service = self.get_service_name(port)
            print(f"{port:<7} {service:<14} {count:>6}  {self.percent(count)}")
