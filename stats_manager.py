class StatsManager:
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
        self.src_counts = {}
        self.dst_counts = {}
        self.port_counts = {}
        self.protocol_counts = {protocol: 0 for protocol in self.PROTOCOLS}
        self.protocol_counts["Total"] = 0

    def update_ip_counts(self, src_ip, dst_ip):
        self.src_counts[src_ip] = self.src_counts.get(src_ip, 0) + 1
        self.dst_counts[dst_ip] = self.dst_counts.get(dst_ip, 0) + 1

    def update_port(self, dst_port):
        self.port_counts[dst_port] = self.port_counts.get(dst_port, 0) + 1

    def update_protocol(self, protocol):
        if protocol not in self.protocol_counts:
            protocol = "Other IP"

        self.protocol_counts[protocol] += 1
        self.protocol_counts["Total"] += 1

    def get_service_name(self, port):
        return self.SERVICES.get(port, "Unknown")

    def get_total_packets(self):
        return self.protocol_counts["Total"]

    def top_items(self, data, limit=5):
        return sorted(data.items(), key=lambda item: item[1], reverse=True)[:limit]

    def build_warnings(self):
        total = self.get_total_packets()
        warnings = []

        if total == 0:
            return warnings

        for ip, count in list(self.src_counts.items()) + list(self.dst_counts.items()):
            if count / total > 0.5:
                percent = self.percent(count)
                warnings.append(
                    f"High traffic concentration for {ip}: {count} packets ({percent})"
                )

        if self.protocol_counts["Non-IP"] / total > 0.3:
            warnings.append("Large amount of Non-IP traffic")

        if self.protocol_counts["ICMP"] / total > 0.3:
            warnings.append("High ICMP traffic, possible ping sweep or flood")

        return warnings

    def percent(self, count):
        total = self.get_total_packets()
        if total == 0:
            return "0.0%"
        return f"{count * 100.0 / total:5.1f}%"

    def print_summary(self):
        total = self.get_total_packets()

        print()
        print("=" * 64)
        print("Network Traffic Summary")
        print("=" * 64)

        if total == 0:
            print("No packets captured yet.")
            return

        print(f"Total packets: {total}")

        self.print_protocols()
        self.print_ip_table("Top Source IPs", self.src_counts)
        self.print_ip_table("Top Destination IPs", self.dst_counts)
        self.print_ports()
        self.print_warnings()

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

    def print_ports(self):
        print()
        print("Top Ports")
        print("-" * 64)

        if not self.port_counts:
            print("No ports captured.")
            return

        for port, count in self.top_items(self.port_counts, limit=10):
            service = self.get_service_name(port)
            marker = " attention" if service == "Unknown" and count > 3 else ""
            print(
                f"{port:<7} {service:<14} {count:>6}  {self.percent(count)}{marker}"
            )

    def print_warnings(self):
        warnings = self.build_warnings()

        if not warnings:
            print()
            print("Warnings")
            print("-" * 64)
            print("No warning patterns detected in this summary window.")
            return

        print()
        print("Warnings")
        print("-" * 64)
        for warning in warnings:
            print(f"! {warning}")
