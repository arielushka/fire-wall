class StatsManager:
    def __init__(self):
        self.src_counts = {}
        self.dst_counts = {}
        self.port_counts = {}
        self.protocol_counts = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "Non-IP": 0,
            "Other IP": 0,
            "Total": 0,
        }

    def get_service_name(self, port):
        services = {
            80: "HTTP",
            443: "HTTPS",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            110: "POP3",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
        }
        return services.get(port, "Unknown")

    def print_summary(self):
        total = self.protocol_counts.get("Total", 0)
        print("\n" + "=" * 50)
        print("Packet Statistics Summary")
        print("=" * 50)

        if total == 0:
            print("No packets captured yet.")
            return

        print(f"Total packets: {total}")

        # Protocol breakdown with simple percentage bars for quick visual scan
        print("\n-- Protocol Breakdown --")
        for protocol in ("TCP", "UDP", "ICMP", "Other IP", "Non-IP"):
            count = self.protocol_counts.get(protocol, 0)
            percent = count * 100.0 / total
            print(f"{protocol:8}: {count:6} ({percent:5.1f}%)")

        # helper: return top N items from a dict sorted by count
        def top_items(data, limit=5):
            return sorted(data.items(), key=lambda item: item[1], reverse=True)[:limit]

        # Top observed source IP addresses
        print("\n-- Top Source IPs --")
        if self.src_counts:
            for ip, count in top_items(self.src_counts, 5):
                percent = (count * 100.0 / total) if total else 0
                print(f"{ip:20} {count:6} ({percent:5.1f}%)")
        else:
            print("No source IPs captured.")

        # Top observed destination IP addresses
        print("\n-- Top Destination IPs --")
        if self.dst_counts:
            for ip, count in top_items(self.dst_counts, 5):
                percent = count * 100.0 / total if total else 0
                print(f"{ip:20} {count:6} ({percent:5.1f}%)")
        else:
            print("No destination IPs captured.")

        # Top ports seen and marking unknown services that account for >=5%
        print("\n-- Top Ports --")
        if self.port_counts:
            for port, count in top_items(self.port_counts, 10):
                service = self.get_service_name(port)
                percent = count * 100.0 / total
                warn = " ⚠️" if service == "Unknown" and percent >= 5.0 else ""
                print(
                    f"Port {port:5} ({service:12}): {count:6} ({percent:5.1f}%) {warn}"
                )
        else:
            print("No ports captured.")

        # Basic heuristic warnings for potentially suspicious patterns
        warnings = []

        # Detect excessive concentration from/to a single IP (>50% of traffic)
        for ip, count in list(self.src_counts.items()) + list(self.dst_counts.items()):
            if total and (count / total) > 0.5:
                percent = count * 100.0 / total
                warnings.append(
                    f"High concentration of packets for IP {ip} ({count} packets, {percent:5.1f}%)"
                )

        # High proportion of non-IP or ICMP traffic may indicate scanning or malformed captures
        if (self.protocol_counts.get("Non-IP", 0) / total) > 0.3:
            warnings.append("Large proportion of Non-IP packets detected")

        if (self.protocol_counts.get("ICMP", 0) / total) > 0.3:
            warnings.append("High ICMP traffic (possible scanning or ping flood)")

        if warnings:
            # Prominent warning block to stand out in terminal output
            print("\n" + "!" * 50)
            print("!!! WARNING: Potential issues detected !!!")
            for warning in warnings:
                print(" - " + warning)
            print("!" * 50)

    def update_ip_counts(self, src_ip, dst_ip):
        self.src_counts[src_ip] = self.src_counts.get(src_ip, 0) + 1
        self.dst_counts[dst_ip] = self.dst_counts.get(dst_ip, 0) + 1

    def update_port(self, dst_port):
        self.port_counts[dst_port] = self.port_counts.get(dst_port, 0) + 1

    def update_protocol(self, packet_type):
        self.protocol_counts[packet_type] += 1
        self.protocol_counts["Total"] += 1
