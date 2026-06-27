import ipaddress


class FirewallManager:
    DEFAULT_BLOCKED_DST_PORTS = {
        21: ("FTP", "MEDIUM"),
        23: ("Telnet", "MEDIUM"),
        135: ("RPC", "HIGH"),
        139: ("NetBIOS", "HIGH"),
        445: ("SMB", "HIGH"),
        3389: ("RDP", "HIGH"),
    }

    SENSITIVE_DST_PORTS = {445, 3389}

    def __init__(self):
        self.blocked_src_ips = set()
        self.blocked_dst_ips = set()
        self.blocked_src_ports = set()
        self.blocked_dst_ports = set()
        self.blocked_protocols = set()
        self.alerted_dst_ports = set()
        self.blocked_src_ip_dst_ip_dst_ports = set()
        self.max_packet_size = 1500
        self.allowed_count = 0
        self.blocked_count = 0
        self.alert_count = 0
        self.blocked_reasons = {}
        self.alert_reasons = {}

    def load_default_rules(self):
        for port in self.DEFAULT_BLOCKED_DST_PORTS:
            self.block_dst_port(port)

        self.block_protocol("ICMP")

    def block_src_ip(self, src_ip):
        self.blocked_src_ips.add(src_ip)

    def block_ip(self, ip):
        self.block_src_ip(ip)

    def block_dst_ip(self, dst_ip):
        self.blocked_dst_ips.add(dst_ip)

    def block_protocol(self, protocol):
        self.blocked_protocols.add(protocol)

    def block_src_port(self, port):
        self.blocked_src_ports.add(port)

    def block_dst_port(self, port):
        self.blocked_dst_ports.add(port)

    def block_port(self, port):
        self.block_dst_port(port)

    def alert_dst_port(self, port):
        self.alerted_dst_ports.add(port)

    def block_src_ip_dst_ip_dst_port(self, src_ip, dst_ip, dst_port):
        self.blocked_src_ip_dst_ip_dst_ports.add((src_ip, dst_ip, dst_port))

    def check_packet(self, packet_info):
        result = self.evaluate_packet(packet_info)
        self.record_result(result)
        return result

    def evaluate_packet(self, packet_info):
        src_ip = packet_info["src_ip"]
        dst_ip = packet_info["dst_ip"]
        protocol = packet_info["protocol"]
        src_port = packet_info["src_port"]
        dst_port = packet_info["dst_port"]
        packet_size = packet_info["packet_size"]
        src_dst_port_rule = (src_ip, dst_ip, dst_port)

        if src_ip in self.blocked_src_ips:
            return self.build_result("BLOCK", f"Blocked source IP: {src_ip}", "HIGH")

        if dst_ip in self.blocked_dst_ips:
            return self.build_result("BLOCK", f"Blocked destination IP: {dst_ip}", "HIGH")

        if src_dst_port_rule in self.blocked_src_ip_dst_ip_dst_ports:
            return self.build_result(
                "BLOCK",
                f"Blocked flow rule: {src_ip} -> {dst_ip}:{dst_port}",
                "HIGH",
            )

        if self.is_public_ip(src_ip) and protocol == "TCP" and dst_port in self.SENSITIVE_DST_PORTS:
            service_name = self.get_service_name(dst_port)
            return self.build_result(
                "BLOCK",
                f"Public source IP accessing sensitive service {service_name}: {dst_port}",
                "HIGH",
            )

        if protocol in self.blocked_protocols:
            severity = "LOW" if protocol == "ICMP" else "MEDIUM"
            return self.build_result("BLOCK", f"Blocked protocol: {protocol}", severity)

        if src_port in self.blocked_src_ports:
            return self.build_result("BLOCK", f"Blocked source port: {src_port}", "MEDIUM")

        if dst_port in self.blocked_dst_ports:
            service_name = self.get_service_name(dst_port)
            severity = self.get_dst_port_severity(dst_port)
            return self.build_result(
                "BLOCK",
                f"Blocked destination port: {dst_port} ({service_name})",
                severity,
            )

        if packet_size > self.max_packet_size:
            return self.build_result("ALERT", "Oversized packet", "MEDIUM")

        if dst_port in self.alerted_dst_ports:
            return self.build_result("ALERT", f"Suspicious destination port: {dst_port}", "LOW")

        return self.build_result("ALLOW", "No firewall rule matched", "LOW")

    def build_result(self, action, reason, severity):
        return {
            "action": action,
            "reason": reason,
            "severity": severity,
        }

    def record_result(self, result):
        action = result["action"]
        reason = result["reason"]

        if action == "BLOCK":
            self.blocked_count += 1
            self.blocked_reasons[reason] = self.blocked_reasons.get(reason, 0) + 1
        elif action == "ALERT":
            self.alert_count += 1
            self.alert_reasons[reason] = self.alert_reasons.get(reason, 0) + 1
        else:
            self.allowed_count += 1

    def get_service_name(self, port):
        service_info = self.DEFAULT_BLOCKED_DST_PORTS.get(port)
        if service_info:
            return service_info[0]
        return "Unknown"

    def get_dst_port_severity(self, port):
        service_info = self.DEFAULT_BLOCKED_DST_PORTS.get(port)
        if service_info:
            return service_info[1]
        return "MEDIUM"

    def is_public_ip(self, ip):
        if not ip:
            return False

        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False

        return address.is_global

    def print_summary(self):
        total = self.allowed_count + self.blocked_count + self.alert_count

        print()
        print("=" * 64)
        print("Firewall Summary")
        print("=" * 64)
        print(f"Checked packets : {total}")
        print(f"Allowed packets : {self.allowed_count}")
        print(f"Blocked packets : {self.blocked_count}")
        print(f"Alerted packets : {self.alert_count}")

        self.print_rules()
        self.print_result_reasons("Blocked Reasons", self.blocked_reasons)
        self.print_result_reasons("Alert Reasons", self.alert_reasons)

    def print_rules(self):
        print()
        print("Active Firewall Rules")
        print("-" * 64)
        self.print_rule_set("Blocked source IPs", self.blocked_src_ips)
        self.print_rule_set("Blocked destination IPs", self.blocked_dst_ips)
        self.print_rule_set("Blocked source ports", self.blocked_src_ports)
        self.print_rule_set("Blocked destination ports", self.blocked_dst_ports)
        self.print_rule_set("Blocked protocols", self.blocked_protocols)
        self.print_rule_set("Alert destination ports", self.alerted_dst_ports)
        self.print_rule_set(
            "Blocked src_ip/dst_ip/dst_port",
            self.blocked_src_ip_dst_ip_dst_ports,
        )
        print(f"{'Max packet size':<32}: {self.max_packet_size} bytes")
        print(
            f"{'Combined sensitive service rule':<32}: "
            "public src_ip + TCP + dst_port 445/3389"
        )

    def print_rule_set(self, title, rules):
        print(f"{title:<32}: {self.format_rules(rules)}")

    def format_rules(self, rules):
        if not rules:
            return "None"

        formatted_rules = []
        for rule in sorted(rules):
            if isinstance(rule, tuple):
                formatted_rules.append(f"{rule[0]} -> {rule[1]}:{rule[2]}")
            else:
                formatted_rules.append(str(rule))

        return ", ".join(formatted_rules)

    def print_result_reasons(self, title, reasons):
        print()
        print(title)
        print("-" * 64)

        if not reasons:
            print("None.")
            return

        for reason, count in sorted(
            reasons.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            print(f"{count:>6}  {reason}")
