class FirewallManager:
    def __init__(self):
        self.blocked_src_ips = set()
        self.blocked_dst_ips = set()
        self.blocked_src_ports = set()
        self.blocked_dst_ports = set()
        self.blocked_protocols = set()
        self.blocked_src_ip_dst_ip_dst_ports = set()
        self.allowed_count = 0
        self.blocked_count = 0
        self.blocked_reasons = {}

    def block_src_ip(self, src_ip):
        self.blocked_src_ips.add(src_ip)

    def block_dst_ip(self, dst_ip):
        self.blocked_dst_ips.add(dst_ip)

    def block_protocol(self, protocol):
        self.blocked_protocols.add(protocol)

    def block_src_port(self, src_port):
        self.blocked_src_ports.add(src_port)

    def block_dst_port(self, dst_port):
        self.blocked_dst_ports.add(dst_port)

    def block_port(self, port):
        self.block_dst_port(port)

    def block_src_ip_dst_ip_dst_port(self, src_ip, dst_ip, dst_port):
        self.blocked_src_ip_dst_ip_dst_ports.add((src_ip, dst_ip, dst_port))

    def check_packet(self, packet_info):
        action = "ALLOW"
        reason = "No firewall rule matched"
        src_dst_port_rule = (
            packet_info["src_ip"],
            packet_info["dst_ip"],
            packet_info["dst_port"],
        )

        if packet_info["protocol"] in self.blocked_protocols:
            action = "BLOCK"
            reason = f"protocol: {packet_info['protocol']} is blocked"
        elif packet_info["src_ip"] in self.blocked_src_ips:
            action = "BLOCK"
            reason = f"src_ip: {packet_info['src_ip']} is blocked"
        elif packet_info["dst_ip"] in self.blocked_dst_ips:
            action = "BLOCK"
            reason = f"dst_ip: {packet_info['dst_ip']} is blocked"
        elif packet_info["src_port"] in self.blocked_src_ports:
            action = "BLOCK"
            reason = f"src_port: {packet_info['src_port']} is blocked"
        elif packet_info["dst_port"] in self.blocked_dst_ports:
            action = "BLOCK"
            reason = f"dst_port: {packet_info['dst_port']} is blocked"
        elif src_dst_port_rule in self.blocked_src_ip_dst_ip_dst_ports:
            action = "BLOCK"
            reason = (
                f"src_ip/dst_ip/dst_port rule matched: "
                f"{packet_info['src_ip']} -> {packet_info['dst_ip']}:"
                f"{packet_info['dst_port']}"
            )

        if action == "ALLOW":
            self.allowed_count += 1
        else:
            self.blocked_count += 1
            self.blocked_reasons[reason] = self.blocked_reasons.get(reason, 0) + 1

        return {"action": action, "reason": reason}

    def print_summary(self):
        total = self.allowed_count + self.blocked_count

        print()
        print("=" * 64)
        print("Firewall Summary")
        print("=" * 64)
        print(f"Checked packets : {total}")
        print(f"Allowed packets : {self.allowed_count}")
        print(f"Blocked packets : {self.blocked_count}")

        self.print_rules()
        self.print_blocked_reasons()

    def print_rules(self):
        print()
        print("Firewall Rules")
        print("-" * 64)
        self.print_rule_set("Blocked source IPs", self.blocked_src_ips)
        self.print_rule_set("Blocked destination IPs", self.blocked_dst_ips)
        self.print_rule_set("Blocked source ports", self.blocked_src_ports)
        self.print_rule_set("Blocked destination ports", self.blocked_dst_ports)
        self.print_rule_set("Blocked protocols", self.blocked_protocols)
        self.print_rule_set(
            "Blocked src_ip/dst_ip/dst_port",
            self.blocked_src_ip_dst_ip_dst_ports,
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

    def print_blocked_reasons(self):
        print()
        print("Blocked Reasons")
        print("-" * 64)

        if not self.blocked_reasons:
            print("No packets blocked.")
            return

        for reason, count in sorted(
            self.blocked_reasons.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            print(f"{count:>6}  {reason}")
