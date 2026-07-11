import ipaddress

from config_loader import load_json_config
from firewall_decision import FirewallDecision


class FirewallManager:
    def __init__(self, firewall_config=None, services=None):
        self.firewall_config = firewall_config or load_json_config("firewall_rules.json")
        self.services = services or self.load_services()

        self.flagged_src_ips = set()
        self.flagged_dst_ips = set()
        self.flagged_src_ports = set()
        self.flagged_dst_ports = set()
        self.flagged_protocols = set()
        self.alerted_dst_ports = set()
        self.flagged_flow_rules = set()
        self.sensitive_dst_ports = set()
        self.max_packet_size = self.firewall_config.get("max_packet_size", 1500)
        self.default_action = self.firewall_config.get("default_action", "ALLOW")

        # These counters help us print a simple firewall summary.
        self.allowed_count = 0
        self.flagged_count = 0
        self.alert_count = 0
        self.flagged_reasons = {}
        self.alert_reasons = {}

    def load_services(self):
        raw_services = load_json_config("services.json")
        return {int(port): info for port, info in raw_services.items()}

    def load_default_rules(self):
        self.flagged_src_ips.update(self.firewall_config.get("flagged_src_ips", []))
        self.flagged_dst_ips.update(self.firewall_config.get("flagged_dst_ips", []))
        self.flagged_protocols.update(self.firewall_config.get("flagged_protocols", []))
        self.flagged_src_ports.update(self.to_int_set("flagged_src_ports"))
        self.flagged_dst_ports.update(self.to_int_set("flagged_dst_ports"))
        self.alerted_dst_ports.update(self.to_int_set("alert_dst_ports"))
        self.sensitive_dst_ports.update(self.to_int_set("sensitive_public_dst_ports"))
        self.load_flow_rules(self.firewall_config.get("flagged_flow_rules", []))

    def to_int_set(self, key):
        return {int(value) for value in self.firewall_config.get(key, [])}

    def load_flow_rules(self, flow_rules):
        for rule in flow_rules:
            self.flag_flow(
                rule["src_ip"],
                rule["dst_ip"],
                int(rule["dst_port"]),
            )

    def flag_src_ip(self, src_ip):
        self.flagged_src_ips.add(src_ip)

    def flag_dst_ip(self, dst_ip):
        self.flagged_dst_ips.add(dst_ip)

    def flag_protocol(self, protocol):
        self.flagged_protocols.add(protocol)

    def flag_src_port(self, port):
        self.flagged_src_ports.add(port)

    def flag_dst_port(self, port):
        self.flagged_dst_ports.add(port)

    def alert_dst_port(self, port):
        self.alerted_dst_ports.add(port)

    def flag_flow(self, src_ip, dst_ip, dst_port):
        self.flagged_flow_rules.add((src_ip, dst_ip, dst_port))

    def check_packet(self, packet_info):
        # First decide what the firewall thinks about this packet.
        # Then save the result in the counters.
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

        # Exact IP rules are checked first because they are very specific.
        if src_ip in self.flagged_src_ips:
            reason = f"Flagged source IP: {src_ip}"
            return self.build_result("FLAG", reason, "HIGH")

        if dst_ip in self.flagged_dst_ips:
            reason = f"Flagged destination IP: {dst_ip}"
            return self.build_result("FLAG", reason, "HIGH")

        if src_dst_port_rule in self.flagged_flow_rules:
            reason = f"Flagged flow rule: {src_ip} -> {dst_ip}:{dst_port}"
            return self.build_result("FLAG", reason, "HIGH")

        is_sensitive_service = dst_port in self.sensitive_dst_ports
        is_tcp = protocol == "TCP"
        is_public_source = self.is_public_ip(src_ip)

        if is_public_source and is_tcp and is_sensitive_service:
            service_name = self.get_service_name(dst_port)
            reason = (
                f"Public source IP accessing sensitive service "
                f"{service_name}: {dst_port}"
            )
            severity = self.get_dst_port_severity(dst_port)
            return self.build_result("FLAG", reason, severity)

        if protocol in self.flagged_protocols:
            severity = "MEDIUM"
            if protocol == "ICMP":
                severity = "LOW"

            reason = f"Flagged protocol: {protocol}"
            return self.build_result("FLAG", reason, severity)

        if src_port in self.flagged_src_ports:
            reason = f"Flagged source port: {src_port}"
            return self.build_result("FLAG", reason, "MEDIUM")

        if dst_port in self.flagged_dst_ports:
            service_name = self.get_service_name(dst_port)
            severity = self.get_dst_port_severity(dst_port)
            reason = f"Flagged destination port: {dst_port} ({service_name})"
            return self.build_result("FLAG", reason, severity)

        # ALERT means suspicious, but still let the packet continue.
        if packet_size > self.max_packet_size:
            return self.build_result("ALERT", "Oversized packet", "MEDIUM")

        if dst_port in self.alerted_dst_ports:
            reason = f"Suspicious destination port: {dst_port}"
            return self.build_result("ALERT", reason, "LOW")

        return self.build_result(self.default_action, "No firewall rule matched", "LOW")

    def build_result(self, action, reason, severity):
        return FirewallDecision(action, reason, severity)

    def record_result(self, result):
        action = result.action
        reason = result.reason

        if action == "FLAG":
            self.flagged_count += 1
            old_count = self.flagged_reasons.get(reason, 0)
            self.flagged_reasons[reason] = old_count + 1
        elif action == "ALERT":
            self.alert_count += 1
            old_count = self.alert_reasons.get(reason, 0)
            self.alert_reasons[reason] = old_count + 1
        else:
            self.allowed_count += 1

    def get_service_name(self, port):
        service_info = self.services.get(port)
        if service_info:
            return service_info["name"]
        return "Unknown"

    def get_dst_port_severity(self, port):
        service_info = self.services.get(port)
        if service_info:
            return service_info.get("severity", "MEDIUM")
        return "MEDIUM"

    def is_public_ip(self, ip):
        if not ip:
            return False

        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            # If the IP text is broken, do not treat it as public.
            return False

        return address.is_global

    def print_summary(self):
        total = self.allowed_count + self.flagged_count + self.alert_count

        print()
        print("=" * 64)
        print("Firewall Summary")
        print("=" * 64)
        print(f"Checked packets : {total}")
        print(f"Allowed packets : {self.allowed_count}")
        print(f"Flagged packets : {self.flagged_count}")
        print(f"Alerted packets : {self.alert_count}")

        self.print_rules()
        self.print_result_reasons("Flagged Reasons", self.flagged_reasons)
        self.print_result_reasons("Alert Reasons", self.alert_reasons)

    def print_rules(self):
        print()
        print("Active Firewall Rules")
        print("-" * 64)
        self.print_rule_set("Flagged source IPs", self.flagged_src_ips)
        self.print_rule_set("Flagged destination IPs", self.flagged_dst_ips)
        self.print_rule_set("Flagged source ports", self.flagged_src_ports)
        self.print_rule_set("Flagged destination ports", self.flagged_dst_ports)
        self.print_rule_set("Flagged protocols", self.flagged_protocols)
        self.print_rule_set("Alert destination ports", self.alerted_dst_ports)
        self.print_rule_set(
            "Flagged src_ip/dst_ip/dst_port",
            self.flagged_flow_rules,
        )
        print(f"{'Max packet size':<32}: {self.max_packet_size} bytes")
        print(
            f"{'Combined sensitive service rule':<32}: "
            f"public src_ip + TCP + dst_port {self.format_rules(self.sensitive_dst_ports)}"
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

        # No fancy sorting here. Just show each reason and how often it happened.
        for reason, count in reasons.items():
            print(f"{count:>6}  {reason}")
