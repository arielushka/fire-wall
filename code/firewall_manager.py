import ipaddress

from config_loader import load_json_config
from firewall_decision import FirewallDecision


class FirewallManager:
    def __init__(self, firewall_config=None, services=None):
        rules = firewall_config or load_json_config("firewall_rules.json")
        self.services = services or self.load_services()

        self.flagged_src_ips = set(rules.get("flagged_src_ips", []))
        self.flagged_dst_ips = set(rules.get("flagged_dst_ips", []))
        self.flagged_src_ports = self.number_set(rules, "flagged_src_ports")
        self.flagged_dst_ports = self.number_set(rules, "flagged_dst_ports")
        self.flagged_protocols = set(rules.get("flagged_protocols", []))
        self.alerted_dst_ports = self.number_set(rules, "alert_dst_ports")
        self.sensitive_dst_ports = self.number_set(
            rules,
            "sensitive_public_dst_ports",
        )
        self.flagged_flow_rules = {
            (rule["src_ip"], rule["dst_ip"], int(rule["dst_port"]))
            for rule in rules.get("flagged_flow_rules", [])
        }

        self.max_packet_size = rules.get("max_packet_size", 1500)
        self.default_action = rules.get("default_action", "ALLOW")

        self.allowed_count = 0
        self.flagged_count = 0
        self.alert_count = 0
        self.flagged_reasons = {}
        self.alert_reasons = {}

    @staticmethod
    def number_set(rules, key):
        return {int(value) for value in rules.get(key, [])}

    @staticmethod
    def load_services():
        services = load_json_config("services.json")
        return {int(port): info for port, info in services.items()}

    def check_packet(self, packet):
        result = self.evaluate_packet(packet)
        self.count_result(result)
        return result

    def evaluate_packet(self, packet):
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]
        protocol = packet["protocol"]
        src_port = packet["src_port"]
        dst_port = packet["dst_port"]

        if src_ip in self.flagged_src_ips:
            return FirewallDecision("FLAG", f"Flagged source IP: {src_ip}", "HIGH")

        if dst_ip in self.flagged_dst_ips:
            return FirewallDecision("FLAG", f"Flagged destination IP: {dst_ip}", "HIGH")

        if (src_ip, dst_ip, dst_port) in self.flagged_flow_rules:
            reason = f"Flagged flow rule: {src_ip} -> {dst_ip}:{dst_port}"
            return FirewallDecision("FLAG", reason, "HIGH")

        if (
            self.is_public_ip(src_ip)
            and protocol == "TCP"
            and dst_port in self.sensitive_dst_ports
        ):
            service = self.service_name(dst_port)
            reason = f"Public source IP accessing sensitive service {service}: {dst_port}"
            return FirewallDecision("FLAG", reason, self.port_severity(dst_port))

        if protocol in self.flagged_protocols:
            severity = "LOW" if protocol == "ICMP" else "MEDIUM"
            return FirewallDecision("FLAG", f"Flagged protocol: {protocol}", severity)

        if src_port in self.flagged_src_ports:
            return FirewallDecision(
                "FLAG",
                f"Flagged source port: {src_port}",
                "MEDIUM",
            )

        if dst_port in self.flagged_dst_ports:
            reason = f"Flagged destination port: {dst_port} ({self.service_name(dst_port)})"
            return FirewallDecision("FLAG", reason, self.port_severity(dst_port))

        if packet["packet_size"] > self.max_packet_size:
            return FirewallDecision("ALERT", "Oversized packet", "MEDIUM")

        if dst_port in self.alerted_dst_ports:
            return FirewallDecision(
                "ALERT",
                f"Suspicious destination port: {dst_port}",
                "LOW",
            )

        return FirewallDecision(self.default_action, "No firewall rule matched", "LOW")

    def count_result(self, result):
        if result.action == "FLAG":
            self.flagged_count += 1
            self.flagged_reasons[result.reason] = (
                self.flagged_reasons.get(result.reason, 0) + 1
            )
        elif result.action == "ALERT":
            self.alert_count += 1
            self.alert_reasons[result.reason] = (
                self.alert_reasons.get(result.reason, 0) + 1
            )
        else:
            self.allowed_count += 1

    def service_name(self, port):
        return self.services.get(port, {}).get("name", "Unknown")

    def port_severity(self, port):
        return self.services.get(port, {}).get("severity", "MEDIUM")

    @staticmethod
    def is_public_ip(ip_text):
        try:
            return ipaddress.ip_address(ip_text).is_global
        except (TypeError, ValueError):
            return False
