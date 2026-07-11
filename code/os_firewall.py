import ipaddress
import subprocess


class WindowsFirewallBlocker:
    RULE_PREFIX = "Fire Wall - Block"

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.blocked_ips = set()

    def block_ip(self, ip_text):
        if not self.enabled or not self.is_public_ip(ip_text):
            return False

        if ip_text in self.blocked_ips:
            return True

        rule_name = self.rule_name(ip_text)
        if self.rule_exists(rule_name):
            self.blocked_ips.add(ip_text)
            return True

        result = self.run_command(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip_text}",
                "enable=yes",
            ]
        )
        if result.returncode != 0:
            return False

        self.blocked_ips.add(ip_text)
        return True

    def rule_exists(self, rule_name):
        result = self.run_command(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "show",
                "rule",
                f"name={rule_name}",
            ]
        )
        return result.returncode == 0 and rule_name.lower() in result.stdout.lower()

    def rule_name(self, ip_text):
        return f"{self.RULE_PREFIX} {ip_text}"

    def run_command(self, command):
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )

    def is_public_ip(self, ip_text):
        try:
            return ipaddress.ip_address(ip_text).is_global
        except (TypeError, ValueError):
            return False

    @property
    def blocked_count(self):
        return len(self.blocked_ips)
