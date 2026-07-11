from dataclasses import dataclass


VALID_FIREWALL_ACTIONS = {"ALLOW", "ALERT", "FLAG"}


@dataclass
class FirewallDecision:
    action: str
    reason: str
    severity: str

    def __post_init__(self):
        self.action = self.action.upper()
        self.severity = self.severity.upper()

        if self.action not in VALID_FIREWALL_ACTIONS:
            raise ValueError(f"Invalid firewall action: {self.action}")

        if not self.reason:
            raise ValueError("Firewall decision must include a reason")
