from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import uuid4


VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_ACTIONS = {"ALLOW", "ALERT", "FLAG", "BLOCK", "INVESTIGATE"}


@dataclass
class SecurityEvent:
    event_type: str
    severity: str
    message: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    details: dict = field(default_factory=dict)
    source: str = "unknown"
    action: str = "ALERT"
    event_id: str = field(default_factory=lambda: str(uuid4()))
    time: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )

    def __post_init__(self):
        self.severity = self.severity.upper()
        self.action = self.action.upper()

        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid event severity: {self.severity}")

        if self.action not in VALID_ACTIONS:
            raise ValueError(f"Invalid event action: {self.action}")

        if not self.event_type:
            raise ValueError("Security event must have an event type")

        if not self.message:
            raise ValueError("Security event must have a message")

    def to_dict(self):
        return {
            "id": self.event_id,
            "time": self.time,
            "source": self.source,
            "type": self.event_type,
            "severity": self.severity,
            "action": self.action,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "message": self.message,
            "details": self.details,
        }
