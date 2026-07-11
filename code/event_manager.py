import json
from datetime import datetime
from pathlib import Path

from security_event import SecurityEvent


class EventManager:
    def __init__(self, output_file="json/events.json", app_name="Fire Wall"):
        self.output_file = Path(output_file)
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        self.app_name = app_name or "Fire Wall"
        self.events = []
        self.session_started_at = self.now()
        self.save()

    def add_events(self, events):
        if not events:
            return

        if any(not isinstance(event, SecurityEvent) for event in events):
            raise TypeError("All events must be SecurityEvent objects")

        self.events.extend(events)
        self.save()

    def save(self):
        data = {
            "app_name": self.app_name,
            "session_started_at": self.session_started_at,
            "generated_at": self.now(),
            "event_count": len(self.events),
            "severity_summary": self.severity_summary(),
            "events": [event.to_dict() for event in self.events],
        }

        with self.output_file.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=4, ensure_ascii=False)

    def severity_summary(self):
        summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for event in self.events:
            if event.severity in summary:
                summary[event.severity] += 1
        return summary

    @staticmethod
    def now():
        return datetime.now().isoformat(timespec="seconds")
