import json
from datetime import datetime
from pathlib import Path

from security_event import SecurityEvent


class EventManager:
    def __init__(self, output_file="json/events.json", app_name=None):
        self.output_file = Path(output_file)
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        self.app_name = app_name or "Fire Wall"
        self.events = []
        self.session_started_at = datetime.now().isoformat(timespec="seconds")
        self.save_events()

    def add_event(self, event):
        if not isinstance(event, SecurityEvent):
            raise TypeError("EventManager.add_event expects a SecurityEvent object")

        self.events.append(event)
        self.save_events()

    def add_events(self, events):
        if not events:
            return

        for event in events:
            if not isinstance(event, SecurityEvent):
                raise TypeError("EventManager.add_events expects SecurityEvent objects")

            self.events.append(event)

        self.save_events()

    def save_events(self):
        data = {
            "app_name": self.app_name,
            "session_started_at": self.session_started_at,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "event_count": len(self.events),
            "severity_summary": self.get_severity_summary(),
            "events": [event.to_dict() for event in self.events],
        }

        with self.output_file.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=4, ensure_ascii=False)

    def get_severity_summary(self):
        summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

        for event in self.events:
            if event.severity in summary:
                summary[event.severity] += 1

        return summary

    def print_event(self, event):
        print()
        print("Security Event")
        print("-" * 64)
        print(f"Time     : {event.time}")
        print(f"Source   : {event.source}")
        print(f"Severity : {event.severity}")
        print(f"Action   : {event.action}")
        print(f"Type     : {event.event_type}")
        print(f"Flow     : {event.src_ip} -> {event.dst_ip}")
        print(f"Message  : {event.message}")

        if event.details:
            print("Details  :")
            for key, value in event.details.items():
                print(f"  {key:<16}: {value}")

    def print_events(self):
        if not self.events:
            print("No security events detected.")
            return

        print()
        print("=" * 64)
        print("Security Events")
        print("=" * 64)

        for event in self.events:
            self.print_event(event)

    def print_severity_summary(self):
        print()
        print("Security Events Summary")
        print("-" * 64)

        summary = self.get_severity_summary()
        for severity, count in summary.items():
            print(f"{severity:<8}: {count}")

        return summary
