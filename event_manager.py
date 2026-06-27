from datetime import datetime


class EventManager:
    def __init__(self):
        # Each event is a dictionary with type, severity, IP flow, and details.
        self.events = []

    def add_event(self, event):
        # Add the timestamp here so detectors do not need to know about output.
        event["time"] = datetime.now().strftime("%H:%M:%S")
        self.events.append(event)
        self.print_event(event)

    def print_event(self, event):
        # Print one clean alert block instead of a raw dictionary.
        print()
        print("Security Event")
        print("-" * 64)
        print(f"Time     : {event['time']}")
        print(f"Severity : {event['severity']}")
        print(f"Type     : {event['type']}")
        print(f"Flow     : {event['src_ip']} -> {event['dst_ip']}")
        print(f"Message  : {event['message']}")

        details = event.get("details")
        if details:
            print("Details  :")
            for key, value in details.items():
                print(f"  {key:<11}: {value}")

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
