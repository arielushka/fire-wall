from datetime import datetime


class EventManager:
    def __init__(self):
        # Each event is a dictionary with type, severity, IP flow, and details.
        self.events = []

    def save_event(self, event):
        data = (
            "Security Event\n"
            + "-" * 64
            + f"\nTime     : {event['time']}\n"
            + f"Severity : {event['severity']}\n"
            + f"Type     : {event['type']}\n"
            + f"Flow     : {event['src_ip']} -> {event['dst_ip']}\n"
            + f"Message  : {event['message']}/n"
        )
        with open("data_events.txt", "a", encoding="utf-8") as f:
            f.write(data)

    def add_event(self, event):
        # Add the timestamp here so detectors do not need to know about output.
        event["time"] = datetime.now().strftime("%H:%M:%S")
        self.events.append(event)
        self.save_event(event)
        self.print_event(event)

    def print_event(self, event):
        # Print one clean alert block instead of showing the raw dictionary.
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

            # Details can be different for firewall alerts and scan alerts.
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
