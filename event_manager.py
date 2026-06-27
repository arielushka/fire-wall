from datetime import datetime


class EventManager:
    def __init__(self):
        self.events = []

    def add_event(self, event):
        event["time"] = datetime.now().strftime("%H:%M:%S")
        self.events.append(event)
        self.print_event(event)

    def print_event(self, event):
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
