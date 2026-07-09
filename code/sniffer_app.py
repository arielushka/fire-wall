import argparse

from scapy.all import sniff

from firewall import FirewallMonitor


def main():
    parser = argparse.ArgumentParser(description="Fire Wall packet monitor")
    parser.add_argument("--count", type=int, default=200)
    args = parser.parse_args()

    monitor = FirewallMonitor()
    print("Fire Wall")
    print(f"Capturing {args.count} packets. Press Ctrl+C to stop.")

    try:
        sniff(prn=monitor.handle_packet, store=False, count=args.count)
    except KeyboardInterrupt:
        print("Stopped by user.")

    print()
    print(monitor.summary_text())
    print("Events saved to json/events.json")


if __name__ == "__main__":
    main()
