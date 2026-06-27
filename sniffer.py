from scapy.all import ICMP, IP, TCP, UDP, sniff

from event_manager import EventManager
from scan_detector import ScanDetector
from stats_manager import StatsManager

PACKET_COUNT = 200
SUMMARY_INTERVAL = 100

stats = StatsManager()
scan_detector = ScanDetector()
events = EventManager()


def handle_packet(packet):
    packet_info = parse_packet(packet)

    stats.update_protocol(packet_info["protocol"])

    if packet_info["src_ip"] and packet_info["dst_ip"]:
        stats.update_ip_counts(packet_info["src_ip"], packet_info["dst_ip"])

    if packet_info["dst_port"] is not None:
        stats.update_port(packet_info["dst_port"])

    event = detect_security_event(packet_info)
    if event:
        events.add_event(event)

    if stats.get_total_packets() % SUMMARY_INTERVAL == 0:
        stats.print_summary()


def parse_packet(packet):
    packet_info = {
        "protocol": "Non-IP",
        "src_ip": None,
        "dst_ip": None,
        "dst_port": None,
        "tcp_flags": "",
    }

    if IP not in packet:
        return packet_info

    packet_info["src_ip"] = packet[IP].src
    packet_info["dst_ip"] = packet[IP].dst
    packet_info["protocol"] = "Other IP"

    if TCP in packet:
        packet_info["protocol"] = "TCP"
        packet_info["dst_port"] = packet[TCP].dport
        packet_info["tcp_flags"] = str(packet[TCP].flags)
    elif UDP in packet:
        packet_info["protocol"] = "UDP"
        packet_info["dst_port"] = packet[UDP].dport
    elif ICMP in packet:
        packet_info["protocol"] = "ICMP"

    return packet_info


def detect_security_event(packet_info):
    if packet_info["protocol"] != "TCP":
        return None

    flags = packet_info["tcp_flags"]
    is_syn_packet = "S" in flags and "A" not in flags

    if not is_syn_packet:
        return None

    return scan_detector.analyze_packet(
        packet_info["dst_port"],
        packet_info["src_ip"],
        packet_info["dst_ip"],
    )


def main():
    print_banner()
    try:
        sniff(prn=handle_packet, store=False, count=PACKET_COUNT)
    except KeyboardInterrupt:
        print()
        print("Capture stopped by user.")

    print_finished()


def print_banner():
    print("=" * 64)
    print("Anti Virus Network Monitor")
    print("=" * 64)
    print(f"Capturing {PACKET_COUNT} packets. Press Ctrl+C to stop.")
    print(f"Summary prints every {SUMMARY_INTERVAL} packets.")


def print_finished():
    print()
    print("=" * 64)
    print("Capture Finished")
    print("=" * 64)
    stats.print_summary()
    events.print_events()


if __name__ == "__main__":
    main()
