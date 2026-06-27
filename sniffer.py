from scapy.all import ICMP, IP, TCP, UDP, sniff

from event_manager import EventManager
from FirewallManager import FirewallManager
from scan_detector import ScanDetector
from stats_manager import StatsManager

PACKET_COUNT = 200
SUMMARY_INTERVAL = 100

# Shared managers keep the packet handler small and focused.
stats = StatsManager()
scan_detector = ScanDetector()
events = EventManager()
firewall = FirewallManager()
firewall.load_default_rules()


def handle_packet(packet):
    # Scapy calls this function once for every captured packet.
    packet_info = parse_packet(packet)

    # Update the counters first so summaries always include every packet.
    stats.update_protocol(packet_info["protocol"])

    if packet_info["src_ip"] and packet_info["dst_ip"]:
        stats.update_ip_counts(packet_info["src_ip"], packet_info["dst_ip"])

    stats.update_packet_size(packet_info["packet_size"])

    if packet_info["src_port"] is not None:
        stats.update_src_port(packet_info["src_port"])

    if packet_info["dst_port"] is not None:
        stats.update_dst_port(packet_info["dst_port"])

    firewall_result = firewall.check_packet(packet_info)
    if firewall_result["action"] == "BLOCK":
        events.add_event(build_firewall_event(packet_info, firewall_result))
    else:
        if firewall_result["action"] == "ALERT":
            events.add_event(build_firewall_event(packet_info, firewall_result))

        event = detect_security_event(packet_info)
        if event:
            events.add_event(event)

    if stats.get_total_packets() % SUMMARY_INTERVAL == 0:
        stats.print_summary()


def parse_packet(packet):
    # Store packet data in one dictionary so the rest of the code does not
    # need to know Scapy's packet-layer syntax.
    packet_info = {
        "protocol": "Non-IP",
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": "",
        "packet_size": len(packet),
    }

    if IP not in packet:
        return packet_info

    packet_info["src_ip"] = packet[IP].src
    packet_info["dst_ip"] = packet[IP].dst
    packet_info["protocol"] = "Other IP"

    if TCP in packet:

        packet_info["protocol"] = "TCP"
        packet_info["src_port"] = packet[TCP].sport
        packet_info["dst_port"] = packet[TCP].dport
        packet_info["tcp_flags"] = str(packet[TCP].flags)
    elif UDP in packet:
        packet_info["protocol"] = "UDP"
        packet_info["src_port"] = packet[UDP].sport
        packet_info["dst_port"] = packet[UDP].dport
    elif ICMP in packet:
        packet_info["protocol"] = "ICMP"

    return packet_info


def detect_security_event(packet_info):
    # For now, the security detector only checks TCP SYN packets.
    if packet_info["protocol"] != "TCP":
        return None

    flags = packet_info["tcp_flags"]
    # SYN without ACK usually means the start of a TCP connection attempt.
    is_syn_packet = "S" in flags and "A" not in flags

    if not is_syn_packet:
        return None

    return scan_detector.analyze_packet(
        packet_info["dst_port"],
        packet_info["src_port"],
        packet_info["src_ip"],
        packet_info["dst_ip"],
        packet_info["packet_size"],
    )


def build_firewall_event(packet_info, firewall_result):
    action = firewall_result["action"]

    return {
        "type": f"Firewall {action.title()}",
        "severity": firewall_result["severity"],
        "src_ip": packet_info["src_ip"],
        "dst_ip": packet_info["dst_ip"],
        "message": firewall_result["reason"],
        "details": {
            "protocol": packet_info["protocol"],
            "src_port": packet_info["src_port"],
            "dst_port": packet_info["dst_port"],
            "packet_size": packet_info["packet_size"],
        },
    }


def main():
    print_banner()
    try:
        # store=False keeps captured packets out of memory after processing.
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
    firewall.print_summary()
    events.print_events()


if __name__ == "__main__":
    main()
