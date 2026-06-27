from scapy.all import sniff, IP, TCP, UDP, ICMP
from scan_detector import ScanDetector
from stats_manager import StatsManager

stats = StatsManager()
scan_detector = ScanDetector()


def handle_packet(packet):
    # Called by Scapy for each captured packet (via `sniff(prn=...)`)
    # Check if the packet contains an IP layer we can analyze
    if IP in packet:

        # Extract and tally IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        stats.update_ip_counts(src_ip, dst_ip)
        # Inspect transport layer to record ports and protocol type
        if TCP in packet:
            # For TCP, record destination port and mark protocol
            dst_port = packet[TCP].dport
            stats.update_port(dst_port)
            stats.update_protocol("TCP")
            flags = str(packet[TCP].flags)
            # Analyze this packet for simple suspicious indicators
            if "S" in flags and "A" not in flags:
                scan_detector.analyze_packet(dst_port, src_ip, dst_ip)
        elif UDP in packet:
            # For UDP, similarly record destination port
            dst_port = packet[UDP].dport
            stats.update_port(dst_port)
            stats.update_protocol("UDP")

            # Analyze this packet for simple suspicious indicators

        elif ICMP in packet:
            # ICMP has no ports; just mark the protocol
            stats.update_protocol("ICMP")

        else:
            # IP packet but transport layer not recognized
            stats.update_protocol("Other IP")

    else:
        # Non-IP packet (e.g., ARP, 802.11 management frames)
        stats.update_protocol("Non-IP")

    # Update aggregate counters

    # Periodically print summary for every 100 packets
    if stats.protocol_counts["Total"] % 100 == 0:
        stats.print_summary()


def main():
    print("Starting sniffer... Press Ctrl+C to stop.")
    sniff(prn=handle_packet, store=False, count=200)


if __name__ == "__main__":
    main()
