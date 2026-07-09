from scapy.all import ICMP, IP, TCP, UDP


def parse_packet(packet):
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


def is_tcp_syn(packet_info):
    return (
        packet_info["protocol"] == "TCP"
        and "S" in packet_info["tcp_flags"]
        and "A" not in packet_info["tcp_flags"]
    )
