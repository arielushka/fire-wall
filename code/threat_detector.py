import time

from packet_parser import is_tcp_syn
from scan_detector import ScanDetector
from security_event import SecurityEvent


class ThreatDetector:
    def __init__(self, config=None):
        config = config or {}
        scan = config.get("scan_detection", {})
        burst = config.get("burst_detection", {})

        self.tcp_scan = ScanDetector(
            port_threshold=scan.get("tcp_syn_port_threshold", 8),
            time_window=scan.get("tcp_syn_time_window_seconds", 10),
            event_type="TCP SYN Port Scan",
            protocol="TCP",
            severity="HIGH",
        )
        self.udp_scan = ScanDetector(
            port_threshold=scan.get("udp_port_threshold", 12),
            time_window=scan.get("udp_time_window_seconds", 10),
            event_type="UDP Port Sweep",
            protocol="UDP",
            severity="MEDIUM",
        )

        self.burst_enabled = burst.get("enabled", True)
        self.burst_limit = burst.get("packet_threshold", 40)
        self.burst_seconds = burst.get("time_window_seconds", 5)
        self.packet_times = {}
        self.reported_bursts = set()

    def analyze_packet(self, packet):
        events = []

        if is_tcp_syn(packet):
            event = self.check_scan(self.tcp_scan, packet)
            if event:
                events.append(event)

        if packet["protocol"] == "UDP" and packet["dst_port"] is not None:
            event = self.check_scan(self.udp_scan, packet)
            if event:
                events.append(event)

        burst = self.check_burst(packet)
        if burst:
            events.append(burst)

        return events

    @staticmethod
    def check_scan(detector, packet):
        return detector.analyze_packet(
            packet["dst_port"],
            packet["src_port"],
            packet["src_ip"],
            packet["dst_ip"],
            packet["packet_size"],
        )

    def check_burst(self, packet):
        src_ip = packet["src_ip"]
        if not self.burst_enabled or not src_ip:
            return None

        now = time.perf_counter()
        cutoff = now - self.burst_seconds
        times = self.packet_times.setdefault(src_ip, [])
        times.append(now)
        self.packet_times[src_ip] = [seen for seen in times if seen >= cutoff]

        packet_count = len(self.packet_times[src_ip])
        if packet_count < self.burst_limit or src_ip in self.reported_bursts:
            return None

        self.reported_bursts.add(src_ip)
        return SecurityEvent(
            event_type="Traffic Burst",
            severity="MEDIUM",
            source="threat_detector",
            action="INVESTIGATE",
            src_ip=src_ip,
            dst_ip=packet["dst_ip"],
            message=(
                f"{src_ip} sent {packet_count} packets in "
                f"{self.burst_seconds} seconds"
            ),
            details={
                "packet_count": packet_count,
                "time_window": self.burst_seconds,
                "threshold": self.burst_limit,
                "protocol": packet["protocol"],
            },
        )
