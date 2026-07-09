import time

from packet_parser import is_tcp_syn
from scan_detector import ScanDetector
from security_event import SecurityEvent


class ThreatDetector:
    def __init__(self, detection_config=None):
        detection_config = detection_config or {}
        scan_config = detection_config.get("scan_detection", {})
        burst_config = detection_config.get("burst_detection", {})

        self.tcp_scan_detector = ScanDetector(
            port_threshold=scan_config.get("tcp_syn_port_threshold", 8),
            time_window=scan_config.get("tcp_syn_time_window_seconds", 10),
            event_type="TCP SYN Port Scan",
            protocol="TCP",
            severity="HIGH",
        )
        self.udp_sweep_detector = ScanDetector(
            port_threshold=scan_config.get("udp_port_threshold", 12),
            time_window=scan_config.get("udp_time_window_seconds", 10),
            event_type="UDP Port Sweep",
            protocol="UDP",
            severity="MEDIUM",
        )
        self.burst_enabled = burst_config.get("enabled", True)
        self.burst_packet_threshold = burst_config.get("packet_threshold", 40)
        self.burst_window_seconds = burst_config.get("time_window_seconds", 5)
        self.burst_tracker = {}
        self.alerted_bursts = set()

    def analyze_packet(self, packet_info):
        events = []

        if is_tcp_syn(packet_info):
            tcp_scan_event = self.tcp_scan_detector.analyze_packet(
                packet_info["dst_port"],
                packet_info["src_port"],
                packet_info["src_ip"],
                packet_info["dst_ip"],
                packet_info["packet_size"],
            )
            if tcp_scan_event:
                events.append(tcp_scan_event)

        if packet_info["protocol"] == "UDP" and packet_info["dst_port"] is not None:
            udp_event = self.udp_sweep_detector.analyze_packet(
                packet_info["dst_port"],
                packet_info["src_port"],
                packet_info["src_ip"],
                packet_info["dst_ip"],
                packet_info["packet_size"],
            )
            if udp_event:
                events.append(udp_event)

        burst_event = self.analyze_burst(packet_info)
        if burst_event:
            events.append(burst_event)

        return events

    def analyze_burst(self, packet_info):
        if not self.burst_enabled or not packet_info["src_ip"]:
            return None

        src_ip = packet_info["src_ip"]
        current_time = time.perf_counter()
        recent_times = self.burst_tracker.setdefault(src_ip, [])
        recent_times.append(current_time)

        cutoff = current_time - self.burst_window_seconds
        self.burst_tracker[src_ip] = [
            seen_time for seen_time in recent_times if seen_time >= cutoff
        ]

        current_count = len(self.burst_tracker[src_ip])
        if current_count < self.burst_packet_threshold:
            return None

        alert_key = (src_ip, self.burst_window_seconds)
        if alert_key in self.alerted_bursts:
            return None

        self.alerted_bursts.add(alert_key)
        return SecurityEvent(
            event_type="Traffic Burst",
            severity="MEDIUM",
            source="threat_detector",
            action="INVESTIGATE",
            src_ip=src_ip,
            dst_ip=packet_info["dst_ip"],
            message=(
                f"{src_ip} sent {current_count} packets in "
                f"{self.burst_window_seconds} seconds"
            ),
            details={
                "packet_count": current_count,
                "time_window": self.burst_window_seconds,
                "threshold": self.burst_packet_threshold,
                "protocol": packet_info["protocol"],
            },
        )
