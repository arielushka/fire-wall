import time

from security_event import SecurityEvent


class ScanDetector:
    def __init__(self, port_threshold=8, time_window=10):
        # For each pair of computers, remember which destination ports were tried.
        self.scan_tracker = {}
        self.alerted_scanners = set()
        self.port_threshold = port_threshold
        self.time_window = time_window

    def analyze_packet(self, dst_port, src_port, src_ip, dst_ip, packet_size):
        src_dst_pair = (src_ip, dst_ip)
        current_time = time.perf_counter()

        if src_dst_pair not in self.scan_tracker:
            self.scan_tracker[src_dst_pair] = {}

        self.scan_tracker[src_dst_pair][dst_port] = current_time
        # Keep only recent ports so old traffic does not trigger alerts.
        self.remove_old_ports(src_dst_pair, current_time)

        recent_ports = self.scan_tracker[src_dst_pair]
        if len(recent_ports) < self.port_threshold:
            return None

        if src_dst_pair in self.alerted_scanners:
            return None

        self.alerted_scanners.add(src_dst_pair)

        return SecurityEvent(
            event_type="Port Scan",
            severity="HIGH",
            source="scan_detector",
            action="ALERT",
            src_ip=src_ip,
            dst_ip=dst_ip,
            message=(
                f"Tried {len(recent_ports)} different destination ports "
                f"in {self.time_window} seconds"
            ),
            details={
                "src_port": src_port,
                "packet_size": packet_size,
                "ports": sorted(recent_ports.keys()),
                "threshold": self.port_threshold,
                "time_window": self.time_window,
            },
        )

    def remove_old_ports(self, src_dst_pair, current_time):
        old_ports = []

        # Collect first, delete second, so the dictionary is not changed while
        # Python is looping over it.
        for port, seen_time in self.scan_tracker[src_dst_pair].items():
            if current_time - seen_time > self.time_window:
                old_ports.append(port)

        for port in old_ports:
            del self.scan_tracker[src_dst_pair][port]
