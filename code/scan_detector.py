import time

from security_event import SecurityEvent


class ScanDetector:
    def __init__(
        self,
        port_threshold=8,
        time_window=10,
        event_type="TCP SYN Port Scan",
        protocol="TCP",
        severity="HIGH",
    ):
        self.port_threshold = port_threshold
        self.time_window = time_window
        self.event_type = event_type
        self.protocol = protocol
        self.severity = severity
        self.scans = {}
        self.reported_scans = set()

    def analyze_packet(self, dst_port, src_port, src_ip, dst_ip, packet_size):
        connection = (src_ip, dst_ip)
        now = time.perf_counter()
        ports = self.scans.setdefault(connection, {})
        ports[dst_port] = now

        cutoff = now - self.time_window
        self.scans[connection] = {
            port: seen_at for port, seen_at in ports.items() if seen_at >= cutoff
        }
        recent_ports = self.scans[connection]

        if (
            len(recent_ports) < self.port_threshold
            or connection in self.reported_scans
        ):
            return None

        self.reported_scans.add(connection)
        return SecurityEvent(
            event_type=self.event_type,
            severity=self.severity,
            source="scan_detector",
            action="ALERT",
            src_ip=src_ip,
            dst_ip=dst_ip,
            message=(
                f"{self.protocol} traffic tried {len(recent_ports)} destination ports "
                f"in {self.time_window} seconds"
            ),
            details={
                "src_port": src_port,
                "packet_size": packet_size,
                "ports": sorted(recent_ports),
                "threshold": self.port_threshold,
                "time_window": self.time_window,
                "protocol": self.protocol,
            },
        )
