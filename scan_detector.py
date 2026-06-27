import time


class ScanDetector:
    def __init__(self):
        self.scan_tracker = {}
        self.alerted_scanners = set()

    def analyze_packet(self, dst_port, src_ip, dst_ip):
        SCAN_PORT_THRESHOLD = 8
        SCAN_TIME_WINDOW = 10

        src_dest_IP = (src_ip, dst_ip)

        if src_dest_IP not in self.scan_tracker:
            self.scan_tracker[src_dest_IP] = {}

        current_time = time.perf_counter()

        self.scan_tracker[src_dest_IP][dst_port] = current_time

        old_ports = []

        for port, seen_time in self.scan_tracker[src_dest_IP].items():
            if current_time - seen_time > SCAN_TIME_WINDOW:
                old_ports.append(port)

        for port in old_ports:
            del self.scan_tracker[src_dest_IP][port]

        if (
            len(self.scan_tracker[src_dest_IP]) >= SCAN_PORT_THRESHOLD
            and src_dest_IP not in self.alerted_scanners
        ):
            print(
                f"[!] Possible port scan: {src_ip} -> {dst_ip} tried 8 different ports in 10 sec"
            )
            self.alerted_scanners.add(src_dest_IP)
