import unittest

from FirewallManager import FirewallManager
from scan_detector import ScanDetector


class FirewallV1Tests(unittest.TestCase):
    def test_blocks_public_source_to_sensitive_service(self):
        firewall = FirewallManager()
        firewall.load_default_rules()

        result = firewall.evaluate_packet(
            {
                "src_ip": "8.8.8.8",
                "dst_ip": "192.168.1.10",
                "protocol": "TCP",
                "src_port": 44444,
                "dst_port": 3389,
                "tcp_flags": "S",
                "packet_size": 60,
            }
        )

        self.assertEqual(result.action, "BLOCK")
        self.assertEqual(result.severity, "CRITICAL")

    def test_alerts_configured_destination_port(self):
        firewall = FirewallManager()
        firewall.load_default_rules()

        result = firewall.evaluate_packet(
            {
                "src_ip": "192.168.1.20",
                "dst_ip": "192.168.1.30",
                "protocol": "TCP",
                "src_port": 50000,
                "dst_port": 3306,
                "tcp_flags": "S",
                "packet_size": 60,
            }
        )

        self.assertEqual(result.action, "ALERT")

    def test_scan_detector_alerts_once_per_pair(self):
        detector = ScanDetector(port_threshold=3, time_window=10)

        self.assertIsNone(detector.analyze_packet(80, 12345, "10.0.0.1", "10.0.0.2", 60))
        self.assertIsNone(detector.analyze_packet(81, 12345, "10.0.0.1", "10.0.0.2", 60))
        first_event = detector.analyze_packet(82, 12345, "10.0.0.1", "10.0.0.2", 60)
        second_event = detector.analyze_packet(83, 12345, "10.0.0.1", "10.0.0.2", 60)

        self.assertIsNotNone(first_event)
        self.assertIsNone(second_event)


if __name__ == "__main__":
    unittest.main()
