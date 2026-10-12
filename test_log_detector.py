
import unittest
from datetime import datetime

from log_detector import parse_log_line, detect_anomalies


class TestLogSentinel(unittest.TestCase):

    def test_valid_log_line(self):
        line = (
            "2026-10-12T09:00:00|"
            "192.168.1.10|shah|LOGIN_SUCCESS"
        )

        result = parse_log_line(line)

        self.assertIsNotNone(result)
        self.assertEqual(result["ip"], "192.168.1.10")
        self.assertEqual(result["username"], "shah")

    def test_invalid_timestamp(self):
        line = "bad-time|192.168.1.10|shah|LOGIN_SUCCESS"

        self.assertIsNone(parse_log_line(line))

    def test_wrong_number_of_fields(self):
        self.assertIsNone(parse_log_line("one|two|three"))

    def test_five_failed_logins_trigger_alert(self):
        events = []

        for minute in range(5):
            events.append({
                "timestamp": datetime(2026, 10, 12, 10, minute),
                "ip": "203.0.113.50",
                "username": "admin",
                "event": "LOGIN_FAILED"
            })

        alerts = detect_anomalies(events)

        self.assertTrue(any(
            alert["type"] == "BRUTE_FORCE_SUSPECTED"
            for alert in alerts
        ))

    def test_four_failed_logins_do_not_trigger_alert(self):
        events = []

        for minute in range(4):
            events.append({
                "timestamp": datetime(2026, 10, 12, 10, minute),
                "ip": "203.0.113.50",
                "username": "admin",
                "event": "LOGIN_FAILED"
            })

        alerts = detect_anomalies(events)

        self.assertFalse(any(
            alert["type"] == "BRUTE_FORCE_SUSPECTED"
            for alert in alerts
        ))

    def test_unusual_hour_login(self):
        events = [{
            "timestamp": datetime(2026, 10, 12, 2, 30),
            "ip": "198.51.100.25",
            "username": "shah",
            "event": "LOGIN_SUCCESS"
        }]

        alerts = detect_anomalies(events)

        self.assertTrue(any(
            alert["type"] == "UNUSUAL_LOGIN_HOUR"
            for alert in alerts
        ))


if __name__ == "__main__":
    unittest.main()
