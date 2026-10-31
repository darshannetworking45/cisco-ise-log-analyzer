import unittest
from src.ise import IseLogAnalyzer

SAMPLE_ISE_LOGS = """
2026-10-31 08:00:01, USER:alice, MAC:00:11:22:33:44:55, NAS:192.0.2.1, STATUS:PASS, REASON:None
2026-10-31 08:01:05, USER:contractor1, MAC:AA:BB:CC:DD:EE:FF, NAS:192.0.2.1, STATUS:FAIL, REASON:24408 Wrong credentials
2026-10-31 08:02:10, USER:laptop-sales, MAC:11:22:33:44:55:66, NAS:192.0.2.2, STATUS:FAIL, REASON:24408 Wrong credentials
2026-10-31 08:03:15, USER:printer-floor2, MAC:22:33:44:55:66:77, NAS:192.0.2.2, STATUS:FAIL, REASON:5400 Authentication timeout
"""

class TestIseAnalyzer(unittest.TestCase):
    def test_log_parsing_and_aggregation(self):
        events = [IseLogAnalyzer.parse_line(l) for l in SAMPLE_ISE_LOGS.strip().splitlines()]
        events = [e for e in events if e is not None]
        self.assertEqual(len(events), 4)

        failures = IseLogAnalyzer.aggregate_failures(events)
        self.assertEqual(failures["24408 Wrong credentials"], 2)
        self.assertEqual(failures["5400 Authentication timeout"], 1)

if __name__ == "__main__":
    unittest.main()
