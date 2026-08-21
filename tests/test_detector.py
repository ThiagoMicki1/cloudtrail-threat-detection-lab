import json
import tempfile
import unittest
from pathlib import Path

from cloudtrail_detector import analyze_path, load_events
from cloudtrail_detector.detector import write_json_report


SAMPLE_LOG = Path("sample_logs/cloudtrail-sample-events.json")


class DetectorTests(unittest.TestCase):
    def test_loads_cloudtrail_records(self):
        events = load_events(SAMPLE_LOG)

        self.assertEqual(len(events), 14)
        self.assertEqual(events[0]["eventName"], "ConsoleLogin")

    def test_detects_required_rules(self):
        alerts = analyze_path(SAMPLE_LOG)
        names = {alert.rule_name for alert in alerts}

        expected = {
            "Root account usage",
            "Failed console login",
            "AccessDenied spike",
            "New access key creation",
            "IAM policy attachment or policy change",
            "Security group opened to the world",
            "CloudTrail stopped or deleted",
            "Suspicious AssumeRole activity",
            "Console login without MFA",
            "IAM user created",
            "MFA device deactivated",
            "S3 bucket policy changed to public-risky permissions",
        }
        self.assertTrue(expected.issubset(names))

    def test_alerts_include_required_fields(self):
        alert = analyze_path(SAMPLE_LOG)[0]

        self.assertTrue(alert.severity)
        self.assertTrue(alert.rule_name)
        self.assertTrue(alert.event_name)
        self.assertTrue(alert.actor)
        self.assertTrue(alert.source_ip)
        self.assertTrue(alert.aws_region)
        self.assertTrue(alert.timestamp)
        self.assertTrue(alert.evidence)
        self.assertTrue(alert.mitre_attack)
        self.assertTrue(alert.recommendation)

    def test_json_report_export(self):
        alerts = analyze_path(SAMPLE_LOG)
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "alerts.json"

            write_json_report(alerts, report_path)

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["total_alerts"], len(alerts))
            self.assertGreaterEqual(report["summary"]["by_severity"]["CRITICAL"], 1)
            self.assertEqual(len(report["alerts"]), len(alerts))


if __name__ == "__main__":
    unittest.main()
