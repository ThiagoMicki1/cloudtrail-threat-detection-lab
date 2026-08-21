from __future__ import annotations

import argparse
from collections import Counter

from .detector import Alert, analyze_path, write_json_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze sanitized AWS CloudTrail JSON logs.")
    parser.add_argument("path", help="CloudTrail JSON file or folder of JSON files")
    parser.add_argument("--json-out", help="Optional path to write a JSON alert report")
    args = parser.parse_args()

    alerts = analyze_path(args.path)
    print_report(alerts)
    if args.json_out:
        write_json_report(alerts, args.json_out)
        print(f"\nJSON report written to: {args.json_out}")
    return 0


def print_report(alerts: list[Alert]) -> None:
    print("=" * 72)
    print("CloudTrail Threat Detection Lab")
    print("=" * 72)
    counts = Counter(alert.severity for alert in alerts)
    print(f"Total alerts: {len(alerts)}")
    print(
        "Severity counts: "
        + " | ".join(f"{severity}: {counts.get(severity, 0)}" for severity in ["INFO", "WARN", "HIGH", "CRITICAL"])
    )

    if not alerts:
        print("\nNo alerts found.")
        return

    for alert in alerts:
        print("\n" + "-" * 72)
        print(f"[{alert.severity}] {alert.rule_name}")
        print(f"Time:        {alert.timestamp}")
        print(f"Event:       {alert.event_name}")
        print(f"Actor:       {alert.actor}")
        print(f"Source IP:   {alert.source_ip}")
        print(f"Region:      {alert.aws_region}")
        print(f"MITRE:       {alert.mitre_attack}")
        print(f"Evidence:    {alert.evidence}")
        print(f"Recommend:   {alert.recommendation}")
