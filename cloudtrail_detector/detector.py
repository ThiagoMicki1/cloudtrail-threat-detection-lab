from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Alert:
    severity: str
    rule_name: str
    event_name: str
    actor: str
    source_ip: str
    aws_region: str
    timestamp: str
    evidence: str
    mitre_attack: str
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def load_events(path: str | Path) -> list[dict[str, Any]]:
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"Input path not found: {target}")

    files = sorted(target.rglob("*.json")) if target.is_dir() else [target]
    events: list[dict[str, Any]] = []
    for file_path in files:
        with file_path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict) and isinstance(data.get("Records"), list):
            events.extend(data["Records"])
        elif isinstance(data, list):
            events.extend(data)
        elif isinstance(data, dict):
            events.append(data)
    return events


def analyze_path(path: str | Path) -> list[Alert]:
    from .rules import run_rules

    return run_rules(load_events(path))


def write_json_report(alerts: list[Alert], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "summary": {
            "total_alerts": len(alerts),
            "by_severity": {
                severity: sum(1 for alert in alerts if alert.severity == severity)
                for severity in ["INFO", "WARN", "HIGH", "CRITICAL"]
            },
        },
        "alerts": [alert.to_dict() for alert in alerts],
    }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
