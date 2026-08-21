"""CloudTrail Threat Detection Lab."""

from .detector import Alert, analyze_path, load_events

__all__ = ["Alert", "analyze_path", "load_events"]
