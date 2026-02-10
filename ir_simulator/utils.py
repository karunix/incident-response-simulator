from ir_simulator.models import Severity


def exit_code_from_incidents(incidents):
    if not incidents:
        return 0

    severities = {i.severity for i in incidents}

    if Severity.CRITICAL in severities:
        return 3
    if Severity.HIGH in severities:
        return 2
    if Severity.MEDIUM in severities:
        return 1

    return 0

from ir_simulator.models import TimelineEvent


def build_timeline(logs):
    timeline = []

    for entry in logs:
        timeline.append(
            TimelineEvent(
                timestamp=entry.get("timestamp", 0),
                description=str(entry),
                significance=_classify_event(entry),
            )
        )

    timeline.sort(key=lambda e: e.timestamp)
    return timeline


def _classify_event(entry):
    event = entry.get("event", "")

    if event in {"PRIV_ESCALATION", "LOG_CLEARED"}:
        return "CRITICAL"
    if event in {"FAIL"}:
        return "SUSPICIOUS"
    return "INFO"

