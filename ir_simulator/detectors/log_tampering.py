from ir_simulator.models import Incident, Severity


def detect_log_tampering(logs):
    incidents = []
    login_seen = False

    for entry in logs:
        event = entry.get("event")

        if event == "LOGIN_SUCCESS":
            login_seen = True

        elif event == "LOG_CLEARED" and login_seen:
            target = entry.get("target", "unknown log")

            incidents.append(
                Incident(
                    title="Potential log tampering detected",
                    severity=Severity.HIGH,
                    evidence=[
                        "Successful login detected",
                        f"Log file cleared: {target}",
                    ],
                    explanation=(
                        "Clearing or tampering with logs after authentication may indicate "
                        "an attempt to hide malicious activity."
                    ),
                    recommended_actions=[
                        "Preserve remaining log files immediately",
                        "Collect forensic images if possible",
                        "Investigate for additional indicators of compromise",
                        "Review access history around the event",
                    ],
                )
            )

            login_seen = False

    return incidents
