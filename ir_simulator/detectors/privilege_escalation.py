
from ir_simulator.models import Incident, Severity


def detect_privilege_escalation(logs):
    incidents = []
    logged_in_users = set()

    for entry in logs:
        user = entry.get("user")
        event = entry.get("event")

        if event == "LOGIN_SUCCESS":
            logged_in_users.add(user)

        elif event == "PRIV_ESCALATION" and user in logged_in_users:
            incidents.append(
                Incident(
                    title="Privilege escalation after successful login",
                    severity=Severity.CRITICAL,
                    evidence=[
                        f"User '{user}' logged in successfully",
                        f"Privilege escalation detected for user '{user}'",
                    ],
                    explanation=(
                        "A privilege escalation following a successful login may indicate "
                        "account compromise and post-exploitation activity."
                    ),
                    recommended_actions=[
                        "Immediately revoke elevated privileges",
                        "Isolate the affected system",
                        "Reset user credentials",
                        "Conduct a full forensic investigation",
                    ],
                )
            )

            logged_in_users.remove(user)

    return incidents
