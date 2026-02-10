from ir_simulator.models import Incident, Severity


FAILED_THRESHOLD = 3


def detect_bruteforce_login(logs):
    incidents = []

    failures_by_ip = {}

    # logs are assumed to be time-ordered
    for entry in logs:
        ip = entry.get("ip")
        event = entry.get("event")

        if event == "FAIL":
            failures_by_ip[ip] = failures_by_ip.get(ip, 0) + 1

        elif event == "SUCCESS":
            if failures_by_ip.get(ip, 0) >= FAILED_THRESHOLD:
                incidents.append(
                    Incident(
                        title="Brute-force login followed by successful authentication",
                        severity=Severity.HIGH,
                        evidence=[
                            f"{failures_by_ip[ip]} failed logins from IP {ip}",
                            f"Successful login from IP {ip}",
                        ],
                        explanation=(
                            "Multiple failed authentication attempts followed by a successful "
                            "login from the same IP may indicate a brute-force attack."
                        ),
                        recommended_actions=[
                            "Disable or lock the affected account",
                            "Reset credentials",
                            "Review authentication logs for further suspicious activity",
                            "Block the source IP if appropriate",
                        ],
                    )
                )

                # Reset to avoid duplicate alerts
                failures_by_ip[ip] = 0

    return incidents
