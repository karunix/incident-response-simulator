from ir_simulator.detectors.bruteforce_login import detect_bruteforce_login
from ir_simulator.models import Severity


def test_bruteforce_followed_by_success_detected():
    logs = [
        {"timestamp": 1, "ip": "1.2.3.4", "event": "FAIL"},
        {"timestamp": 2, "ip": "1.2.3.4", "event": "FAIL"},
        {"timestamp": 3, "ip": "1.2.3.4", "event": "FAIL"},
        {"timestamp": 4, "ip": "1.2.3.4", "event": "SUCCESS"},
    ]

    incidents = detect_bruteforce_login(logs)

    assert len(incidents) == 1
    assert incidents[0].severity == Severity.HIGH


def test_normal_login_activity_ok():
    logs = [
        {"timestamp": 1, "ip": "5.6.7.8", "event": "SUCCESS"},
    ]

    incidents = detect_bruteforce_login(logs)

    assert incidents == []
