from ir_simulator.detectors.log_tampering import detect_log_tampering
from ir_simulator.models import Severity


def test_log_deletion_detected():
    logs = [
        {"event": "LOGIN_SUCCESS", "user": "root"},
        {"event": "LOG_CLEARED", "target": "/var/log/auth.log"},
    ]

    incidents = detect_log_tampering(logs)

    assert len(incidents) == 1
    assert incidents[0].severity == Severity.HIGH


def test_normal_logging_ok():
    logs = [
        {"event": "LOGIN_SUCCESS", "user": "alice"},
        {"event": "LOG_ROTATED", "target": "/var/log/syslog"},
    ]

    incidents = detect_log_tampering(logs)

    assert incidents == []
