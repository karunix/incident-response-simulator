from ir_simulator.detectors.privilege_escalation import detect_privilege_escalation
from ir_simulator.models import Severity


def test_privilege_escalation_after_login_detected():
    logs = [
        {"user": "alice", "event": "LOGIN_SUCCESS"},
        {"user": "alice", "event": "PRIV_ESCALATION"},
    ]

    incidents = detect_privilege_escalation(logs)

    assert len(incidents) == 1
    assert incidents[0].severity == Severity.CRITICAL


def test_login_without_escalation_ok():
    logs = [
        {"user": "bob", "event": "LOGIN_SUCCESS"},
    ]

    incidents = detect_privilege_escalation(logs)

    assert incidents == []
