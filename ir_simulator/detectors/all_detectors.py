from ir_simulator.detectors.bruteforce_login import detect_bruteforce_login
from ir_simulator.detectors.privilege_escalation import detect_privilege_escalation
from ir_simulator.detectors.log_tampering import detect_log_tampering


def run_all_detectors(logs):
    incidents = []

    incidents.extend(detect_bruteforce_login(logs))
    incidents.extend(detect_privilege_escalation(logs))
    incidents.extend(detect_log_tampering(logs))

    return incidents
