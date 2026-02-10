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
