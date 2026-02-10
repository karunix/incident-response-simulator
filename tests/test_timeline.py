from ir_simulator.utils import build_timeline


def test_timeline_sorted_and_classified():
    logs = [
        {"timestamp": 3, "event": "SUCCESS"},
        {"timestamp": 1, "event": "FAIL"},
        {"timestamp": 2, "event": "LOGIN_SUCCESS"},
    ]

    timeline = build_timeline(logs)

    assert timeline[0].timestamp == 1
    assert timeline[0].significance == "SUSPICIOUS"
    assert timeline[-1].significance == "INFO"
