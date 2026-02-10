import argparse
import json
import sys

from ir_simulator.detectors.all_detectors import run_all_detectors
from ir_simulator.utils import exit_code_from_incidents


def parse_args():
    parser = argparse.ArgumentParser(
        description="Incident Response Simulator"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to JSON file containing log events"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output incidents in JSON format"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    with open(args.input) as f:
        logs = json.load(f)

    incidents = run_all_detectors(logs)

    if args.json:
        print(json.dumps(
            {"incidents": [i.__dict__ for i in incidents]},
            default=str,
        ))
    else:
        for i in incidents:
            print(f"[{i.severity.value}] {i.title}")

    sys.exit(exit_code_from_incidents(incidents))


if __name__ == "__main__":
    main()
