import json
from pathlib import Path

from detection.engine import detect, load_rule
from ingestion.pipeline import process_aws_event


def run_detection(event_path: str, rule_path: str) -> dict:
    normalized_event = process_aws_event(event_path)
    rule = load_rule(rule_path)

    result = detect(normalized_event, rule)

    return {
        "event": normalized_event,
        "detection": result,
    }


if __name__ == "__main__":
    event_path = "data/events/iam_create_access_key.json"
    rule_path = "detection/rules/suspicious_iam_activity.yaml"

    result = run_detection(event_path, rule_path)

    print(json.dumps(result, indent=2))
