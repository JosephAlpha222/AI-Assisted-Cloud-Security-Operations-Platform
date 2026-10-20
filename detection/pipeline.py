import json

from detection.engine import detect, detect_all, load_rule, load_rules
from ingestion.pipeline import process_aws_event


def run_detection(event_path: str, rule_path: str) -> dict:
    """Run detection against one rule."""
    normalized_event = process_aws_event(event_path)
    rule = load_rule(rule_path)

    result = detect(normalized_event, rule)

    return {
        "event": normalized_event,
        "detection": result,
    }


def run_detection_all(event_path: str, rules_directory: str) -> dict:
    """Run detection against every rule in a directory."""
    normalized_event = process_aws_event(event_path)
    rules = load_rules(rules_directory)

    findings = detect_all(normalized_event, rules)

    return {
        "event": normalized_event,
        "detections": findings,
    }


if __name__ == "__main__":
    event_path = "data/events/iam_create_access_key.json"
    rules_directory = "detection/rules"

    result = run_detection_all(event_path, rules_directory)

    print(json.dumps(result, indent=2))
