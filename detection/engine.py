
import json
import yaml


def validate_rule(rule):
    """Validate the structure of a detection rule."""
    if not isinstance(rule, dict):
        raise ValueError("Detection rule must be a YAML mapping.")

    for field in ("name", "severity", "actions"):
        if field not in rule:
            raise ValueError(
                f"Detection rule is missing required field: {field}"
            )

    if not isinstance(rule["name"], str) or not rule["name"].strip():
        raise ValueError("Rule name must be a non-empty string.")

    if not isinstance(rule["severity"], str) or not rule["severity"].strip():
        raise ValueError("Rule severity must be a non-empty string.")

    actions = rule["actions"]

    if not isinstance(actions, list) or not actions:
        raise ValueError("Rule actions must be a non-empty list.")

    if not all(
        isinstance(action, str) and action.strip()
        for action in actions
    ):
        raise ValueError("Every rule action must be a non-empty string.")

    return rule


def load_event(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_rule(path):
    with open(path, "r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    return validate_rule(rule)


def detect(event, rule):
    """Evaluate one event against one detection rule."""
    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary.")

    validate_rule(rule)

    action = event.get("action", "")

    if not isinstance(action, str):
        action = ""

    matched = action in rule["actions"]

    if matched:
        return {
            "detected": True,
            "rule_id": rule.get("id", "IAM-001"),
            "rule": rule["name"],
            "severity": rule["severity"],
            "title": rule.get(
                "title",
                "Suspicious IAM activity detected",
            ),
            "reason": f"Action '{action}' matched the detection rule.",
            "response": rule.get(
                "response",
                {"type": "investigate"},
            ),
        }

    return {
        "detected": False,
        "rule_id": rule.get("id", "IAM-001"),
        "rule": rule["name"],
        "severity": "informational",
        "title": "No matching suspicious activity",
        "reason": f"Action '{action}' did not match the detection rule.",
        "response": {"type": "none"},
    }


def detect_all(event, rules):
    """Return every detection finding that matches an event."""
    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary.")

    if not isinstance(rules, list):
        raise ValueError("Rules must be a list.")

    findings = []

    for rule in rules:
        result = detect(event, rule)

        if result["detected"]:
            findings.append(result)

    return findings


if __name__ == "__main__":
    event = load_event("data/events/iam_create_access_key.json")
    rule = load_rule("detection/rules/suspicious_iam_activity.yaml")
    print(json.dumps(detect(event, rule), indent=2))
