
import json


def load_event(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_rule(path):
    import yaml

    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def detect(event, rule):
    action = event.get("action", "")
    suspicious_actions = rule.get("actions", [])
    matched = action in suspicious_actions

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
            "reason": (
                f"Action '{action}' matched the detection rule."
            ),
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
        "reason": (
            f"Action '{action}' did not match the detection rule."
        ),
        "response": {"type": "none"},
    }


if __name__ == "__main__":
    event = load_event(
        "data/events/iam_create_access_key.json"
    )
    rule = load_rule(
        "detection/rules/suspicious_iam_activity.yaml"
    )

    print(json.dumps(detect(event, rule), indent=2))
