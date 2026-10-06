import json
import yaml


def load_event(path):
    with open(path, "r") as file:
        return json.load(file)


def load_rule(path):
    with open(path, "r") as file:
        return yaml.safe_load(file)


def detect(event, rule):
    if event["action"] in rule["actions"]:
        return {
            "detected": True,
            "rule": rule["name"],
            "severity": rule["severity"],
            "response": rule["response"]
        }

    return {
        "detected": False
    }


if __name__ == "__main__":
    event = load_event(
        "data/events/iam_create_access_key.json"
    )

    rule = load_rule(
        "detection/rules/suspicious_iam_activity.yaml"
    )

    result = detect(event, rule)

    print(json.dumps(result, indent=2))
