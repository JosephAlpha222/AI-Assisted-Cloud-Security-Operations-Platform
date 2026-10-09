
from detection.pipeline import run_detection
from detection.engine import detect


def test_suspicious_iam_activity_is_detected():
    result = run_detection(
        "data/events/iam_create_access_key.json",
        "detection/rules/suspicious_iam_activity.yaml",
    )

    detection = result["detection"]

    assert detection["detected"] is True
    assert detection["rule"] == "Suspicious IAM Activity"
    assert detection["severity"] == "high"
    assert detection["rule_id"] == "IAM-001"
    assert detection["title"]
    assert detection["reason"]
    assert detection["response"]["type"] == "investigate"


def test_benign_ec2_activity_is_not_detected():
    result = run_detection(
        "data/events/describe_instances.json",
        "detection/rules/suspicious_iam_activity.yaml",
    )

    detection = result["detection"]

    assert detection["detected"] is False
    assert detection["severity"] == "informational"
    assert detection["reason"]
    assert detection["response"]["type"] == "none"


def test_unmatched_action_has_consistent_result():
    rule = {
        "name": "Test IAM Rule",
        "severity": "high",
        "actions": ["CreateAccessKey"],
    }

    event = {"action": "DescribeInstances"}

    result = detect(event, rule)

    expected_fields = {
        "detected",
        "rule_id",
        "rule",
        "severity",
        "title",
        "reason",
        "response",
    }

    assert set(result.keys()) == expected_fields
    assert result["detected"] is False


def test_matched_action_has_explanation():
    rule = {
        "name": "Test IAM Rule",
        "severity": "high",
        "actions": ["CreateAccessKey"],
    }

    event = {"action": "CreateAccessKey"}

    result = detect(event, rule)

    assert result["detected"] is True
    assert "CreateAccessKey" in result["reason"]
