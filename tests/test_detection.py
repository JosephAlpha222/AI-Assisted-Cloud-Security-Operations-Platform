
import pytest

from detection.engine import detect, load_rule
from detection.pipeline import run_detection


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

    result = detect({"action": "DescribeInstances"}, rule)

    assert set(result) == {
        "detected", "rule_id", "rule", "severity",
        "title", "reason", "response",
    }
    assert result["detected"] is False


def test_matched_action_has_explanation():
    rule = {
        "name": "Test IAM Rule",
        "severity": "high",
        "actions": ["CreateAccessKey"],
    }

    result = detect({"action": "CreateAccessKey"}, rule)

    assert result["detected"] is True
    assert "CreateAccessKey" in result["reason"]


def test_rule_missing_required_field_is_rejected(tmp_path):
    path = tmp_path / "rule.yaml"
    path.write_text("name: Test Rule\nseverity: high\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing required field: actions"):
        load_rule(str(path))


def test_rule_with_string_actions_is_rejected(tmp_path):
    path = tmp_path / "rule.yaml"
    path.write_text(
        "name: Test Rule\nseverity: high\nactions: CreateAccessKey\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="actions must be a non-empty list"):
        load_rule(str(path))


def test_rule_with_empty_actions_is_rejected(tmp_path):
    path = tmp_path / "rule.yaml"
    path.write_text(
        "name: Test Rule\nseverity: high\nactions: []\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="actions must be a non-empty list"):
        load_rule(str(path))


def test_rule_with_empty_action_is_rejected(tmp_path):
    path = tmp_path / "rule.yaml"
    path.write_text(
        "name: Test Rule\nseverity: high\nactions:\n  - CreateAccessKey\n  - ''\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Every rule action must be a non-empty string",
    ):
        load_rule(str(path))


def test_event_missing_action_is_not_detected():
    rule = {
        "name": "Test IAM Rule",
        "severity": "high",
        "actions": ["CreateAccessKey"],
    }

    result = detect({}, rule)

    assert result["detected"] is False
    assert result["severity"] == "informational"


def test_event_with_non_string_action_is_not_detected():
    rule = {
        "name": "Test IAM Rule",
        "severity": "high",
        "actions": ["CreateAccessKey"],
    }

    result = detect({"action": ["CreateAccessKey"]}, rule)

    assert result["detected"] is False
    assert result["severity"] == "informational"


def test_non_dictionary_event_is_rejected():
    rule = {
        "name": "Test IAM Rule",
        "severity": "high",
        "actions": ["CreateAccessKey"],
    }

    with pytest.raises(ValueError, match="Event must be a dictionary"):
        detect(None, rule)
