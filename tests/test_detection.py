
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


def test_detect_all_returns_all_matching_findings():
    from detection.engine import detect_all

    event = {"action": "CreateAccessKey"}

    rules = [
        {
            "id": "IAM-001",
            "name": "Suspicious IAM Activity",
            "severity": "high",
            "actions": ["CreateAccessKey", "AttachUserPolicy"],
        },
        {
            "id": "IAM-002",
            "name": "Credential Creation Monitoring",
            "severity": "medium",
            "actions": ["CreateAccessKey"],
        },
    ]

    findings = detect_all(event, rules)

    assert len(findings) == 2
    assert all(finding["detected"] for finding in findings)
    assert findings[0]["rule_id"] == "IAM-001"
    assert findings[1]["rule_id"] == "IAM-002"


def test_detect_all_returns_empty_list_when_no_rules_match():
    from detection.engine import detect_all

    event = {"action": "DescribeInstances"}

    rules = [
        {
            "id": "IAM-001",
            "name": "Suspicious IAM Activity",
            "severity": "high",
            "actions": ["CreateAccessKey"],
        }
    ]

    assert detect_all(event, rules) == []


def test_detect_all_rejects_non_list_rules():
    import pytest
    from detection.engine import detect_all

    with pytest.raises(ValueError, match="Rules must be a list"):
        detect_all({"action": "CreateAccessKey"}, {})


def test_detect_all_rejects_invalid_rule():
    import pytest
    from detection.engine import detect_all

    invalid_rule = {
        "name": "Invalid Rule",
        "severity": "high",
        "actions": [],
    }

    with pytest.raises(ValueError, match="non-empty list"):
        detect_all({"action": "CreateAccessKey"}, [invalid_rule])
