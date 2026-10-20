
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


def test_load_rules_loads_yaml_and_yml_files(tmp_path):
    from detection.engine import load_rules

    (tmp_path / "first.yaml").write_text(
        "name: First Rule\n"
        "severity: high\n"
        "actions:\n"
        "  - CreateAccessKey\n",
        encoding="utf-8",
    )

    (tmp_path / "second.yml").write_text(
        "name: Second Rule\n"
        "severity: medium\n"
        "actions:\n"
        "  - PutUserPolicy\n",
        encoding="utf-8",
    )

    rules = load_rules(tmp_path)

    assert len(rules) == 2
    assert [rule["name"] for rule in rules] == [
        "First Rule",
        "Second Rule",
    ]


def test_load_rules_rejects_empty_directory(tmp_path):
    import pytest
    from detection.engine import load_rules

    with pytest.raises(ValueError, match="No YAML detection rules"):
        load_rules(tmp_path)


def test_load_rules_reports_invalid_rule_filename(tmp_path):
    import pytest
    from detection.engine import load_rules

    (tmp_path / "broken.yaml").write_text(
        "name: Broken Rule\n"
        "severity: high\n"
        "actions: []\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="broken.yaml"):
        load_rules(tmp_path)


def test_run_detection_all_returns_multiple_findings(tmp_path):
    from detection.pipeline import run_detection_all

    (tmp_path / "first.yaml").write_text(
        "id: IAM-101\n"
        "name: IAM Credential Creation\n"
        "severity: high\n"
        "actions:\n"
        "  - CreateAccessKey\n",
        encoding="utf-8",
    )

    (tmp_path / "second.yaml").write_text(
        "id: IAM-102\n"
        "name: IAM Activity Monitoring\n"
        "severity: medium\n"
        "actions:\n"
        "  - CreateAccessKey\n",
        encoding="utf-8",
    )

    result = run_detection_all(
        "data/events/iam_create_access_key.json",
        str(tmp_path),
    )

    assert len(result["detections"]) == 2
    assert all(item["detected"] for item in result["detections"])
    assert {
        item["rule_id"] for item in result["detections"]
    } == {"IAM-101", "IAM-102"}


def test_run_detection_all_returns_empty_findings_for_unmatched_event(
    tmp_path,
):
    from detection.pipeline import run_detection_all

    (tmp_path / "iam.yaml").write_text(
        "name: IAM Credential Creation\n"
        "severity: high\n"
        "actions:\n"
        "  - CreateAccessKey\n",
        encoding="utf-8",
    )

    result = run_detection_all(
        "data/events/describe_instances.json",
        str(tmp_path),
    )

    assert result["detections"] == []


def test_summarize_findings_counts_severity_levels():
    from detection.pipeline import summarize_findings

    findings = [
        {"severity": "high"},
        {"severity": "HIGH"},
        {"severity": "medium"},
        {"severity": "critical"},
        {"severity": "custom"},
    ]

    assert summarize_findings(findings) == {
        "status": "findings_detected",
        "total_findings": 5,
        "severity_counts": {
            "high": 2,
            "medium": 1,
            "critical": 1,
            "custom": 1,
        },
    }


def test_summarize_findings_handles_empty_list():
    from detection.pipeline import summarize_findings

    assert summarize_findings([]) == {
        "status": "no_findings",
        "total_findings": 0,
        "severity_counts": {},
    }


def test_summarize_findings_rejects_invalid_finding():
    import pytest
    from detection.pipeline import summarize_findings

    with pytest.raises(ValueError, match="non-empty severity"):
        summarize_findings([{"severity": " "}])
