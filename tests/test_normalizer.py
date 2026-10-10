import pytest

from ingestion.normalizers.aws_cloudtrail import (
    determine_severity,
    normalize_cloudtrail_event,
)


def test_high_risk_iam_action():
    event = {
        "event_id": "test-001",
        "timestamp": "2026-10-07T10:00:00Z",
        "cloud": "aws",
        "account_id": "123456789012",
        "region": "eu-north-1",
        "service": "iam",
        "event_type": "identity_activity",
        "action": "CreateAccessKey",
        "user": {"id": "test-user", "type": "IAMUser"},
        "source": {"ip": "203.0.113.10"},
        "resource": {"type": "iam-user", "id": "test-user"},
        "result": "success",
        "risk_score": 0,
        "severity": "low",
        "detection": None,
    }

    normalized = normalize_cloudtrail_event(event)

    assert normalized.provider == "aws"
    assert normalized.service == "iam"
    assert normalized.action == "CreateAccessKey"
    assert normalized.severity == "high"


def test_low_risk_compute_event():
    event = {
        "event_id": "test-002",
        "timestamp": "2026-10-07T10:00:00Z",
        "cloud": "aws",
        "account_id": "123456789012",
        "region": "eu-north-1",
        "service": "ec2",
        "event_type": "compute_activity",
        "action": "DescribeInstances",
        "user": {"id": "test-user", "type": "IAMUser"},
        "source": {"ip": "203.0.113.10"},
        "resource": {"type": "ec2", "id": "example"},
        "result": "success",
        "risk_score": 0,
        "severity": "low",
        "detection": None,
    }

    normalized = normalize_cloudtrail_event(event)

    assert normalized.provider == "aws"
    assert normalized.service == "ec2"
    assert normalized.action == "DescribeInstances"
    assert normalized.severity == "low"


def test_severity_function():
    assert determine_severity({"action": "CreateAccessKey"}) == "high"
    assert determine_severity({"action": "DescribeInstances"}) == "low"


def test_non_dictionary_event_is_rejected():
    with pytest.raises(ValueError, match="Event must be a dictionary"):
        normalize_cloudtrail_event(None)


def test_non_dictionary_user_is_rejected():
    event = {"action": "CreateAccessKey", "user": "invalid"}

    with pytest.raises(ValueError, match="user must be a dictionary"):
        normalize_cloudtrail_event(event)


def test_non_dictionary_source_is_rejected():
    event = {"action": "CreateAccessKey", "source": "invalid"}

    with pytest.raises(ValueError, match="source must be a dictionary"):
        normalize_cloudtrail_event(event)


def test_non_dictionary_resource_is_rejected():
    event = {"action": "CreateAccessKey", "resource": "invalid"}

    with pytest.raises(ValueError, match="resource must be a dictionary"):
        normalize_cloudtrail_event(event)
