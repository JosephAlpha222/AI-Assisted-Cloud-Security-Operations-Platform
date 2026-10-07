from detection.pipeline import run_detection


def test_suspicious_iam_activity_is_detected():
    result = run_detection(
        "data/events/iam_create_access_key.json",
        "detection/rules/suspicious_iam_activity.yaml",
    )

    assert result["detection"]["detected"] is True
    assert result["detection"]["rule"] == "Suspicious IAM Activity"
    assert result["detection"]["severity"] == "high"


def test_benign_ec2_activity_is_not_detected():
    result = run_detection(
        "data/events/describe_instances.json",
        "detection/rules/suspicious_iam_activity.yaml",
    )

    assert result["detection"]["detected"] is False
