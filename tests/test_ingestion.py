
import json

import pytest

from ingestion.pipeline import load_json_event, process_aws_event
from ingestion.save import save_normalized_event


def test_load_valid_json_event(tmp_path):
    path = tmp_path / "event.json"
    path.write_text(
        json.dumps({"action": "DescribeInstances"}),
        encoding="utf-8",
    )

    assert load_json_event(str(path)) == {
        "action": "DescribeInstances"
    }


def test_missing_event_file_is_reported(tmp_path):
    path = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError, match="Event file not found"):
        load_json_event(str(path))


def test_malformed_json_is_rejected(tmp_path):
    path = tmp_path / "malformed.json"
    path.write_text('{"action": ', encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON"):
        load_json_event(str(path))


@pytest.mark.parametrize(
    "content",
    ['["event"]', '"event"', "123", "null"],
)
def test_non_object_json_is_rejected(tmp_path, content):
    path = tmp_path / "not_object.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="Event file must contain a JSON object",
    ):
        load_json_event(str(path))


def test_process_valid_aws_event(tmp_path):
    source = tmp_path / "event.json"
    source.write_text(
        json.dumps({
            "event_id": "test-100",
            "action": "DescribeInstances",
            "service": "ec2",
        }),
        encoding="utf-8",
    )

    event = process_aws_event(str(source))

    assert event["event_id"] == "test-100"
    assert event["provider"] == "aws"
    assert event["action"] == "DescribeInstances"
    assert event["severity"] == "low"


def test_save_normalized_event_creates_output_directory(tmp_path):
    output = tmp_path / "nested" / "normalized.json"
    event = {"event_id": "test-200", "severity": "low"}

    save_normalized_event(event, str(output))

    assert json.loads(output.read_text(encoding="utf-8")) == event


def test_save_rejects_non_dictionary_event(tmp_path):
    output = tmp_path / "normalized.json"

    with pytest.raises(ValueError, match="Event must be a dictionary"):
        save_normalized_event(["invalid"], str(output))


def test_save_replaces_existing_output(tmp_path):
    output = tmp_path / "normalized.json"
    output.write_text('{"old": true}', encoding="utf-8")

    event = {"event_id": "test-300"}

    save_normalized_event(event, str(output))

    assert json.loads(output.read_text(encoding="utf-8")) == event
