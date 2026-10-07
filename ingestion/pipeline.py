import json
from pathlib import Path

from ingestion.normalizers.aws_cloudtrail import normalize_cloudtrail_event
from ingestion.save import save_normalized_event


def load_json_event(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def process_aws_event(path: str) -> dict:
    raw_event = load_json_event(path)
    normalized_event = normalize_cloudtrail_event(raw_event)

    return normalized_event.to_dict()


if __name__ == "__main__":
    input_path = Path("data/events/describe_instances.json")

    event = process_aws_event(str(input_path))

    output_path = Path(
        "data/normalized/describe_instances.normalized.json"
    )

    save_normalized_event(event, str(output_path))

    print(json.dumps(event, indent=2))
    print(f"\nNormalized event saved to: {output_path}")
