import json
from pathlib import Path


def save_normalized_event(event: dict, output_path: str) -> None:
    path = Path(output_path)

    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(event, file, indent=2)
