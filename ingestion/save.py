
import json
import os
import tempfile
from pathlib import Path


def save_normalized_event(event: dict, output_path: str) -> None:
    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            json.dump(event, file, indent=2)
            file.write("\n")

        os.replace(temporary_path, path)
        temporary_path = None

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
