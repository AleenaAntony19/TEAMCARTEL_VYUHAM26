from __future__ import annotations

from pathlib import Path

import yaml

CATEGORIES = {"image_host", "forum", "mirror", "paste", "gallery", "directory"}


def load_registry(path: str | Path) -> list[dict]:
    data = yaml.safe_load(Path(path).read_text()) or []
    out = []
    for row in data:
        category = row.get("category")
        if category not in CATEGORIES:
            raise ValueError(f"Unknown registry category: {category}")
        if row.get("enabled"):
            out.append(row)
    return out

