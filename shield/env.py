"""Reads `.env` for the API server. Kept to the stdlib: the format we ship is plain KEY=value lines."""
from __future__ import annotations

import os
import re
from pathlib import Path


def load_env(path: Path) -> None:
    """Real environment variables win. Empty values and `  # comments` are ignored."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        m = re.match(r"\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)$", line)
        if not m or line.lstrip().startswith("#"):
            continue
        value = re.sub(r"(^|\s+)#.*$", "", m.group(2)).strip().strip("'\"")
        if value:
            os.environ.setdefault(m.group(1), value)
