from __future__ import annotations

import subprocess
from pathlib import Path

from . import Finding, fingerprint


def _tracked(root: Path) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files"], cwd=root, capture_output=True, text=True, timeout=20, check=False
        )
        return [x for x in out.stdout.splitlines() if x]
    except Exception:
        return []


def scan_config(root: Path) -> list[Finding]:
    out: list[Finding] = []
    tracked = _tracked(root)
    for rel in tracked:
        name = Path(rel).name
        if name.startswith(".env") and name != ".env.example":
            out.append(Finding(fingerprint("ENV_TRACKED", rel, rel, rel), "config", "ENV_TRACKED", "critical", rel, 0, 0, 0, 0, "environment file is tracked", "", ["untrack_file", "gitignore_add", "ignore"]))
        if name in {"id_rsa", "id_ed25519"} or name.endswith((".pem", ".p12", ".keystore")):
            out.append(Finding(fingerprint("KEY_FILE_TRACKED", rel, rel, rel), "config", "KEY_FILE_TRACKED", "critical", rel, 0, 0, 0, 0, "private key material is tracked", "", ["untrack_file", "gitignore_add", "ignore"]))

    gitignore = root / ".gitignore"
    if not gitignore.exists() or ".env" not in gitignore.read_text(errors="ignore"):
        out.append(Finding(fingerprint("GITIGNORE_MISSING_ENV", ".gitignore", ".env", ".env"), "config", "GITIGNORE_MISSING_ENV", "medium", ".gitignore", 0, 0, 0, 0, ".gitignore does not ignore .env", "", ["gitignore_add", "ignore"]))

    from . import SKIP_DIRS

    for path in root.rglob("settings*.py"):
        rel = path.relative_to(root).as_posix()
        if SKIP_DIRS.intersection(rel.split("/")):
            continue
        for i, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            if "DEBUG" in line and "True" in line:
                out.append(Finding(fingerprint("DEBUG_TRUE_DJANGO", rel, line, "True"), "config", "DEBUG_TRUE_DJANGO", "high", rel, i, 0, i, 0, "Django DEBUG=True", "", ["ignore"]))
    return out

