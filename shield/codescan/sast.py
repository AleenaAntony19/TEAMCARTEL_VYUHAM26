from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from . import SKIP_DIRS, Finding, fingerprint


def _flagged_line(code: str, line: int) -> str:
    """Bandit's snippet includes neighbouring lines (which may hold secrets): keep the flagged one, masked."""
    from . import evidence

    for raw in code.splitlines():
        num, _, rest = raw.strip().partition(" ")
        if num == str(line):
            return evidence(rest, "", "sast")
    return ""


def _bandit_cmd() -> list[str]:
    # frozen engine ships bandit inside itself (`shield-engine bandit`); otherwise use this interpreter's module
    return [sys.executable, "bandit"] if getattr(sys, "frozen", False) else [sys.executable, "-m", "bandit"]


def scan_sast(root: Path, exclude: tuple[str, ...] = ()) -> list[Finding]:
    skip = ",".join(str(root / d) for d in sorted(SKIP_DIRS)) + "".join("," + str(root / e) for e in exclude if "*" not in e)
    try:
        proc = subprocess.run(
            [*_bandit_cmd(), "-r", str(root), "-f", "json", "-q", "-x", skip],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        data = json.loads(proc.stdout or "{}")
    except Exception:
        return _fallback(root)

    out = []
    for item in data.get("results", []):
        rule = item.get("test_id", "")  # already 'B506' etc.
        sev = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(item.get("issue_severity", "LOW"), "low")
        file = item.get("filename", "")
        try:
            rel = Path(file).resolve().relative_to(root.resolve()).as_posix()
        except Exception:
            rel = file
        line = int(item.get("line_number", 0))
        text = item.get("code", "")
        out.append(
            Finding(
                id=fingerprint(rule, rel, text, text),
                engine="sast",
                rule=rule,
                severity=sev,
                file=rel,
                line=line,
                col=0,
                end_line=line,
                end_col=0,
                message=item.get("issue_text", "")[:200],
                masked="",
                fixes=["yaml_safe_load"] if rule == "B506" else (["requests_verify"] if rule == "B501" else ["ignore"]),
                confidence={"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}.get(item.get("issue_confidence", "LOW"), 0.5),
                evidence=_flagged_line(text, line),
            )
        )
    return out


def _fallback(root: Path) -> list[Finding]:
    out = []
    for path in root.rglob("*.py"):
        if any(part in {".git", ".venv", "venv"} for part in path.parts):
            continue
        rel = path.relative_to(root).as_posix()
        for i, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            if "yaml.load(" in line:
                out.append(Finding(fingerprint("B506", rel, line, "yaml.load"), "sast", "B506", "high", rel, i, 0, i, 0, "unsafe yaml.load", "", ["yaml_safe_load", "ignore"]))
            if "verify=False" in line:
                out.append(Finding(fingerprint("B501", rel, line, "verify=False"), "sast", "B501", "medium", rel, i, 0, i, 0, "TLS verification disabled", "", ["requests_verify", "ignore"]))
            if "shell=True" in line:
                out.append(Finding(fingerprint("B602", rel, line, "shell=True"), "sast", "B602", "high", rel, i, 0, i, 0, "subprocess shell=True", "", ["ignore"]))
    return out

