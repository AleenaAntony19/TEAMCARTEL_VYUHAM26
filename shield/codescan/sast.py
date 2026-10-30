from __future__ import annotations

import json
import subprocess
from pathlib import Path

from . import Finding, fingerprint


def scan_sast(root: Path) -> list[Finding]:
    try:
        proc = subprocess.run(
            ["bandit", "-r", str(root), "-f", "json", "-q"],
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
        rule = f"B{item.get('test_id', '')}"
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

