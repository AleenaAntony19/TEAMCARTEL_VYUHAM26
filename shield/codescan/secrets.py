from __future__ import annotations

import re
import subprocess
from pathlib import Path

from . import Finding, fingerprint, mask

EXTRA_RULES = {
    "Anthropic Token": re.compile(r"sk-ant-(?:api|admin)\d{2}-[\w-]{80,}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "Hugging Face Token": re.compile(r"hf_[A-Za-z]{34}"),
    "OpenAI Token": re.compile(r"sk-proj-[\w-]{40,}"),
    "Razorpay Key": re.compile(r"rzp_(?:live|test)_[A-Za-z0-9]{14}"),
    "GitHub Token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Slack Token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
CRITICAL = {"Anthropic Token", "Google API Key", "Hugging Face Token", "OpenAI Token", "GitHub Token", "AWS Access Key", "Private Key"}


def _severity(rule: str) -> str:
    if rule in CRITICAL:
        return "critical"
    if rule in {"Razorpay Key", "Slack Token"}:
        return "high"
    return "medium"


def scan_secrets(files: list[Path], root: Path) -> list[Finding]:
    out: list[Finding] = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for rule, pat in EXTRA_RULES.items():
                for m in pat.finditer(line):
                    value = m.group(0)
                    out.append(
                        Finding(
                            id=fingerprint(rule, rel, line, value),
                            engine="secrets",
                            rule=rule,
                            severity=_severity(rule),
                            file=rel,
                            line=i,
                            col=m.start() + 1,
                            end_line=i,
                            end_col=m.end() + 1,
                            message=f"{rule} committed in source",
                            masked=mask(value, rule),
                            fixes=["move_to_env", "ignore"]
                            if path.name not in {".env", "id_rsa"}
                            else ["untrack_file", "gitignore_add", "ignore"],
                        )
                    )
    return out


def scan_history(root: Path) -> list[Finding]:
    out: list[Finding] = []
    try:
        proc = subprocess.run(
            ["git", "log", "-p", "--all", "-n", "500"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        text = proc.stdout
    except Exception:
        return out

    commit = ""
    for line in text.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1]
        for rule, pat in EXTRA_RULES.items():
            for m in pat.finditer(line):
                value = m.group(0)
                out.append(
                    Finding(
                        id=fingerprint(rule, "history", line, value),
                        engine="secrets",
                        rule=rule,
                        severity=_severity(rule),
                        file="history",
                        line=0,
                        col=0,
                        end_line=0,
                        end_col=0,
                        message=f"{rule} found in git history commit {commit[:8]}",
                        masked=mask(value, rule),
                        fixes=["ignore"],
                        in_history=True,
                    )
                )
    return out

