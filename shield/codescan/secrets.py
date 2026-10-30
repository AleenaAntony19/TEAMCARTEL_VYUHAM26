from __future__ import annotations

import re
import subprocess
from pathlib import Path

from . import Finding, evidence, fingerprint, mask, record_error

EXTRA_RULES = {
    "Anthropic Token": re.compile(r"sk-ant-(?:api|admin)\d{2}-[\w-]{80,}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "Hugging Face Token": re.compile(r"hf_[A-Za-z]{34}"),
    "OpenAI Token": re.compile(r"sk-proj-[\w-]{40,}"),
    "Groq Token": re.compile(r"gsk_[A-Za-z0-9]{40,}"),
    "Razorpay Key": re.compile(r"rzp_(?:live|test)_[A-Za-z0-9]{14}"),
    "GitHub Token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Slack Token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
CRITICAL = {"Groq Token", "Anthropic Token", "Google API Key", "Hugging Face Token", "OpenAI Token", "GitHub Token", "AWS Access Key", "Private Key"}


def is_doc_example(value: str) -> bool:
    """Vendor documentation sample keys (AWS: AKIAIOSFODNN7EXAMPLE, wJalr...EXAMPLEKEY) are published, not secrets."""
    return value.endswith("EXAMPLE") or value.endswith("EXAMPLEKEY")


def _severity(rule: str) -> str:
    if rule in CRITICAL:
        return "critical"
    if rule in {"Razorpay Key", "Slack Token", "AWS Access Key", "GitHub Token", "Stripe Access Key", "JSON Web Token", "Basic Auth Credentials"}:
        return "high" if rule not in CRITICAL else "critical"
    return "medium"


DROP_DS = {"Public IP (ipv4)"}


def _detect_secrets(path: Path) -> list[tuple[str, int, str]]:
    """(rule, line, value) from Yelp detect-secrets' default plugins; [] if the library is missing."""
    try:
        from detect_secrets import SecretsCollection
        from detect_secrets.settings import default_settings
    except ImportError:
        return []
    sc = SecretsCollection()
    with default_settings():
        sc.scan_file(str(path))
    return [(s.type, s.line_number, s.secret_value or "") for _, s in sc if s.type not in DROP_DS]


def scan_secrets(files: list[Path], root: Path) -> list[Finding]:
    out: list[Finding] = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError as exc:
            record_error(rel, "secrets", exc)
            continue
        fixes = ["move_to_env", "ignore"] if not path.name.startswith(".env") and path.name not in {"id_rsa", "id_ed25519"} else ["untrack_file", "gitignore_add", "ignore"]
        hits: list[tuple[str, int, int, int, str, float]] = []
        for i, line in enumerate(lines, 1):
            for rule, pat in EXTRA_RULES.items():
                for m in pat.finditer(line):
                    if not is_doc_example(m.group(0)):
                        hits.append((rule, i, m.start(), m.end(), m.group(0), 0.95))
        try:
            for rule, i, value in _detect_secrets(path):
                line = lines[i - 1] if 0 < i <= len(lines) else ""
                col = line.find(value) if value else -1
                if any(h[1] == i and (col < 0 or h[2] <= col < h[3]) for h in hits):
                    continue  # already reported by a specific rule
                conf = 0.5 if "Entropy" in rule or rule == "Secret Keyword" else 0.85
                hits.append((rule, i, max(col, 0), max(col, 0) + len(value), value, conf))
        except Exception as exc:
            record_error(rel, "detect-secrets", exc)
        for rule, i, a, b, value, conf in hits:
            line = lines[i - 1]
            out.append(
                Finding(
                    id=fingerprint(rule, rel, line, value),
                    engine="secrets",
                    rule=rule,
                    severity=_severity(rule) if rule in EXTRA_RULES or conf > 0.5 else "medium",
                    file=rel,
                    line=i,
                    col=a + 1,
                    end_line=i,
                    end_col=b + 1,
                    message=("CRITICAL: Rotate this key now. " if rule in CRITICAL else "") + f"{rule} committed in source",
                    masked=mask(value, rule) if value else "•••",
                    fixes=fixes,
                    confidence=conf,
                    evidence=evidence(line, value, rule) if value else "",
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
                if is_doc_example(value):
                    continue
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
                        message=("CRITICAL: Rotate this key now. " if rule in CRITICAL else "") + f"{rule} found in git history commit {commit[:8]}",
                        masked=mask(value, rule),
                        fixes=["ignore"],
                        in_history=True,
                    )
                )
    return out

