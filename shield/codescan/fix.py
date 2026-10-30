"""Fix plans for codescan findings.

Edit model (shared with the VS Code extension's preview): a TextEdit replaces the range
[line:col, end_line:end_col) in `file`; lines are 1-based, columns 0-based; an empty range inserts.
Edits are applied bottom-up so earlier ranges stay valid. Every path is confined to the scan root.
"""
from __future__ import annotations

import base64
import hashlib
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from shield.detect import detect, verhoeff_check_digit
from shield.models import Entity
from shield.redact.image import redact_image


@dataclass
class TextEdit:
    file: str
    line: int
    col: int
    end_line: int
    end_col: int
    new_text: str


@dataclass
class FileOp:
    op: str  # append_line | replace_binary | git_rm_cached
    file: str
    content_b64: str | None = None
    summary: str = ""


@dataclass
class FixPlan:
    edits: list[TextEdit] = field(default_factory=list)
    file_ops: list[FileOp] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def public(self) -> dict:
        """Dry-run view: edits plus op summaries; payloads (which may hold the secret) are left out."""
        return {
            "edits": [asdict(e) for e in self.edits],
            "file_ops": [{"op": o.op, "file": o.file, "summary": o.summary} for o in self.file_ops],
            "notes": self.notes,
        }


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _append(file: str, line: str, summary: str) -> FileOp:
    return FileOp("append_line", file, _b64(line), summary)


def _env_name(line_text: str, finding: dict) -> str:
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*[\"']", line_text)
    name = m.group(1) if m else finding["rule"]
    return re.sub(r"[^A-Z0-9_]", "_", name.upper()) or "SECRET"


def _line_edit(rel: str, lineno: int, old: str, new: str) -> TextEdit:
    return TextEdit(rel, lineno, 0, lineno, len(old), new)


FAKE_VALUES = {
    "IN_AADHAAR": f"9999 9999 999{verhoeff_check_digit('99999999999')}",  # format-valid, reserved-looking test number
    "IN_PAN": "AAAPZ1234A",
    "MOBILE_IN": "+91 90000 00000",
    "EMAIL_ADDRESS": "user1@example.com",
    "IN_UPI": "test@upi",
    "IN_IFSC": "SBIN0000000",
}


def _fake(rule: str) -> str:
    return FAKE_VALUES.get(rule, f"[FAKE-{rule}]")


def plan_fix(root: Path, finding: dict, kind: str) -> FixPlan:
    plan = FixPlan()
    rel = finding["file"]
    path = _inside(root, rel)

    if kind == "ignore":
        plan.file_ops.append(_append(".shieldignore", f"{finding['id']}  # {finding['rule']} {rel}", "add finding id to .shieldignore"))
        return plan
    if kind == "gitignore_add":
        entry = ".env" if finding["rule"] == "GITIGNORE_MISSING_ENV" else rel
        plan.file_ops.append(_append(".gitignore", entry, f"add {entry} to .gitignore"))
        return plan
    if kind == "untrack_file":
        plan.file_ops.append(FileOp("git_rm_cached", rel, summary=f"git rm --cached {rel} (file stays on disk)"))
        plan.file_ops.append(_append(".gitignore", rel, f"add {rel} to .gitignore"))
        plan.notes.append("Rotate this secret now: it is already in git history.")
        return plan

    lines = path.read_text(errors="ignore").splitlines() if path.is_file() and kind not in {"redact_image", "strip_exif"} else []

    if kind == "move_to_env":
        line_text = lines[finding["line"] - 1]
        m = re.search(r"([:=]\s*)([\"'])([^\"']+)\2", line_text)
        if not m:
            plan.notes.append("Could not locate a quoted literal on this line; move it manually.")
            return plan
        name, value = _env_name(line_text, finding), m.group(3)
        lookup = {
            ".py": f'os.environ["{name}"]',
            ".js": f"process.env.{name}", ".ts": f"process.env.{name}", ".mjs": f"process.env.{name}", ".cjs": f"process.env.{name}",
            ".go": f'os.Getenv("{name}")', ".java": f'System.getenv("{name}")', ".rb": f'ENV["{name}"]',
            ".yml": "${" + name + "}", ".yaml": "${" + name + "}",
        }.get(path.suffix)
        if not lookup:
            plan.notes.append(f"move_to_env does not support {path.suffix or 'this file type'}")
            return plan
        new_line = line_text[: m.start()] + m.group(1) + lookup + line_text[m.end():]
        plan.edits.append(_line_edit(rel, finding["line"], line_text, new_line))
        if path.suffix == ".py" and not any(re.match(r"\s*import os\b", ln) for ln in lines):
            plan.edits.append(TextEdit(rel, 1, 0, 1, 0, "import os\n"))
        plan.file_ops.append(_append(".env", f"{name}={value}", f"add {name}=<secret> to .env"))
        plan.file_ops.append(_append(".env.example", f"{name}=", f"add {name}= to .env.example"))
        plan.file_ops.append(_append(".gitignore", ".env", "make sure .env is git-ignored"))
        plan.notes.append("Rotate this key now: a committed key is compromised even after this change.")
        if finding.get("in_history"):
            plan.notes.append("Also in git history: rotate first, then purge with git filter-repo --replace-text <file>.")
        return plan

    if kind in {"redact_pii", "fake_pii"}:
        line = lines[finding["line"] - 1]
        value = next((e.value for e in detect(line) if e.type == finding["rule"]), None)
        if value is None:
            plan.notes.append("Could not locate the value on this line (file changed since scan?). Re-scan.")
            return plan
        new_value = f"[REDACTED-{finding['rule']}]" if kind == "redact_pii" else _fake(finding["rule"])
        plan.edits.append(_line_edit(rel, finding["line"], line, line.replace(value, new_value)))
        return plan

    if kind in {"redact_image", "strip_exif"}:
        entities = []
        if kind == "redact_image":
            from shield.redact.image import ocr_words

            text = " ".join(w for w, _ in ocr_words(path))
            entities = [Entity(e.type, e.value, e.start, e.end, e.score) for e in detect(text)]
        with tempfile.TemporaryDirectory() as tmp:  # never write scratch files into the workspace
            out = Path(tmp) / f"out{path.suffix}"
            redact_image(path, entities, out, aggressive=(kind == "redact_image"))
            data = out.read_bytes()
        what = f"opaque fill over {len(entities)} OCR value(s) + metadata stripped" if kind == "redact_image" else "metadata stripped"
        plan.file_ops.append(FileOp("replace_binary", rel, base64.b64encode(data).decode(), f"rewrite {rel}: {what}"))
        plan.notes.append("The original is copied to .shield/backup/ (git-ignored) before replacement.")
        return plan

    if kind == "hash_pdq":
        import cv2

        from shield import pdq

        img = cv2.imread(str(path))
        if img is None:
            plan.notes.append("Cannot decode this image for PDQ.")
            return plan
        rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        regions = pdq.pdq_regions(rgb)
        plan.file_ops.append(FileOp("bank_add", rel, None, f"add {len(regions)} PDQ region hashes (x8 dihedral) of {rel} to .shield/bank.json"))
        plan.notes.append("PDQ is for near-duplicate / leak monitoring. It does not redact or sanitize the image.")
        plan.notes.extend(f"PDQ {r.region}: {r.hex} (quality {r.quality})" for r in regions)
        return plan

    if kind == "yaml_safe_load":
        for i, ln in enumerate(lines, 1):
            if "yaml.load(" in ln:
                new = re.sub(r",\s*Loader\s*=\s*[\w.]+", "", ln.replace("yaml.load(", "yaml.safe_load("))
                plan.edits.append(_line_edit(rel, i, ln, new))
        return plan

    if kind == "requests_verify":
        line = lines[finding["line"] - 1]
        new = re.sub(r",\s*verify\s*=\s*False|verify\s*=\s*False\s*,?\s*", "", line)
        plan.edits.append(_line_edit(rel, finding["line"], line, new))
        return plan

    plan.notes.append(f"Fix kind not implemented: {kind}")
    return plan


def _inside(root: Path, rel: str) -> Path:
    root = root.resolve()
    p = (root / rel).resolve()
    if p != root and root not in p.parents:
        raise ValueError(f"path escapes the scan root: {rel}")
    return p


def apply_edits(text: str, edits: list[TextEdit]) -> str:
    lines = text.split("\n")
    starts = [0]
    for ln in lines:
        starts.append(starts[-1] + len(ln) + 1)

    def offset(line: int, col: int) -> int:
        line = max(1, min(line, len(lines)))
        return starts[line - 1] + min(col, len(lines[line - 1]))

    for e in sorted(edits, key=lambda e: (e.line, e.col), reverse=True):
        a, b = offset(e.line, e.col), offset(e.end_line, e.end_col)
        text = text[:a] + e.new_text + text[b:]
    return text


def apply_plan(plan: FixPlan, root: Path) -> None:
    root = root.resolve()
    by_file: dict[str, list[TextEdit]] = {}
    for e in plan.edits:
        by_file.setdefault(e.file, []).append(e)
    for rel, edits in by_file.items():
        p = _inside(root, rel)
        p.write_text(apply_edits(p.read_text(), edits))

    for op in plan.file_ops:
        p = _inside(root, op.file)
        if op.op == "append_line":
            line = base64.b64decode(op.content_b64 or "").decode()
            existing = p.read_text() if p.exists() else ""
            if line in existing.splitlines():
                continue
            sep = "" if not existing or existing.endswith("\n") else "\n"
            p.write_text(existing + sep + line + "\n")
        elif op.op == "replace_binary":
            original = p.read_bytes()
            backup = _inside(root, ".shield/backup")
            backup.mkdir(parents=True, exist_ok=True, mode=0o700)
            (backup / f"{hashlib.sha256(original).hexdigest()}{p.suffix}").write_bytes(original)
            gi = root / ".gitignore"
            if ".shield/backup/" not in (gi.read_text() if gi.exists() else ""):
                apply_plan(FixPlan(file_ops=[_append(".gitignore", ".shield/backup/", "")]), root)
            p.write_bytes(base64.b64decode(op.content_b64 or ""))
        elif op.op == "bank_add":
            from .media import bank_add

            bank_add(p, f"repo:{op.file}", root)
        elif op.op == "git_rm_cached":
            subprocess.run(["git", "rm", "--cached", "--quiet", "--", str(p)], cwd=root, check=False)
