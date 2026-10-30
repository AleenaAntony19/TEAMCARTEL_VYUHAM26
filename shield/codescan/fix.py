from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from shield.detect import verhoeff_check_digit
from shield.redact.image import redact_image
from shield.models import Entity


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
    op: str
    file: str
    content_b64: str | None = None


@dataclass
class FixPlan:
    edits: list[TextEdit] = field(default_factory=list)
    file_ops: list[FileOp] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _env_name(finding: dict) -> str:
    stem = Path(finding["file"]).stem.upper().replace("-", "_")
    return re.sub(r"[^A-Z0-9_]", "_", stem) or "SECRET"


def plan_fix(root: Path, finding: dict, kind: str) -> FixPlan:
    plan = FixPlan()
    rel = finding["file"]
    path = root / rel

    if kind == "ignore":
        plan.file_ops.append(FileOp("append", ".shieldignore", base64.b64encode(f"{finding['id']}  # {finding['rule']} {rel}\n".encode()).decode()))
        return plan

    if kind == "gitignore_add":
        plan.file_ops.append(FileOp("append", ".gitignore", base64.b64encode(f"{rel}\n".encode()).decode()))
        return plan

    if kind == "untrack_file":
        plan.file_ops.append(FileOp("git_rm_cached", rel))
        plan.file_ops.append(FileOp("append", ".gitignore", base64.b64encode(f"{rel}\n".encode()).decode()))
        plan.notes.append("Rotate this secret now.")
        return plan

    if kind == "move_to_env":
        name = _env_name(finding)
        line_text = path.read_text(errors="ignore").splitlines()[finding["line"] - 1]
        m = re.search(r"=\s*[\"']([^\"']+)[\"']", line_text)
        if not m:
            plan.notes.append("Could not locate the literal to move.")
            return plan
        value = m.group(1)
        if path.suffix == ".py":
            new_line = re.sub(r"=\s*[\"'][^\"']+[\"']", f'= os.environ["{name}"]', line_text)
            if "import os" not in path.read_text(errors="ignore"):
                plan.edits.append(TextEdit(rel, 1, 0, 1, 0, "import os\n"))
        elif path.suffix in {".js", ".ts", ".mjs", ".cjs"}:
            new_line = re.sub(r"=\s*[\"'][^\"']+[\"']", f"= process.env.{name}", line_text)
        elif path.suffix == ".go":
            new_line = re.sub(r"=\s*[\"'][^\"']+[\"']", f'= os.Getenv("{name}")', line_text)
        else:
            plan.notes.append(f"Unsupported language for move_to_env: {path.suffix}")
            return plan
        plan.edits.append(TextEdit(rel, finding["line"], 0, finding["line"], len(line_text), new_line))
        plan.file_ops.append(FileOp("append", ".env", base64.b64encode(f"{name}={value}\n".encode()).decode()))
        plan.file_ops.append(FileOp("append", ".env.example", base64.b64encode(f"{name}=\n".encode()).decode()))
        plan.file_ops.append(FileOp("append", ".gitignore", base64.b64encode(b".env\n").decode()))
        plan.notes.append("Rotate this key now. A committed key is compromised.")
        if finding.get("in_history"):
            plan.notes.append("Also in git history: rotate first, then run git filter-repo --replace-text <file>.")
        return plan

    if kind in {"redact_pii", "fake_pii"}:
        text = path.read_text(errors="ignore")
        lines = text.splitlines()
        line = lines[finding["line"] - 1]
        value = None
        from shield.detect import detect

        for ent in detect(line):
            if ent.type == finding["rule"]:
                value = ent.value
                break
        if value is None:
            plan.notes.append("Could not locate value on line.")
            return plan
        if kind == "redact_pii":
            new_value = f"[REDACTED-{finding['rule']}]"
        else:
            if finding["rule"] == "IN_AADHAAR":
                base_num = "9999 9999 999"
                check = verhoeff_check_digit(base_num.replace(" ", ""))
                new_value = f"{base_num}{check}"
            elif finding["rule"] == "IN_PAN":
                new_value = "AAAPZ1234A"
            elif finding["rule"] == "MOBILE_IN":
                new_value = "+91 90000 00000"
            elif finding["rule"] == "EMAIL_ADDRESS":
                new_value = "user1@example.com"
            else:
                new_value = f"[FAKE-{finding['rule']}]"
        new_line = line.replace(value, new_value)
        plan.edits.append(TextEdit(rel, finding["line"], 0, finding["line"], len(line), new_line))
        return plan

    if kind in {"redact_image", "strip_exif"}:
        src = path
        out = path.with_suffix(path.suffix + ".sanitized" + path.suffix)
        entities = []
        if kind == "redact_image":
            from shield.redact.image import ocr_words
            from shield.detect import detect

            text = " ".join(w for w, _ in ocr_words(src))
            entities = [Entity(e.type, e.value, e.start, e.end, e.score) for e in detect(text)]
        redact_image(src, entities, out, aggressive=(kind == "redact_image"))
        plan.file_ops.append(FileOp("replace_binary", rel, base64.b64encode(out.read_bytes()).decode()))
        plan.notes.append("Original backed up under .shield/backup/")
        out.unlink(missing_ok=True)
        return plan

    if kind == "yaml_safe_load":
        text = path.read_text(errors="ignore")
        new = text.replace("yaml.load(", "yaml.safe_load(")
        plan.edits.append(TextEdit(rel, 1, 0, len(text.splitlines()), 0, new))
        return plan

    if kind == "requests_verify":
        lines = path.read_text(errors="ignore").splitlines()
        line = lines[finding["line"] - 1]
        new_line = line.replace(", verify=False", "").replace("verify=False,", "").replace("verify=False", "")
        plan.edits.append(TextEdit(rel, finding["line"], 0, finding["line"], len(line), new_line))
        return plan

    plan.notes.append(f"Fix kind not implemented: {kind}")
    return plan


def apply_plan(plan: FixPlan):
    for op in plan.file_ops:
        if op.op == "append":
            data = base64.b64decode(op.content_b64 or "")
            path = Path(op.file)
            path.parent.mkdir(parents=True, exist_ok=True)
            existing = path.read_text() if path.exists() else ""
            path.write_text(existing + data.decode())
        elif op.op == "replace_binary":
            data = base64.b64decode(op.content_b64 or "")
            backup = Path(".shield/backup")
            backup.mkdir(parents=True, exist_ok=True)
            sha = hashlib.sha256(data).hexdigest()
            (backup / f"{sha}{Path(op.file).suffix}").write_bytes(data)
            Path(op.file).write_bytes(data)
        elif op.op == "git_rm_cached":
            import subprocess
            subprocess.run(["git", "rm", "--cached", op.file], check=False)
    for edit in plan.edits:
        path = Path(edit.file)
        lines = path.read_text().splitlines()
        if edit.line == 1 and edit.end_line == len(lines) and edit.col == 0 and edit.end_col == 0:
            path.write_text(edit.new_text)
            continue
        if 1 <= edit.line <= len(lines):
            lines[edit.line - 1] = edit.new_text
            path.write_text("\n".join(lines) + "\n")

