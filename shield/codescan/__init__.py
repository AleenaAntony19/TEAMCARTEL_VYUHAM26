from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator, Literal

FIX_KINDS = [
    "move_to_env",
    "gitignore_add",
    "untrack_file",
    "redact_pii",
    "fake_pii",
    "redact_image",
    "strip_exif",
    "yaml_safe_load",
    "requests_verify",
    "ignore",
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".next"}


@dataclass
class Finding:
    id: str
    engine: str
    rule: str
    severity: str
    file: str
    line: int
    col: int
    end_line: int
    end_col: int
    message: str
    masked: str
    fixes: list[str] = field(default_factory=list)
    in_history: bool = False

    def to_dict(self):
        return asdict(self)


def mask(value: str, rule: str) -> str:
    if rule == "IN_AADHAAR":
        digits = "".join(c for c in value if c.isdigit())
        return f"XXXX XXXX {digits[-4:]}" if len(digits) >= 4 else "•••"
    if len(value) <= 8:
        return "•••"
    if any(c.isdigit() for c in value) and len(value) > 12:
        return value[:4] + "…" + value[-2:]
    return value[:4] + "…" + value[-2:]


def fingerprint(rule: str, relpath: str, line_text: str, value: str) -> str:
    safe = line_text.replace(value, "«V»")
    raw = f"{rule}|{relpath}|{safe}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def walk(root: Path, only: list[Path] | None = None) -> Iterator[tuple[Path, Literal["text", "image", "binary"]]]:
    root = root.resolve()
    if only:
        paths = [root / p if not p.is_absolute() else p for p in only]
    else:
        try:
            out = subprocess.run(
                ["git", "ls-files", "-co", "--exclude-standard"],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if out.returncode == 0 and out.stdout.strip():
                paths = [root / line for line in out.stdout.splitlines() if line.strip()]
            else:
                raise RuntimeError
        except Exception:
            paths = []
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for name in filenames:
                    paths.append(Path(dirpath) / name)

    for path in paths:
        if not path.exists() or path.is_dir():
            continue
        suffix = path.suffix.lower()
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if suffix in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tiff"}:
            if size <= 10 * 1024 * 1024:
                yield path, "image"
            continue
        if size > 2 * 1024 * 1024 or suffix in {".min.js", ".lock"}:
            continue
        try:
            head = path.read_bytes()[:8192]
        except OSError:
            continue
        if b"\x00" in head:
            yield path, "binary"
        else:
            yield path, "text"


def load_ignores(root: Path) -> set[str]:
    path = root / ".shieldignore"
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.add(line)
    return out


def scan(root: str | Path, only=None, engines=None, history=False) -> dict:
    root = Path(root).resolve()
    engines = engines or ["secrets", "pii", "sast", "config", "media"]
    files = list(walk(root, only))
    text_files = [p for p, k in files if k == "text"]
    image_files = [p for p, k in files if k == "image"]

    findings: list[Finding] = []
    stats = {"files": len(files), "skipped": 0, "ms": 0, "engines": {}}

    def run(name, fn):
        try:
            findings.extend(fn())
            stats["engines"][name] = "ok"
        except Exception as exc:
            stats["engines"][name] = f"error: {exc}"

    if "secrets" in engines:
        from .secrets import scan_history, scan_secrets

        run("secrets", lambda: scan_secrets(text_files, root))
        if history:
            run("secrets_history", lambda: scan_history(root))
    if "pii" in engines:
        from .pii import scan_pii

        run("pii", lambda: scan_pii(text_files, root, findings))
    if "sast" in engines:
        from .sast import scan_sast

        run("sast", lambda: scan_sast(root))
    if "config" in engines:
        from .config import scan_config

        run("config", lambda: scan_config(root))
    if "media" in engines:
        from .media import scan_media

        run("media", lambda: scan_media(image_files, root))

    ignore = load_ignores(root)
    findings = [f for f in findings if f.id not in ignore]

    dedup = {}
    for f in findings:
        dedup[(f.file, f.line, f.rule)] = f
    findings = sorted(dedup.values(), key=lambda f: (f.file, f.line, f.rule))

    return {
        "version": 1,
        "root": str(root),
        "findings": [f.to_dict() for f in findings],
        "stats": stats,
    }

