from __future__ import annotations

import fnmatch
import hashlib
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
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
    "hash_pdq",
    "ignore",
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".next", ".shield"}  # .shield holds backups of originals


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
    confidence: float = 0.0  # 0 = engine default, filled in scan()
    evidence: str = ""  # masked context, never the raw value
    recommendation: str = ""
    bbox: list[int] | None = None  # image findings: [x, y, w, h] in pixels

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


def evidence(line: str, value: str, rule: str) -> str:
    """Context with the finding's value *and* any other secret/PII on the line masked."""
    from shield.detect import detect

    from .secrets import EXTRA_RULES

    text = line.replace(value, mask(value, rule)) if value else line
    for pat in EXTRA_RULES.values():
        text = pat.sub(lambda m: mask(m.group(0), "secret"), text)
    for e in detect(text):
        if e.type not in {"ORG", "DATE_TIME", "PERSON"}:
            text = text.replace(e.value, mask(e.value, e.type))
    return " ".join(text.split())[:200]


_ERRORS: list[dict] = []
_ERR_LOCK = threading.Lock()


def record_error(path: Path | str, engine: str, exc: BaseException) -> None:
    """Per-file failures are reported in stats.errors instead of being silently skipped."""
    with _ERR_LOCK:
        _ERRORS.append({"file": str(path), "engine": engine, "error": type(exc).__name__})


def fingerprint(rule: str, relpath: str, line_text: str, value: str) -> str:
    safe = line_text.replace(value, "«V»")
    raw = f"{rule}|{relpath}|{safe}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


DOC_SUFFIXES = {".pdf", ".docx", ".xlsx"}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tiff"}


def walk(
    root: Path, only: list[Path] | None = None, exclude: tuple[str, ...] = (), max_file_mb: float = 2
) -> Iterator[tuple[Path, Literal["text", "image", "document", "binary"]]]:
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

    max_text = int(max_file_mb * 1024 * 1024)
    for path in paths:
        try:
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            continue  # outside the workspace (symlink or absolute --files path)
        if SKIP_DIRS.intersection(rel.split("/")[:-1]) or any(fnmatch.fnmatch(rel, pat) for pat in exclude):
            continue
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        try:
            size = path.stat().st_size
        except OSError as exc:
            record_error(path, "walk", exc)
            continue
        if suffix in IMAGE_SUFFIXES:
            if size <= 5 * max_text:
                yield path, "image"
            continue
        if suffix in DOC_SUFFIXES:
            if size <= 10 * max_text:
                yield path, "document"
            continue
        if size > max_text or path.name.endswith((".min.js", ".lock")) or path.name == "package-lock.json":
            continue
        try:
            with path.open("rb") as fh:
                head = fh.read(8192)
        except OSError as exc:
            record_error(path, "walk", exc)
            continue
        yield path, ("binary" if b"\x00" in head else "text")


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


RECOMMEND = {
    "secrets": "Move the value to an environment variable or secret manager, then rotate it: a committed secret is compromised.",
    "pii": "Replace with a synthetic test value or a token; real personal data should not live in source or fixtures.",
    "sast": "Fix the unsafe call (see the rule docs); add a test that covers the safe behaviour.",
    "config": "Stop tracking the file and add it to .gitignore; rotate anything it contained.",
    "media": "Remove the sensitive region with an opaque fill and strip metadata; a PDQ fingerprint does not sanitize an image.",
    "document": "Sanitize the document with Shield·Scout (web) so text, metadata and hidden layers are removed, then replace the file.",
}
DEFAULT_CONFIDENCE = {"secrets": 0.9, "pii": 0.85, "sast": 0.7, "config": 0.95, "media": 0.6, "document": 0.85}
ALL_ENGINES = ["secrets", "pii", "sast", "config", "media", "document"]


def scan(
    root: str | Path,
    only=None,
    engines=None,
    history=False,
    workers: int = 4,
    timeout: float = 300,
    ocr: bool = True,
    max_file_mb: float = 2,
    exclude: tuple[str, ...] = (),
) -> dict:
    """Run independent engines in parallel (bounded by `workers`); each engine gets the remaining time budget."""
    started = time.monotonic()
    root = Path(root).resolve()
    engines = engines or ALL_ENGINES
    with _ERR_LOCK:
        _ERRORS.clear()
    files = list(walk(root, only, tuple(exclude), max_file_mb))
    text_files = [p for p, k in files if k == "text"]
    image_files = [p for p, k in files if k == "image"]
    doc_files = [p for p, k in files if k == "document"]

    findings: list[Finding] = []
    stats: dict = {"files": len(files), "skipped": 0, "ms": 0, "engines": {}, "errors": [], "ocr": "disabled"}

    jobs = {}
    if "secrets" in engines:
        from .secrets import scan_history, scan_secrets

        jobs["secrets"] = lambda: scan_secrets(text_files, root)
        if history:
            jobs["secrets_history"] = lambda: scan_history(root)
    if "pii" in engines:
        from .pii import scan_pii

        jobs["pii"] = lambda: scan_pii(text_files, root)
    if "sast" in engines and not only:
        from .sast import scan_sast

        jobs["sast"] = lambda: scan_sast(root, tuple(exclude))
    if "config" in engines and not only:
        from .config import scan_config

        jobs["config"] = lambda: scan_config(root)
    if "media" in engines and image_files:
        from .media import scan_media

        jobs["media"] = lambda: scan_media(image_files, root, ocr=ocr, stats=stats)
    if "document" in engines and doc_files:
        from .docs import scan_documents

        jobs["document"] = lambda: scan_documents(doc_files, root, ocr=ocr)
    if ocr and (image_files or doc_files):
        from shutil import which

        stats["ocr"] = "ok" if which("tesseract") else "unavailable: tesseract not found"

    pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="codescan")
    futures = {pool.submit(fn): name for name, fn in jobs.items()}
    done, pending = wait(futures, timeout=max(1.0, timeout - (time.monotonic() - started)))
    for fut in done:
        name = futures[fut]
        try:
            findings.extend(fut.result())
            stats["engines"][name] = "ok"
        except Exception as exc:
            stats["engines"][name] = f"error: {type(exc).__name__}"
    for fut in pending:
        stats["engines"][futures[fut]] = "timeout"
    pool.shutdown(wait=False, cancel_futures=True)
    stats["timed_out"] = bool(pending)

    ignore = load_ignores(root)
    findings = [f for f in findings if f.id not in ignore]

    dedup: dict = {}
    for f in findings:
        # image/document findings all sit at line 0: the box tells them apart
        key = (f.file, f.line, f.col, f.rule, tuple(f.bbox or ()), f.id if not f.line else "")
        if key not in dedup or ORDER.get(f.severity, 9) < ORDER.get(dedup[key].severity, 9):
            dedup[key] = f
    findings = sorted(dedup.values(), key=lambda f: (ORDER.get(f.severity, 9), f.file, f.line, f.rule))
    for f in findings:
        f.confidence = f.confidence or DEFAULT_CONFIDENCE.get(f.engine, 0.5)
        f.recommendation = f.recommendation or RECOMMEND.get(f.engine, "")

    with _ERR_LOCK:
        stats["errors"] = list(_ERRORS)[:200]
    stats["ms"] = int((time.monotonic() - started) * 1000)
    return {
        "version": 2,
        "root": str(root),
        "findings": [f.to_dict() for f in findings],
        "stats": stats,
    }


ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
