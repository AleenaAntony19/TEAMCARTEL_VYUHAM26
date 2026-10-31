"""Shield·Scout HTTP API (FastAPI). Run: python -m shield.api  (binds 127.0.0.1:8000 by default).

Development model: single local user, no accounts. Set SHIELD_API_TOKEN to require
`Authorization: Bearer <token>` on every /api route; see SECURITY.md before exposing it on a network.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import logging
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .. import llm, pdq, uploads, verify
from ..detect import UNVERIFIED, detect, labelled_ids, replacement, severity
from ..ledger import Ledger
from ..models import BASE, SFACE, YUNET, Entity
from ..redact import redact, redact_text
from ..review import mask_value

log = logging.getLogger("shield.api")

WORK_ROOT = Path(os.getenv("SHIELD_WORK_DIR") or Path(tempfile.gettempdir()) / "shield-work")
JOB_TTL = int(os.getenv("SHIELD_JOB_TTL_SECONDS", "3600"))
MAX_JOBS = int(os.getenv("SHIELD_MAX_JOBS", "2"))
MAX_PENDING = int(os.getenv("SHIELD_MAX_PENDING", "16"))
CRAWL_MAX_PAGES = int(os.getenv("SHIELD_CRAWL_MAX_PAGES", "100"))
CRAWL_MAX_DEPTH = int(os.getenv("SHIELD_CRAWL_MAX_DEPTH", "3"))
CRAWL_RPS = float(os.getenv("SHIELD_CRAWL_RPS", "1"))
CRAWL_TIMEOUT = float(os.getenv("SHIELD_CRAWL_TIMEOUT", "300"))
REGISTRY = Path(os.getenv("SHIELD_REGISTRY") or BASE / "registry/seeds.yaml")
API_TOKEN = os.getenv("SHIELD_API_TOKEN", "")


def is_public_demo() -> bool:
    return os.getenv("SHIELD_PUBLIC_DEMO", "0").lower() in ("1", "true", "yes") or API_TOKEN in ("public", "demo")
LOCAL_ONLY = os.getenv("SHIELD_LOCAL_ONLY") == "1"
FACE_REGIONS = os.getenv("SHIELD_FACE_REGIONS", "1") == "1"

SEVERITY = {
    "IN_AADHAAR": "critical", "CREDIT_CARD": "critical", "IN_BANK_ACCOUNT": "critical",
    "IN_PAN": "high", "IN_PASSPORT": "high", "IN_UPI": "high", "IN_IFSC": "medium",
    "MOBILE_IN": "medium", "EMAIL_ADDRESS": "medium", "IN_GSTIN": "medium",
    "API_KEY": "critical", "PERSON": "low", "ORG": "low", "DATE_TIME": "low", "FACE": "high", "GEO_COORDINATES": "high",
}
RECOMMEND = {
    "API_KEY": "Rotate this key now, then remove it: anyone who has seen this file can use it.",
    "IN_AADHAAR": "Remove or replace; Aadhaar must not be shared outside authorised KYC flows (masked form keeps last 4 at most).",
    "CREDIT_CARD": "Remove; card numbers must not be stored or shared (PCI-DSS).",
    "IN_BANK_ACCOUNT": "Remove or tokenise the account number.",
    "IN_PAN": "Replace with a token unless the recipient needs it for tax purposes.",
    "FACE": "Remove the photo region (opaque fill) unless the person consented to sharing.",
    "GEO_COORDINATES": "Remove or coarsen (2 decimals ≈ 1 km); precise coordinates reveal where someone lives or works.",
}
FILE_ACTIONS = {".pdf": ["remove"], ".png": ["remove"], ".jpg": ["remove"], ".jpeg": ["remove"]}  # opaque fill only
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ---------- job model ----------
@dataclass
class Stage:
    name: str
    status: str = "pending"  # pending | running | done | failed | skipped | cancelled
    detail: str = ""
    ms: int = 0


@dataclass
class Job:
    id: str
    kind: str  # analysis | discovery
    created: float
    workdir: Path
    status: str = "queued"  # queued | running | ready | failed | cancelled
    stages: list[Stage] = field(default_factory=list)
    display_name: str = ""
    suffix: str = ""
    findings: list[dict] = field(default_factory=list)
    entities: dict[str, Entity] = field(default_factory=dict)  # finding id -> entity (never serialised)
    redaction: dict | None = None
    agent_run: dict | None = None  # binding LLM swarm run: status, events, result
    redact_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)  # a redact rewrites out/: two at once corrupt each other
    summary: dict | None = None  # layers inspected and the document severity, for the case header
    discovery: dict | None = None
    error: str = ""
    cancel: threading.Event = field(default_factory=threading.Event)
    state: str = "new"
    raw: tuple | None = None  # (all detected entities, layer texts) for the deliberation stream; never serialised
    ledger: Ledger = field(default_factory=Ledger)

    def public(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "status": self.status, "created": self.created, "state": self.state,
            "display_name": self.display_name, "input_type": self.suffix.lstrip(".") or "text",
            "stages": [asdict(s) for s in self.stages], "findings": self.findings,
            "redaction": self.redaction, "discovery": self.discovery, "error": self.error, "summary": self.summary,
            "agent_run": {k: v for k, v in self.agent_run.items() if k != "events"} | {"event_count": len(self.agent_run["events"])} if self.agent_run else None,
        }


class Cancelled(Exception):
    pass


# Allowed graph transitions for an analysis job. red_team_attack -> object_redact is the single
# aggressive retry; consensus_ledger -> object_redact lets the user redact again with new selections.
GRAPH = {
    "new": {"intake"},
    "intake": {"deliberate"},
    "deliberate": {"object_redact"},
    "object_redact": {"red_team_attack"},
    "red_team_attack": {"object_redact", "consensus_ledger"},
    "consensus_ledger": {"object_redact"},
}


def _advance(job: "Job", state: str, details: dict) -> None:
    """Move the job along GRAPH and chain a ledger block (types/counts/hashes only; Ledger rejects raw PII)."""
    if state not in GRAPH.get(job.state, set()):
        raise HTTPException(409, f"illegal transition {job.state} -> {state}")
    job.state = state
    job.ledger.append(f"graph:{state}", state.upper(), details)


JOBS: dict[str, Job] = {}
LOCK = threading.Lock()
POOL = ThreadPoolExecutor(max_workers=MAX_JOBS, thread_name_prefix="shield-job")
SWARM_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="shield-swarm")
LLM_CFG = llm.from_env()
REFERENCES = pdq.HashBank()  # PDQ hashes of user-authorised reference images; pixels are never kept
REF_LABELS: list[dict] = []
ENROLLED: list = []  # consented face vectors (int8 SFace), memory only; cleared with the session


def _workdir() -> Path:
    WORK_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    return Path(tempfile.mkdtemp(prefix="job-", dir=WORK_ROOT))  # mkdtemp is 0700


def _drop(job: Job) -> None:
    job.cancel.set()
    with job.redact_lock:  # never delete files under a running redaction
        shutil.rmtree(job.workdir, ignore_errors=True)


def sweep() -> None:
    now = time.time()
    with LOCK:
        expired = [j for j in JOBS.values() if now - j.created > JOB_TTL and j.status not in {"queued", "running"} and (j.agent_run or {}).get("status") != "running"]
        for j in expired:
            JOBS.pop(j.id, None)
    for j in expired:
        _drop(j)
    # orphans from a previous process (crash/restart) are not in JOBS; remove them once they pass the TTL
    known = {j.workdir for j in JOBS.values()}
    if WORK_ROOT.exists():
        for d in WORK_ROOT.glob("job-*"):
            try:
                if d not in known and now - d.stat().st_mtime > JOB_TTL:
                    shutil.rmtree(d, ignore_errors=True)
            except OSError:
                pass


def _get(job_id: str) -> Job:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "job not found or expired")
    return job


def _run_stage(job: Job, name: str, fn):
    if job.cancel.is_set():
        raise Cancelled()
    st = Stage(name, "running")
    job.stages.append(st)
    t = time.monotonic()
    try:
        out = fn()
        st.status = "done"
        return out
    except Cancelled:
        st.status = "cancelled"
        raise
    except Exception as exc:
        st.status, st.detail = "failed", type(exc).__name__  # exception text may contain document content
        raise
    finally:
        st.ms = int((time.monotonic() - t) * 1000)
        log.info("job=%s stage=%s status=%s ms=%s", job.id, name, st.status, st.ms)


def _submit(job: Job, fn) -> None:
    with LOCK:
        active = sum(j.status in {"queued", "running"} for j in JOBS.values())
        if active >= MAX_PENDING:
            raise HTTPException(429, "too many jobs in progress; try again shortly")
        JOBS[job.id] = job

    def wrapper():
        job.status = "running"
        try:
            fn(job)
            job.status = "ready"
        except Cancelled:
            job.status = "cancelled"
        except Exception as exc:
            job.status, job.error = "failed", type(exc).__name__
            log.warning("job=%s failed: %s", job.id, type(exc).__name__)

    POOL.submit(wrapper)


# ---------- analysis ----------
def _evidence(text: str, start: int, end: int, spans: list[tuple[int, int]]) -> str:
    """Context around a finding; every detected span in the window is masked char-by-char (keeps last 4),
    so a value cut by the window edge is still masked."""
    lo, hi = max(0, start - 40), min(len(text), end + 40)
    chars = list(text[lo:hi])
    for s, e in spans:
        keep_from = e - 4 if e - s > 8 else e
        for i in range(max(s, lo), min(e, hi)):
            if i < keep_from and chars[i - lo].isalnum():
                chars[i - lo] = "•"
    return " ".join("".join(chars).split())


NOT_PERSONAL = {"ORG", "LOCATION", "DATE_TIME"}
CRITICAL_IN_IMAGE = {"IN_AADHAAR", "CREDIT_CARD", "IN_BANK_ACCOUNT", "API_KEY"}


def _types_in_image(img) -> list[str]:
    """Sensitive data printed inside an embedded image, by type only: a scanned ID has no text layer for the detectors."""
    import pytesseract
    from PIL import Image

    text = pytesseract.image_to_string(Image.fromarray(img[:, :, ::-1]), config="--psm 6")
    found = detect(text, "ocr") + _extra_entities({"ocr": text}, [])
    return sorted({e.type for e in found if e.type not in NOT_PERSONAL})


def _face_entities(src: Path) -> list[tuple[Entity, str, list[str]]]:
    """Embedded images to remove: face *regions* (YuNet detection, no recognition) and images with sensitive text."""
    from .. import face
    from ..profile import extract_images

    out = []
    plain_image = src.suffix.lower() in {".png", ".jpg", ".jpeg"}  # these already went through OCR as their own layer
    for name, img, bbox in extract_images(src):
        rows = face.detect_faces(img)
        kinds = [] if plain_image else _types_in_image(img)
        if not len(rows) and not kinds:
            continue
        if src.suffix.lower() == ".pdf" and bbox:
            x0, y0, x1, y1, pno = bbox  # remove the whole placed image: pixel->page scaling is not tracked
            out.append((Entity("FACE", "", 0, 0, 0.9, f"bbox:{x0},{y0},{x1},{y1}@{pno}"), f"page {pno + 1}, image {name}", kinds))
        elif plain_image:
            for r in rows:
                x, y, w, h = (int(v) for v in r[:4])
                out.append((Entity("FACE", "", 0, 0, float(r[-1]), f"bbox:{x},{y},{x + w},{y + h}"), f"pixels {x},{y} {w}x{h}", []))
        else:
            out.append((Entity("FACE", "", 0, 0, 0.9, "media"), f"embedded image {name}", kinds))
    return out


def _extra_entities(layers: dict[str, str], entities: list[Entity]) -> list[Entity]:
    """What the strict detectors reject but a reviewer must still see: labelled IDs that fail their checks, and API keys."""
    from ..codescan.secrets import EXTRA_RULES, is_doc_example

    out: list[Entity] = []
    for layer, text in layers.items():
        found = labelled_ids(text, layer)
        ascii_text = re.sub(r"[^\x00-\x7F]", "X", text)  # OCR misreads a glyph inside keys; 1:1 keeps offsets valid
        for rx in EXTRA_RULES.values():
            found += [Entity("API_KEY", m.group(0), m.start(), m.end(), 0.85, layer) for m in rx.finditer(ascii_text) if not is_doc_example(m.group(0))]
        for e in found:
            taken = [o for o in entities + out if o.layer == layer]
            if not any(o.start < e.end and o.end > e.start for o in taken):
                out.append(e)
    return out


def _analyse(job: Job, src: Path) -> None:
    from ..detect import audit_all_extracted_text
    from ..detector import DetectorAgent
    from ..extractor import ExtractorAgent

    _advance(job, "intake", {"format": job.suffix.lstrip(".") or "txt", "input_sha256": hashlib.sha256(src.read_bytes()).hexdigest()})
    extraction = _run_stage(job, "extractor_agent", lambda: ExtractorAgent().execute(src))
    job.stages[-1].detail = f"{extraction.status} · layers {','.join(extraction.layers)} · {extraction.execution_ms} ms · retries {extraction.retry_count}"
    if extraction.status == "failed":
        job.stages[-1].status = "failed"
        raise RuntimeError("extraction failed")
    layers = extraction.layers
    detection = _run_stage(job, "detector_agent+personas", lambda: DetectorAgent().execute(extraction))
    if detection.status == "failed" and detection.error != "No extractable text available.":
        job.stages[-1].status, job.stages[-1].detail = "failed", "detection validation failed"
        raise RuntimeError("detection failed")
    entities, kept, records = detection.detected, detection.entities, detection.reviews
    job.stages[-1].detail = f"{len(entities)} detected · {len(kept)} kept · {sum(r.verdict == 'dismissed' for r in records)} dismissed · {detection.severity_band}"
    # audit against everything the personas looked at, so a deliberate dismissal is not re-raised as a miss
    extras = _extra_entities(layers, entities)
    audit = _run_stage(job, "validator_audit", lambda: audit_all_extracted_text(layers, entities + extras))
    job.stages[-1].detail = f"{audit.verification_completeness_pct:.1f}% complete · {len(audit.potential_misses)} potential misses in {audit.total_tokens_scanned} tokens"
    job.raw = (entities, layers)
    score, band, _ = severity(kept + extras)
    if any(e.type == "API_KEY" for e in extras):  # a live key is an incident whatever else the file holds
        score, band = max(score, 90), "CRITICAL"
    job.summary = {"layers": list(layers), "severity": band, "score": score}
    rec_by_key = {}
    ri = iter(records)
    for e in entities:  # records align with non-FACE entities in order
        rec_by_key[(e.layer, e.start, e.type)] = next(ri)
    spans = {n: [(e.start, e.end) for e in entities + extras if e.layer == n] for n in layers}
    for m in audit.potential_misses:
        spans.setdefault(m.layer, []).append((m.start, m.end))

    faces: list[tuple[Entity, str, list[str]]] = []
    if FACE_REGIONS and src.suffix.lower() != ".txt":
        try:
            faces = _run_stage(job, "face_regions", lambda: _face_entities(src))
        except Cancelled:
            raise
        except Exception:
            pass  # stage already recorded as failed; analysis continues without face regions
    else:
        job.stages.append(Stage("face_regions", "skipped", "disabled" if not FACE_REGIONS else "text input"))

    findings, ents = [], {}
    salt = job.id.encode()
    for e in kept + extras:
        fid = hashlib.sha256(salt + f"{e.type}|{e.layer}|{e.start}".encode()).hexdigest()[:12]
        rec = rec_by_key.get((e.layer, e.start, e.type))
        actions = FILE_ACTIONS.get(job.suffix, ["token", "mask", "remove"]) if e.layer in {"visible", "ocr"} else ["token", "mask", "remove"]
        findings.append({
            "id": fid, "type": e.type, "severity": "medium" if e.score == UNVERIFIED and e.type != "PERSON" else SEVERITY.get(e.type, "medium"),
            "confidence": round(e.score, 2), "layer": e.layer, "location": {"layer": e.layer, "start": e.start, "end": e.end},
            "masked": mask_value(e.value), "evidence": _evidence(layers.get(e.layer, ""), e.start, e.end, spans.get(e.layer, [])),
            "analyzer": f"pattern:{e.type}", "checks": [asdict(c) for c in rec.checks] if rec else [],
            "recommendation": RECOMMEND.get(e.type, "Review; replace with a token if not needed by the recipient."),
            "actions": actions,
        })
        ents[fid] = e
    for m in audit.potential_misses:  # validator agent: tokens the detectors did not classify
        if m.layer in {"exif", "metadata"} and m.band not in {"CRITICAL", "HIGH"}:
            continue  # XMP schema URLs and the like, not personal data
        fid = hashlib.sha256(salt + f"MISS|{m.layer}|{m.start}".encode()).hexdigest()[:12]
        findings.append({
            "id": fid, "type": "POTENTIAL_LEAK", "severity": {"CRITICAL": "high", "HIGH": "medium"}.get(m.band, "low"),
            "confidence": round(min(m.severity_score / 100, 0.9), 2), "layer": m.layer,
            "location": {"layer": m.layer, "start": m.start, "end": m.end},
            "masked": m.masked_token, "evidence": _evidence(layers.get(m.layer, ""), m.start, m.end, spans.get(m.layer, []) + [(m.start, m.end)]),
            "analyzer": f"validator_audit:{m.suspected_category}", "checks": [],
            "recommendation": "Unclassified high-risk token; review and redact if it is an identifier or secret.",
            "actions": FILE_ACTIONS.get(job.suffix, ["token", "mask", "remove"]) if m.layer in {"visible", "ocr"} else ["token", "mask", "remove"],
        })
        ents[fid] = Entity("POTENTIAL_LEAK", m.token, m.start, m.end, 0.6, m.layer)
    for e, where, kinds in faces:
        fid = hashlib.sha256(salt + e.layer.encode()).hexdigest()[:12]
        supported = e.layer.startswith("bbox:")
        critical = bool(CRITICAL_IN_IMAGE.intersection(kinds))
        findings.append({
            "id": fid, "type": "SENSITIVE_IMAGE" if kinds else "FACE", "severity": "critical" if critical else "high", "confidence": round(e.score, 2), "layer": "image",
            "location": {"layer": "image", "where": where, "bbox": e.layer.split(":", 1)[1] if supported else None},
            "masked": ", ".join(kinds), "evidence": f"{', '.join(kinds)} readable inside an image ({where})" if kinds else f"face region detected ({where}); no identification performed",
            "analyzer": "ocr:embedded_image" if kinds else "yunet:face_detection", "checks": [],
            "recommendation": RECOMMEND["FACE"] if supported else "Automatic removal is not supported for this format; remove the image manually.",
            "actions": ["remove"] if supported else [],
        })
        ents[fid] = e
        if kinds:  # the score above only saw the text layer
            job.summary["severity"], job.summary["score"] = ("CRITICAL", max(job.summary["score"], 85)) if critical else (job.summary["severity"] if job.summary["score"] >= 70 else "HIGH", max(job.summary["score"], 70))
    findings.sort(key=lambda f: (ORDER.get(f["severity"], 9), f["layer"], f["location"].get("start", 0)))
    job.findings, job.entities = findings, ents
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["type"]] = counts.get(f["type"], 0) + 1
    _advance(job, "deliberate", {"kept": counts, "dismissed": sum(r.verdict == "dismissed" for r in records)})


# ---------- request models ----------
class Selection(BaseModel):
    finding_id: str = Field(min_length=1, max_length=64)
    action: Literal["token", "mask", "remove"]


class RedactRequest(BaseModel):
    selections: list[Selection] = Field(min_length=1, max_length=1000)
    dry_run: bool = False


class DiscoveryRequest(BaseModel):
    org: str = Field(min_length=2, max_length=100, pattern=r"^[\w .&'-]+$")
    domain: str = Field(default="", max_length=253, pattern=r"^([a-z0-9-]+\.)*[a-z0-9-]*$")
    entity_types: list[str] = Field(default_factory=list, max_length=20)
    crawl: bool = False
    use_faces: bool = False  # opt-in: also compare crawled faces with the consented enrolment
    job_id: str | None = None  # block this job's detected values from every query
    extra_urls: list[str] = Field(default_factory=list, max_length=20)  # pages to scan once, without following links

    @field_validator("extra_urls")
    @classmethod
    def _http_only(cls, urls: list[str]) -> list[str]:
        if any(not u.startswith(("https://", "http://")) or len(u) > 2000 for u in urls):
            raise ValueError("extra_urls must be http(s) URLs")
        return urls


class LLMSettings(BaseModel):
    provider: Literal["none", "groq", "anthropic"]
    model: str = Field(default="", max_length=100)
    endpoint: str = Field(default="", max_length=300)
    api_key: str = Field(default="", max_length=400)
    timeout: float = Field(default=20, ge=1, le=120)
    retries: int = Field(default=2, ge=0, le=5)

    @field_validator("api_key")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class ExplainRequest(BaseModel):
    job_id: str
    finding_id: str


# ---------- app ----------
app = FastAPI(
    title="Shield·Scout API",
    version="1.0.0",
    description="Upload, analyse, redact and verify documents; discover candidate leaks. See docs/API.md.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in os.getenv("SHIELD_CORS_ORIGINS", "http://localhost:5173").split(",") if o],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Shield-LLM-Provider", "X-Shield-LLM-Key", "X-Shield-LLM-Model"],
)


MAX_REQUEST_BYTES = int(os.getenv("SHIELD_MAX_REQUEST_MB", "50")) * 1024 * 1024


SESSION_COOKIE = "shield_session"


def _session_value() -> str:
    return hashlib.sha256(API_TOKEN.encode()).hexdigest()


def _authorized(request: Request) -> bool:
    return secrets.compare_digest(request.headers.get("authorization", ""), f"Bearer {API_TOKEN}") or secrets.compare_digest(
        request.cookies.get(SESSION_COOKIE, ""), _session_value())


@app.middleware("http")
async def guard(request: Request, call_next):
    if "transfer-encoding" in request.headers:  # no Content-Length means the size limit below cannot apply
        return JSONResponse({"detail": "Content-Length required"}, status_code=411)
    if int(request.headers.get("content-length") or 0) > MAX_REQUEST_BYTES:
        return JSONResponse({"detail": "request too large"}, status_code=413)
    if request.url.path.startswith(("/api/", "/mcp")) and request.method != "OPTIONS":
        if not is_public_demo() and API_TOKEN and request.url.path not in ("/api/auth", "/api/health") and not _authorized(request):  # hosts probe health with no token
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        sweep()
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


class AuthRequest(BaseModel):
    token: str = Field(max_length=500)


@app.post("/api/auth")
def auth(body: AuthRequest, request: Request):
    """Trade the API token for a cookie: browsers cannot add headers to EventSource or download links."""
    if not API_TOKEN or not secrets.compare_digest(body.token, API_TOKEN):
        raise HTTPException(401, "wrong token")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, _session_value(), httponly=True, samesite="strict", secure=request.url.scheme == "https")
    return resp


@app.get("/api/health")
def health():
    import shutil as sh

    return {
        "ok": True,
        "tools": {"tesseract": bool(sh.which("tesseract")), "pdftotext": bool(sh.which("pdftotext"))},
        "face_models": YUNET.exists() and SFACE.exists(),
    }


@app.get("/api/config")
def config():
    from ..textscout import get_provider

    provider = get_provider()
    egress = []
    if not LOCAL_ONLY:
        egress.append("If you choose AI with your own key: masked findings and search snippets go to that provider on your account")
    if LLM_CFG.provider != "none":
        egress.append(f"Discovery AI triage: masked search titles and snippets are sent to {LLM_CFG.provider}")
        egress.append(f"LLM explanations: finding type, rule, severity and masked evidence are sent to {LLM_CFG.endpoint}")
    if provider.name != "offline":
        egress.append(f"Discovery search: firewall-approved query strings are sent to {provider.name}")
    egress.append("Discovery crawl (only when requested): HTTP GET requests to registry domains, pages you add, and AI leads")
    if not LOCAL_ONLY:
        egress.append("Confirming an image match: its hostname is looked up at rdap.org")
    return {
        "local_only": LOCAL_ONLY,
        "limits": {
            "max_upload_mb": uploads.MAX_UPLOAD_BYTES // (1024 * 1024), "max_text_chars": uploads.MAX_TEXT_CHARS,
            "max_pdf_pages": uploads.MAX_PDF_PAGES, "allowed": sorted(uploads.SUFFIXES), "job_ttl_seconds": JOB_TTL,
            "max_concurrent_jobs": MAX_JOBS, "crawl_max_pages": CRAWL_MAX_PAGES, "crawl_max_depth": CRAWL_MAX_DEPTH,
        },
        "search_provider": provider.name,
        "llm": LLM_CFG.public(),
        "data_leaving_machine": egress,
        "enrolled": len(ENROLLED),
        "public_demo": is_public_demo(),
        "face_regions": FACE_REGIONS,
    }


@app.post("/api/jobs", status_code=202)
async def create_job(file: UploadFile | None = File(None), text: str | None = Form(None)):
    if (file is None) == (text is None):
        raise HTTPException(422, "send exactly one of 'file' or 'text'")
    if file is not None:
        data = await file.read(uploads.MAX_UPLOAD_BYTES + 1)
        name = file.filename or ""
    else:
        data, name = text.encode("utf-8"), "pasted.txt"
    try:
        suffix = uploads.validate(name, data)
    except uploads.UploadError as exc:
        raise HTTPException(422, str(exc)) from None
    job = Job(uuid.uuid4().hex, "analysis", time.time(), _workdir(), suffix=suffix,
              display_name="pasted text" if file is None else Path(name).name[:120])
    src = job.workdir / f"input{suffix}"  # never the client's filename
    src.write_bytes(data)
    job.stages.append(Stage("validate", "done", f"{len(data)} bytes"))
    _submit(job, lambda j: _analyse(j, src))
    return {"id": job.id}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    return _get(job_id).public()


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str):
    job = _get(job_id)
    job.cancel.set()
    return {"id": job.id, "status": job.status, "cancel_requested": True}


@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: str):
    with LOCK:
        job = JOBS.pop(job_id, None)
    if not job:
        raise HTTPException(404, "job not found or expired")
    _drop(job)
    return {"deleted": job_id}


@app.delete("/api/session")
def clear_session():
    global LLM_CFG
    _not_in_public_demo()
    with LOCK:
        jobs = list(JOBS.values())
        JOBS.clear()
    for j in jobs:
        _drop(j)
    REFERENCES._rows.clear()
    REF_LABELS.clear()
    ENROLLED.clear()
    LLM_CFG = llm.from_env()  # forget any runtime key
    return {"cleared_jobs": len(jobs)}


def _selected(job: Job, req: RedactRequest) -> list[Entity]:
    out = []
    for sel in req.selections:
        e = job.entities.get(sel.finding_id)
        if e is None:
            raise HTTPException(422, f"unknown finding {sel.finding_id}")
        f = next(f for f in job.findings if f["id"] == sel.finding_id)
        if sel.action not in f["actions"]:
            raise HTTPException(422, f"action '{sel.action}' not available for finding {sel.finding_id}")
        out.append(Entity(e.type, e.value, e.start, e.end, e.score, e.layer, sel.action))
    return out


@app.post("/api/jobs/{job_id}/redact")
def redact_job(job_id: str, req: RedactRequest):
    job = _get(job_id)
    if not job.redact_lock.acquire(blocking=False):
        raise HTTPException(409, "a redaction of this file is already running")
    try:
        return _redact(job, req)
    finally:
        job.redact_lock.release()


def _redact(job: Job, req: RedactRequest):
    if job.status != "ready" or job.kind != "analysis":
        raise HTTPException(409, f"job is {job.status}; analysis must finish first")
    if (job.agent_run or {}).get("status") == "running":
        raise HTTPException(409, "the agent swarm is redacting this file; wait for it to finish")
    ents = _selected(job, req)
    src = job.workdir / f"input{job.suffix}"

    if req.dry_run:
        if job.suffix == ".txt":
            return {"dry_run": True, "preview_text": redact_text(src.read_text(encoding="utf-8"), ents)[:20000]}
        plan = [{"finding_id": s.finding_id, "type": e.type, "layer": e.layer, "masked": mask_value(e.value) if e.value else "",
                 "replacement": "opaque fill" if job.suffix in FILE_ACTIONS or e.type == "FACE" else replacement(e, e.value)}
                for s, e in zip(req.selections, ents)]
        return {"dry_run": True, "plan": plan, "note": "Metadata, comments and embedded files are also removed when applied."}

    out_dir = job.workdir / "out"
    shutil.rmtree(out_dir, ignore_errors=True)
    t = time.monotonic()
    actions: dict[str, int] = {}
    for e in ents:
        actions[f"{e.type}:{e.action}"] = actions.get(f"{e.type}:{e.action}", 0) + 1
    _advance(job, "object_redact", {"selected": actions, "aggressive": False})
    out = redact(src, ents, out_dir)
    originals = [e.value for e in ents if e.value]
    attacks = verify.attack(out, originals)
    _advance(job, "red_team_attack", {a.name: a.passed for a in attacks})
    retried = False
    if not all(a.passed for a in attacks) and job.suffix != ".txt":
        retried = True
        _advance(job, "object_redact", {"selected": actions, "aggressive": True})
        out = redact(src, ents, out_dir, aggressive=True)
        attacks = verify.attack(out, originals)
        _advance(job, "red_team_attack", {a.name: a.passed for a in attacks})
    clean = all(a.passed for a in attacks)
    _advance(job, "consensus_ledger", {"status": "CLEAN" if clean else "FAILED", "output_sha256": hashlib.sha256(out.read_bytes()).hexdigest()})
    preview = ""
    try:
        preview = _masked(verify._extract_text(out)[:20000])  # anything the user chose to keep stays masked on screen
    except Exception:
        preview = "(preview unavailable: text extraction failed)"
    job.redaction = {
        "status": "CLEAN" if clean else "FAILED",
        "checks": [asdict(a) for a in attacks],
        "retried_aggressive": retried,
        "selected": len(ents),
        "output_name": f"sanitized{job.suffix}",
        "sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
        "preview_text": preview,
        "has_preview_image": job.suffix in {".pdf", ".png", ".jpg", ".jpeg"},
        "ms": int((time.monotonic() - t) * 1000),
        "note": "Original preserved. Download is only enabled when every check passed.",
        "ledger_head": job.ledger.blocks[-1]["current_hash"],
        "ledger_valid": job.ledger.verify() is None,
    }
    job.stages.append(Stage("redact+verify", "done" if clean else "failed", job.redaction["status"], job.redaction["ms"]))
    return job.redaction


def _output(job: Job) -> Path:
    out = job.workdir / "out" / f"input_sanitized{job.suffix}"
    if not job.redaction or not out.exists():
        raise HTTPException(404, "no sanitized output yet")
    return out


@app.get("/api/jobs/{job_id}/download")
def download(job_id: str):
    job = _get(job_id)
    out = _output(job)
    if job.redaction["status"] != "CLEAN":
        raise HTTPException(409, "verification failed; sanitized output withheld")
    return FileResponse(out, filename=job.redaction["output_name"], content_disposition_type="attachment")


@app.get("/api/jobs/{job_id}/preview.png")
def preview_png(job_id: str):
    import pymupdf
    from PIL import Image

    job = _get(job_id)
    out = _output(job)
    if job.suffix == ".pdf":
        with pymupdf.open(out) as doc:
            data = doc[0].get_pixmap(dpi=80).tobytes("png")
    elif job.suffix in {".png", ".jpg", ".jpeg"}:
        img = Image.open(out).convert("RGB")
        img.thumbnail((1200, 1200))
        buf = io.BytesIO()
        img.save(buf, "PNG")
        data = buf.getvalue()
    else:
        raise HTTPException(404, "no image preview for this format")
    return Response(data, media_type="image/png")


@app.post("/api/jobs/{job_id}/fingerprint")
def fingerprint(job_id: str):
    import cv2
    import numpy as np

    job = _get(job_id)
    if job.suffix not in {".png", ".jpg", ".jpeg"}:
        raise HTTPException(422, "fingerprints are computed for image inputs")
    img = cv2.imdecode(np.frombuffer((job.workdir / f"input{job.suffix}").read_bytes(), np.uint8), cv2.IMREAD_COLOR)
    regions = pdq.pdq_regions(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
    return {
        "pdq": [asdict(r) for r in regions],
        "note": "A PDQ fingerprint is for matching copies of this image. It is not redaction and does not sanitize the original.",
    }


@app.post("/api/references")
async def add_reference(file: UploadFile = File(...), label: str = Form("reference", max_length=60), authorized: bool = Form(False)):
    import cv2
    import numpy as np

    if not authorized:
        raise HTTPException(422, "confirm you are authorised to use this image for matching")
    data = await file.read(uploads.MAX_UPLOAD_BYTES + 1)
    try:
        uploads.validate(file.filename or "", data)
    except uploads.UploadError as exc:
        raise HTTPException(422, str(exc)) from None
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise HTTPException(422, "references must be PNG or JPEG images")
    rid = uuid.uuid4().hex[:8]
    rows = len(REFERENCES)
    REFERENCES.add_reference(rid, label, cv2.cvtColor(img, cv2.COLOR_BGR2RGB), [])
    if len(REFERENCES) == rows:
        raise HTTPException(422, "this image has too little detail to fingerprint; use a photo or a detailed scan")
    del img, data  # only PDQ hashes are retained
    REF_LABELS.append({"id": rid, "label": label})
    return {"id": rid, "label": label, "stored": "PDQ hashes only (8 dihedral × regions); image discarded"}


@app.get("/api/references")
def list_references():
    return {"references": REF_LABELS, "hash_rows": len(REFERENCES)}


# ---------- discovery ----------
SCOUT_EVENT_CAP = 3000


def _scout_event(job: "Job", ev: dict) -> None:
    evs = job.discovery.setdefault("events", []) if job.discovery is not None else None
    if evs is not None and len(evs) < SCOUT_EVENT_CAP:
        evs.append({"ts": time.time(), **ev})


def _on_site(url: str, domain: str) -> bool:
    host = urlparse(url).hostname or ""
    return host == domain or host.endswith("." + domain)


def _masked(text: str, blocked: list[str] = ()) -> str:
    """Web text before it is shown or sent to a model. Org and place names stay: the firewall allows them, and triage needs them."""
    from ..detect import variants
    from ..textscout import LONG_NUMBER

    found = {e.value for e in detect(text) + detect(text.upper()) + labelled_ids(text) if e.type not in {"ORG", "LOCATION", "DATE_TIME"}}
    found |= {v for b in blocked for v in variants(b) if v}  # the document's own values, such as a plain name no detector labels
    for value in sorted(found, key=len, reverse=True):
        text = re.sub(re.escape(value), mask_value(value), text, flags=re.I)
    return LONG_NUMBER.sub("•••", text)  # a wrong checksum or a mistyped phone is still a personal value


def _discover(job: Job, req: DiscoveryRequest, blocked_values: list[str], cfg: llm.LLMConfig) -> None:
    from .. import scout_agent
    from ..textscout import SearchError, build_queries, firewall, get_provider

    from ..registry import load_registry

    predefined = sorted({r["domain"] for r in load_registry(REGISTRY) if not r["domain"].replace(".", "").isdigit()})  # IPs are the local demo
    queries = _run_stage(job, "build_queries", lambda: build_queries(req.org, req.entity_types, req.domain, predefined))
    checked = _run_stage(job, "privacy_firewall", lambda: [{"query": q, "allowed": firewall(q, blocked_values)} for q in queries])
    provider = get_provider()
    results: list[dict] = []
    job.discovery = {"provider": provider.name, "queries": checked, "results": results, "crawl": None, "events": []}
    for c in checked:
        _scout_event(job, {"kind": "query", "query": c["query"], "allowed": c["allowed"], "provider": provider.name})

    def run_search(todo: list[str]):
        def fetch(q):
            try:
                return q, [] if job.cancel.is_set() else provider.search(q), None
            except Exception as exc:
                return q, [], exc

        # searches are I/O: ten in parallel take the time of one. Brave has no retry here, so it stays serial.
        with ThreadPoolExecutor(max_workers=1 if provider.name == "brave" else 8) as pool:
            answers = list(pool.map(fetch, todo))
        for q, hits, failure in answers:
            if job.cancel.is_set():
                raise Cancelled()
            try:
                if failure:
                    raise failure
            except SearchError as exc:
                job.stages[-1].detail = str(exc)
                _scout_event(job, {"kind": "search_error", "provider": provider.name, "reason": str(exc)})
                if exc.fatal:
                    break
                continue
            except Exception as exc:
                job.stages[-1].detail = f"{provider.name} error: {type(exc).__name__}"
                _scout_event(job, {"kind": "search_error", "provider": provider.name, "reason": job.stages[-1].detail})
                continue
            for h in hits:
                if any(r["source_url"] == h.get("url", "") and r["match_type"] == "text_search" for r in results):
                    continue  # several queries often return the same page
                if not h.get("url"):
                    continue
                results.append({
                    "source_url": h["url"], "title": _masked(h.get("title", ""), blocked_values)[:200], "excerpt": _masked(h.get("snippet", ""), blocked_values)[:300],
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "match_type": "text_search",
                    "score": None, "evidence_status": "candidate: needs human review", "query": q,
                    "provider": h.get("provider", provider.name), "tier": h.get("tier"),
                })
                _scout_event(job, {"kind": "search_hit", "url": h.get("url", ""), "provider": provider.name, "query": q})

    leads: list[str] = []

    def run_agent():
        """Search, let the model pick from what is new, repeat once on its sharper queries. No new results, no call."""
        todo, read = [c["query"] for c in checked if c["allowed"]], 0
        subject_ok = firewall(f"{req.org} {req.domain}", blocked_values)  # the subject itself goes to the model
        ai = job.discovery["ai"] = {"used": cfg.provider != "none" and bool(cfg.api_key) and subject_ok, "calls": 0, "tokens": 0, "read": 0, "leads": 0}
        for rounds_left in range(scout_agent.MAX_ROUNDS - 1, -1, -1):
            run_search(todo)
            fresh = [r for r in results[read:] if r["match_type"] == "text_search" and r.get("provider") != "offline"]
            read = len(results)
            listed = [r for r in fresh if any(_on_site(r["source_url"], d) for d in predefined)]
            for r in listed:  # a hit on a predefined site is a lead by definition: no model needed
                r["ai_why"] = "on a predefined site"
                leads.append(r["source_url"])
                _scout_event(job, {"kind": "ai_lead", "url": r["source_url"], "why": r["ai_why"]})
            fresh = [r for r in fresh if r not in listed]
            ai["leads"] = len(leads)
            if not ai["used"] or not fresh:
                return
            try:
                out = scout_agent.triage(cfg, req.org, fresh, blocked_values)
            except llm.LLMError as exc:
                _scout_event(job, {"kind": "search_error", "provider": cfg.provider, "reason": f"AI triage skipped: {exc}"})
                return
            ai["calls"] += 1 if out["tokens"] else 0
            ai["tokens"] += out["tokens"]
            ai["read"] += min(len(fresh), scout_agent.MAX_HITS) if out["tokens"] else 0
            for p in out["picks"]:
                next(r for r in results if r["source_url"] == p["source_url"])["ai_why"] = p["why"] or "picked by AI"
                leads.append(p["source_url"])
                _scout_event(job, {"kind": "ai_lead", "url": p["source_url"], "why": p["why"]})
            ai["leads"] = len(leads)
            _scout_event(job, {"kind": "ai_triage", "read": min(len(fresh), scout_agent.MAX_HITS), "picked": len(out["picks"]), "tokens": out["tokens"]})
            todo = out["next"] if rounds_left else []  # a query shown here must really run
            for q in todo:
                job.discovery["queries"].append({"query": q, "allowed": True})
                _scout_event(job, {"kind": "query", "query": q, "allowed": True, "provider": provider.name})
            if not todo:
                return

    _run_stage(job, f"search:{provider.name}", run_agent)
    job.ledger.append("scout", "SEARCH", {"provider": provider.name, "queries": len(checked),
                                          "blocked": sum(not c["allowed"] for c in checked), "results": len(results)})

    if not req.crawl:
        job.stages.append(Stage("crawl", "skipped", "not requested"))
        return
    faces = req.use_faces and bool(ENROLLED)
    if not len(REFERENCES) and not faces:
        job.stages.append(Stage("crawl", "skipped", "no reference images or face enrolment"))
        return
    _run_stage(job, "crawl+match", lambda: asyncio.run(_crawl(job, results, faces, req.extra_urls + leads[:scout_agent.MAX_LEADS])))
    job.ledger.append("scout", "CRAWL", {k: v for k, v in (job.discovery["crawl"] or {}).items()})


async def _crawl(job: Job, results: list[dict], use_faces: bool = False, extra_urls: list[str] = ()) -> None:
    from ..crawl import Job as CrawlJob, Scheduler
    from ..matcher import Matcher
    from ..net import Fetcher
    from ..registry import load_registry

    fetcher = Fetcher()
    # face vectors only when the user enrolled with consent + selfie and asked for it
    matcher = Matcher(list(ENROLLED) if use_faces else [], REFERENCES)
    sched = Scheduler(rps_per_domain=CRAWL_RPS, global_concurrency=8, budget_pages=CRAWL_MAX_PAGES, max_depth=CRAWL_MAX_DEPTH)
    for row in load_registry(REGISTRY):
        for url in row.get("entry_urls", []):
            depth = CRAWL_MAX_DEPTH - row.get("follow", CRAWL_MAX_DEPTH)  # follow: 0 scans only the listed pages
            sched.push(row.get("tier", 2), 0.5, CrawlJob(url, "page", depth, row["domain"], seed_category=row["category"], site=f'{row["category"]}@{row["domain"]}'))
    for url in extra_urls:  # depth at the limit: scan this page, follow nothing
        sched.push(1, 0.5, CrawlJob(url, "page", CRAWL_MAX_DEPTH, urlparse(url).hostname or ""))

    async def on_image(ref):
        m = await matcher.on_image(ref, fetcher)
        if m:
            results.append({
                "source_url": m.page_url, "image_url": m.image_url, "title": "", "excerpt": "",
                "timestamp": m.discovered_at, "match_type": f"{m.kind}:{m.region}", "score": m.pdq_distance,
                "similarity": m.similarity, "id": m.id, "kind": m.kind, "pdq_distance": m.pdq_distance,
                "thumb_b64": base64.b64encode(m.thumb_jpeg).decode(),  # 128 px, Gaussian radius 25: for review, not redaction
                "evidence_status": f"confirmed: {m.kind} strong match" if m.verdict == "confirmed" else "candidate: needs human review",
            })
            _scout_event(job, {"kind": "match", "url": m.page_url, "image_url": m.image_url, "match": m.kind, "verdict": m.verdict})

    async def on_event(ev):
        _scout_event(job, ev)  # page fetched / blocked / robots-denied / error: public URLs and counters only

    task = asyncio.create_task(sched.run(fetcher, on_image, on_event, CRAWL_TIMEOUT))
    deadline = time.monotonic() + CRAWL_TIMEOUT
    while not task.done():
        if job.cancel.is_set() or time.monotonic() > deadline:
            task.cancel()
            break
        await asyncio.sleep(0.2)
    try:
        counters = await task
    except asyncio.CancelledError:
        counters = dict(sched.counters, stopped="cancelled" if job.cancel.is_set() else "timeout")
    job.discovery["crawl"] = {**counters, "images_failed": matcher.failed}
    if job.cancel.is_set():
        raise Cancelled()


@app.post("/api/discovery", status_code=202)
def start_discovery(req: DiscoveryRequest, request: Request):
    cfg = request_llm(request)
    blocked: list[str] = []
    if req.job_id:
        # personal values are blocked; org/date context is what discovery is meant to search for
        blocked = [e.value for e in _get(req.job_id).entities.values() if e.value and e.type not in {"ORG", "DATE_TIME"}]
    job = Job(uuid.uuid4().hex, "discovery", time.time(), _workdir(), display_name=f"discovery: {req.org}")
    _submit(job, lambda j: _discover(j, req, blocked, cfg))
    return {"id": job.id}


# ---------- LLM provider ----------
def _not_in_public_demo() -> None:
    """Server-wide switches: on an open site a visitor could wipe everyone, or point the AI endpoint at their own host and collect the key."""
    if is_public_demo():
        raise HTTPException(403, "not available in public demo mode")


def request_llm(request: Request) -> llm.LLMConfig:
    """Who pays for this request's AI: the visitor's key, nobody (rules only), or the server's key.

    A visitor's key lives for this request and the job it starts: never stored on the job, logged or returned.
    """
    provider, key = request.headers.get("x-shield-llm-provider", ""), request.headers.get("x-shield-llm-key", "")
    if LOCAL_ONLY or provider == "none":
        return llm.LLMConfig()
    if not key:  # an open site must not let strangers spend the server's key
        return llm.LLMConfig() if is_public_demo() else LLM_CFG
    try:
        return llm.configure(llm.LLMConfig(timeout=LLM_CFG.timeout), provider=provider, api_key=key, model=request.headers.get("x-shield-llm-model", ""))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@app.get("/api/llm")
def get_llm():
    return {**LLM_CFG.public(), "local_only": LOCAL_ONLY, "providers": list(llm.PROVIDERS)}


@app.put("/api/llm")
def set_llm(body: LLMSettings):
    global LLM_CFG
    _not_in_public_demo()
    if LOCAL_ONLY and body.provider != "none":
        raise HTTPException(403, "local-only mode: remote LLM providers are disabled")
    try:
        LLM_CFG = llm.configure(LLM_CFG, **body.model_dump())
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return LLM_CFG.public()  # never echoes the key


@app.post("/api/llm/test")
def test_llm(request: Request):
    cfg = request_llm(request)
    if cfg.provider == "none":
        raise HTTPException(409, "no provider configured")
    return llm.test_connection(cfg)


@app.post("/api/llm/explain")
def explain(req: ExplainRequest, request: Request):
    job = _get(req.job_id)
    f = next((f for f in job.findings if f["id"] == req.finding_id), None)
    if not f:
        raise HTTPException(404, "finding not found")
    try:
        return llm.explain(request_llm(request), {**f, "rule": f["type"]})
    except llm.LLMError as exc:
        raise HTTPException(502, str(exc)) from None


WEB_DIST = BASE / "web/dist"


def mount_web() -> None:
    """Mount the built web app last: a mount at "/" would shadow routes registered after it."""
    if WEB_DIST.exists():
        app.mount("/", StaticFiles(directory=WEB_DIST, html=True), name="web")


MIN_TOKEN_LENGTH = 32  # /api/auth has no rate limit, so length is the defence: use `openssl rand -hex 32`


def _refuse_unsafe_bind(host: str) -> None:
    """People upload private documents, so a server others can reach must never start unprotected."""
    import ipaddress

    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"  # any other name, and "" (all interfaces), counts as public
    if loopback:
        return
    if os.getenv("SHIELD_ALLOW_LOCAL") == "1":
        raise SystemExit(f"Refusing to start: SHIELD_ALLOW_LOCAL=1 lets the crawler reach this machine, which is unsafe on SHIELD_HOST={host!r}. Unset it, or bind 127.0.0.1.")
    if is_public_demo():
        logging.info("Running in public demo mode: authentication guard bypassed for open evaluation.")
        return
    if len(API_TOKEN.strip()) < MIN_TOKEN_LENGTH:
        raise SystemExit(f"Refusing to start: SHIELD_HOST={host!r} is not loopback and SHIELD_API_TOKEN is empty. Set a token or bind 127.0.0.1.")


def main() -> None:
    import uvicorn

    host = os.getenv("SHIELD_HOST", "127.0.0.1")
    _refuse_unsafe_bind(host)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # its INFO line prints request URLs, and Google CSE keeps the key in the URL
    uvicorn.run(app, host=host, port=int(os.getenv("SHIELD_PORT") or os.getenv("PORT") or "8000"))  # hosts like Render inject PORT


if __name__ == "__main__":
    main()
