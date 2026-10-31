"""Shield·Scout MCP server: real engine operations exposed as Model Context Protocol tools.

Every tool runs real code (Verhoeff/Luhn, Tesseract, PyMuPDF/OOXML/pixel redaction, PDQ, attacks).
Privacy contract: tools address findings by `finding_id`; raw values stay in this process and are
never returned, so an LLM driving these tools only ever sees masked data.

Used two ways:
- in-process by shield/agent_runtime.py (same `server.list_tools()` / `server.call_tool()` handlers)
- externally over stdio: `python -m shield.mcp` (e.g. from Claude Desktop / Claude Code)
"""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from mcp.server.mcpserver import MCPServer

from .. import pdq, verify
from ..detect import detect, luhn_valid, variants, verhoeff_valid
from ..models import Entity
from ..redact import redact
from ..review import mask_value

server = MCPServer(
    "shield-scout",
    instructions="Privacy forensics tools. Open a document, inspect masked findings, validate identifiers, "
    "redact destructively, then attack the output. Values are always masked.",
)

PIXEL_FORMATS = {".pdf", ".png", ".jpg", ".jpeg"}  # these redact with opaque fill regardless of action
ACTIONS = {"token", "mask", "remove", "keep"}
# Safety floor: an LLM verdict may choose *how* these are redacted, never whether. Identity, financial
# and location identifiers that survived the deterministic checks are always redacted.
FLOOR_TYPES = {"IN_PAN", "IN_PASSPORT", "IN_BANK_ACCOUNT", "IN_UPI", "IN_GSTIN", "GEO_COORDINATES", "FACE"}


@dataclass
class Session:
    id: str
    src: Path  # document, or workspace root for kind == "workspace"
    workdir: Path
    layers: dict[str, str]
    findings: dict[str, Entity]  # finding_id -> entity (raw value: internal only)
    bank: pdq.HashBank | None = None
    output: Path | None = None
    redacted_ids: list[str] = field(default_factory=list)
    cycles: int = 0
    last_attack: dict | None = None  # ground truth from the latest penetration test
    kind: str = "document"
    code_findings: dict[str, dict] = field(default_factory=dict)  # workspace sessions: codescan findings by id
    on_tool: Callable[[str, dict, dict], None] | None = None  # audit hook (ledger)
    on_stage: Callable[[str, dict], None] | None = None  # job-graph hook


SESSIONS: dict[str, Session] = {}


def register_session(src: Path, layers: dict[str, str], findings: dict[str, Entity], workdir: Path, **hooks) -> Session:
    s = Session(uuid.uuid4().hex[:12], Path(src), Path(workdir), layers, findings, **hooks)
    SESSIONS[s.id] = s
    return s


def _session(session_id: str) -> Session:
    if session_id not in SESSIONS:
        raise ValueError(f"unknown session '{session_id}'; call open_document first")
    return SESSIONS[session_id]


def _allowed(path: Path) -> Path:
    """External MCP callers may only open files under SHIELD_MCP_ROOT (default: current directory)."""
    root = Path(os.getenv("SHIELD_MCP_ROOT", os.getcwd())).resolve()
    p = path.resolve()
    if p != root and root not in p.parents:
        raise ValueError("path outside SHIELD_MCP_ROOT")
    if not p.is_file():
        raise ValueError("not a file")
    return p


def _mask_text(text: str) -> str:
    """Mask every detected sensitive value (keeps last 4) so OCR/text output is safe to show an LLM."""
    for e in sorted(detect(text), key=lambda e: -len(e.value)):
        if e.type not in {"DATE_TIME", "ORG"} and e.value:
            text = text.replace(e.value, mask_value(e.value))
    # long digit runs the detectors did not classify are still masked
    return re.sub(r"\d{6,}", lambda m: mask_value(m.group(0)), text)


def _audit(s: Session, tool: str, args: dict, result: dict) -> dict:
    if s.on_tool:
        s.on_tool(tool, args, result)
    return result


# ---------------------------------------------------------------- tools
@server.tool()
def open_document(path: str) -> dict:
    """Open a PDF/DOCX/XLSX/image/text file: extract every layer, detect findings, return a session id and masked findings."""
    from ..profile import layer_texts

    src = _allowed(Path(path))
    layers = layer_texts(src)
    from ..review import review

    findings = {}
    kept, _ = review([e for name, text in layers.items() for e in detect(text, layer=name)], layers)
    for e in kept:  # deterministic persona ring already dismissed placeholders / failed checksums
        fid = hashlib.sha256(f"{src}|{e.type}|{e.layer}|{e.start}".encode()).hexdigest()[:12]
        findings[fid] = e
    s = register_session(src, layers, findings, Path(tempfile.mkdtemp(prefix="shield-mcp-")))
    return {"session_id": s.id, "format": src.suffix.lstrip("."), "layers": sorted(layers), **list_findings(s.id)}


@server.tool()
def list_findings(session_id: str) -> dict:
    """List the session's findings: id, type, layer, masked value, masked context and detector confidence."""
    s = _session(session_id)
    out = []
    for fid, e in s.findings.items():
        text = s.layers.get(e.layer, "")
        ctx = _mask_text(text[max(0, e.start - 30) : e.end + 30]) if text else ""
        out.append({"id": fid, "type": e.type, "layer": e.layer, "masked": mask_value(e.value) if e.value else "",
                    "context": " ".join(ctx.split()), "confidence": round(e.score, 2)})
    return {"findings": out, "count": len(out)}


@server.tool()
def validate_checksum(session_id: str, finding_id: str) -> dict:
    """Mathematically validate a finding: Verhoeff (D5 dihedral group) for Aadhaar, Luhn mod-10 for cards."""
    s = _session(session_id)
    e = s.findings.get(finding_id)
    if e is None:
        return {"error": f"unknown finding {finding_id}"}
    digits = re.sub(r"\D", "", e.value)
    if e.type == "IN_AADHAAR" or (e.type in {"POTENTIAL_LEAK", "IN_BANK_ACCOUNT"} and len(digits) == 12):
        res = {"valid": verhoeff_valid(digits), "algorithm": "Verhoeff_D5", "authority": "UIDAI / Aadhaar Act 2016 / DPDP Act 2023"}
    elif e.type == "CREDIT_CARD" or 13 <= len(digits) <= 19:
        res = {"valid": luhn_valid(digits), "algorithm": "Luhn_Mod10", "authority": "RBI / PCI-DSS"}
    else:
        res = {"valid": None, "algorithm": None, "note": f"no checksum exists for {e.type}"}
    return _audit(s, "validate_checksum", {"finding_id": finding_id}, {"finding_id": finding_id, "type": e.type, **res})


@server.tool()
def extract_ocr_region(session_id: str, page: int = 0, bbox: list[int] | None = None) -> dict:
    """Run Tesseract OCR on a page (PDF, rendered at 200 dpi) or image, optionally cropped to bbox [x0,y0,x1,y1]. Text is returned masked; new sensitive values become findings."""
    import pymupdf
    import pytesseract
    from PIL import Image

    s = _session(session_id)
    if s.src.suffix.lower() == ".pdf":
        with pymupdf.open(s.src) as doc:
            if not 0 <= page < doc.page_count:
                return {"error": f"page must be 0..{doc.page_count - 1}"}
            pix = doc[page].get_pixmap(dpi=200)
            img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    elif s.src.suffix.lower() in {".png", ".jpg", ".jpeg"}:
        img = Image.open(s.src).convert("RGB")
    else:
        return {"error": "OCR applies to PDF pages and images"}
    if bbox:
        if len(bbox) != 4:
            return {"error": "bbox must be [x0, y0, x1, y1]"}
        img = img.crop(tuple(int(v) for v in bbox))
    text = pytesseract.image_to_string(img, config="--psm 6")
    new = []
    for e in detect(text, layer="ocr"):
        known = {x.value for x in s.findings.values()}
        if e.value not in known and e.type not in {"DATE_TIME", "ORG"}:
            fid = hashlib.sha256(f"{s.id}|ocr|{page}|{e.type}|{e.start}".encode()).hexdigest()[:12]
            s.findings[fid] = Entity(e.type, e.value, e.start, e.end, e.score, "ocr")
            new.append({"id": fid, "type": e.type, "masked": mask_value(e.value)})
    return _audit(s, "extract_ocr_region", {"page": page, "bbox": bbox}, {"text_masked": _mask_text(text)[:1500], "new_findings": new})


@server.tool()
def compute_perceptual_pdq(session_id: str) -> dict:
    """Compute 256-bit PDQ hashes (full + centre crops, 8 dihedral variants matched) for the document's images and compare with the reference bank."""
    import cv2

    from ..profile import extract_images

    s = _session(session_id)
    out = []
    for name, img, _ in extract_images(s.src):
        regions = pdq.pdq_regions(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
        near = s.bank.nearest(regions) if s.bank is not None and len(s.bank) and regions else None
        out.append({"image": name, "hashes": [{"region": r.region, "hex": r.hex, "quality": r.quality} for r in regions],
                    "bank_match": {"label": near[0]["label"], "distance": near[1], "band": pdq.band(near[1])} if near else None})
    return _audit(s, "compute_perceptual_pdq", {}, {"images": out, "note": "PDQ is for matching; it does not redact."})


@server.tool()
def execute_destructive_redaction(session_id: str, decisions: list[dict], strategy: str = "standard") -> dict:
    """Destructively redact. decisions = [{"finding_id": str, "action": "token"|"mask"|"remove"|"keep"}].
    strategy "aggressive" rasterizes PDFs / pads image boxes / raw-replaces OOXML bytes. Checksum-verified
    Aadhaar/cards and PAN/passport/bank/UPI/GSTIN/coordinates/faces are always redacted (safety floor), even if marked keep."""
    s = _session(session_id)
    if strategy not in {"standard", "aggressive"}:
        return {"error": "strategy must be standard or aggressive"}
    chosen: dict[str, str] = {}
    for d in decisions:
        fid, act = str(d.get("finding_id", "")), str(d.get("action", ""))
        if fid not in s.findings or act not in ACTIONS:
            return {"error": f"bad decision {d!r}"}
        chosen[fid] = act
    enforced = []
    for fid, e in s.findings.items():
        digits = re.sub(r"\D", "", e.value)
        verified = (e.type == "IN_AADHAAR" and verhoeff_valid(digits)) or (e.type == "CREDIT_CARD" and luhn_valid(digits))
        if (verified or e.type in FLOOR_TYPES) and chosen.get(fid, "keep") == "keep":
            chosen[fid] = "remove" if s.src.suffix.lower() in PIXEL_FORMATS else "token"
            enforced.append(fid)
    ents = [Entity(e.type, e.value, e.start, e.end, e.score, e.layer, a) for fid, a in chosen.items() if a != "keep" for e in [s.findings[fid]]]
    if s.on_stage:
        s.on_stage("object_redact", {"selected": len(ents), "strategy": strategy, "floor_enforced": len(enforced)})
    out = redact(s.src, ents, s.workdir / "out", aggressive=strategy == "aggressive")
    s.output, s.cycles = out, s.cycles + 1
    # a union: a narrower replan must not shrink what the red team attacks, or a value could survive and still pass
    s.redacted_ids = sorted(set(s.redacted_ids) | {fid for fid, a in chosen.items() if a != "keep"})
    return _audit(s, "execute_destructive_redaction", {"decisions": len(chosen), "strategy": strategy},
                  {"redacted": len(ents), "kept": sum(a == "keep" for a in chosen.values()), "floor_enforced": enforced,
                   "strategy": strategy, "cycle": s.cycles, "output_sha256": hashlib.sha256(out.read_bytes()).hexdigest()})


@server.tool()
def adversarial_penetration_test(session_id: str) -> dict:
    """Attack the latest sanitized output: text extraction, decompressed binary grep, metadata/EXIF audit, and (PDF) an OCR second pass of rendered pages. Reports leaks without values."""
    import pymupdf
    import pytesseract
    from PIL import Image

    s = _session(session_id)
    if not s.output or not s.output.exists():
        return {"error": "nothing redacted yet; call execute_destructive_redaction first"}
    originals = [s.findings[f].value for f in s.redacted_ids if s.findings[f].value]
    attacks = [{"name": a.name, "passed": a.passed, "evidence": a.evidence} for a in verify.attack(s.output, originals)]
    if s.output.suffix.lower() == ".pdf":
        try:
            with pymupdf.open(s.output) as doc:
                text = ""
                for page in doc:
                    pix = page.get_pixmap(dpi=150)
                    text += pytesseract.image_to_string(Image.frombytes("RGB", (pix.width, pix.height), pix.samples))
            hits = sum(any(v in text for v in variants(o)) for o in originals)
            attacks.append({"name": "ocr_second_pass", "passed": hits == 0, "evidence": [f"{hits} value(s) readable by OCR"] if hits else []})
        except Exception as exc:
            attacks.append({"name": "ocr_second_pass", "passed": False, "evidence": [f"could not run ({type(exc).__name__}); not verified"]})
    clean = all(a["passed"] for a in attacks)
    if s.on_stage:
        s.on_stage("red_team_attack", {a["name"]: a["passed"] for a in attacks})
    s.last_attack = {"clean": clean, "attacks": attacks, "cycle": s.cycles}
    return _audit(s, "adversarial_penetration_test", {}, s.last_attack)


@server.tool()
def measure_layout(session_id: str) -> dict:
    """FormatGuard's layout probe: per finding, the replacement length for each action and (PDF) the exact boxes that would be filled, so a choice keeps tables and line lengths intact."""
    import pymupdf

    s = _session(session_id)
    out = []
    pdf = pymupdf.open(s.src) if s.src.suffix.lower() == ".pdf" else None
    try:
        for fid, e in s.findings.items():
            if not e.value:
                continue
            item = {"id": fid, "type": e.type, "layer": e.layer, "length": len(e.value),
                    "replacement_length": {"token": len(f"[REDACTED-{e.type}]"), "mask": len(e.value), "remove": 0}}
            if pdf is not None:
                boxes = [[round(v, 1) for v in r] for page in pdf for v_ in variants(e.value) for r in page.search_for(v_)]
                item["pdf_boxes"] = boxes[:6]
                item["note"] = "PDF fill keeps layout for any action" if boxes else "value not in a text layer (metadata/annotation/embedded)"
            elif s.src.suffix.lower() in {".docx", ".xlsx", ".txt", ".csv", ".json"}:
                item["note"] = "mask keeps column widths/line length; token changes length by %+d" % (len(f"[REDACTED-{e.type}]") - len(e.value))
            out.append(item)
    finally:
        if pdf is not None:
            pdf.close()
    return _audit(s, "measure_layout", {}, {"format": s.src.suffix.lstrip("."), "items": out})


@server.tool()
def compute_pca_projection(session_id: str, k: int = 32) -> dict:
    """Project the document's images into a k-D PCA subspace fitted on the configured index set (SHIELD_PCA_INDEX_DIR) and return the nearest index images with cosine scores. Candidate signal only."""
    import cv2

    from ..models import BASE
    from ..pcamatch import PCAIndex, features
    from ..profile import extract_images

    s = _session(session_id)
    index_dir = Path(os.getenv("SHIELD_PCA_INDEX_DIR") or BASE / "demo/mockweb/img")
    items = {p.name: features(img) for p in sorted(index_dir.glob("*.jpg"))[:400] if (img := cv2.imread(str(p))) is not None}
    if len(items) < 3:
        return {"error": f"PCA index needs >= 3 images in {index_dir}"}
    index = PCAIndex.fit(items, k=max(2, min(int(k), 64)))
    out = []
    for name, img, _ in extract_images(s.src):
        top = index.query(features(img))[:3]
        out.append({"image": name, "nearest": [{"index_image": n, "cosine": round(c, 3)} for n, c in top]})
    return _audit(s, "compute_pca_projection", {"k": k}, {"k": int(index.components.shape[0]), "index_size": len(items), "images": out,
                   "note": "pixel-feature PCA; not rotation-invariant; treat as a candidate for review"})


# ---------------------------------------------------------------- code workspaces (RefactorBot)
@server.tool()
def open_workspace(path: str) -> dict:
    """Scan a code workspace (secrets, PII, SAST, config) and open a session over its findings (masked)."""
    from ..codescan import scan

    root = _allowed_dir(Path(path))
    res = scan(root, engines=["secrets", "pii", "sast", "config"], ocr=False)
    s = register_session(root, {}, {}, Path(tempfile.mkdtemp(prefix="shield-ws-")))
    s.kind = "workspace"
    s.code_findings = {f["id"]: f for f in res["findings"]}
    return {"session_id": s.id, **list_code_findings(s.id)}


def _allowed_dir(path: Path) -> Path:
    root = Path(os.getenv("SHIELD_MCP_ROOT", os.getcwd())).resolve()
    p = path.resolve()
    if p != root and root not in p.parents:
        raise ValueError("path outside SHIELD_MCP_ROOT")
    if not p.is_dir():
        raise ValueError("not a directory")
    return p


@server.tool()
def list_code_findings(session_id: str) -> dict:
    """Workspace findings: id, engine, rule, severity, file:line, masked evidence, available fixes."""
    s = _session(session_id)
    keys = ("id", "engine", "rule", "severity", "file", "line", "masked", "evidence", "fixes", "confidence")
    return {"findings": [{k: f.get(k) for k in keys} for f in s.code_findings.values()], "count": len(s.code_findings)}


@server.tool()
def refactor_code_secret(session_id: str, finding_id: str, fix: str = "move_to_env") -> dict:
    """Apply a codescan fix atomically: move_to_env (literal -> .env + os.environ/process.env), redact_pii, fake_pii,
    yaml_safe_load, requests_verify. Python results must still parse (ast) or nothing is written. Originals go to .shield/backup/."""
    import ast
    import shutil

    from ..codescan.fix import apply_edits, apply_plan, plan_fix

    s = _session(session_id)
    f = s.code_findings.get(finding_id)
    if f is None or fix not in f.get("fixes", []) or fix not in {"move_to_env", "redact_pii", "fake_pii", "yaml_safe_load", "requests_verify"}:
        return {"error": f"fix '{fix}' not available for {finding_id}"}
    if f["engine"] in {"secrets", "pii"}:
        # earlier fixes in this file may have shifted lines; ids are line-independent, so re-locate it
        from ..codescan import scan

        fresh = {x["id"]: x for x in scan(s.src, only=[Path(f["file"])], engines=[f["engine"]], ocr=False)["findings"]}
        if finding_id not in fresh:
            return {"applied": False, "notes": ["finding no longer present (already fixed?)"]}
        f = s.code_findings[finding_id] = fresh[finding_id]
    plan = plan_fix(s.src, f, fix)
    if not plan.edits and not plan.file_ops:
        return {"applied": False, "notes": plan.notes}
    for path in {e.file for e in plan.edits}:
        target = s.src / path
        new = apply_edits(target.read_text(), [e for e in plan.edits if e.file == path])
        if target.suffix == ".py":
            try:
                ast.parse(new)
            except SyntaxError as exc:
                return {"applied": False, "error": f"fix would break {path}: SyntaxError line {exc.lineno}"}
        backup = s.src / ".shield/backup"
        backup.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, backup / f"{hashlib.sha256(target.read_bytes()).hexdigest()[:16]}_{target.name}")
    apply_plan(plan, s.src)
    return _audit(s, "refactor_code_secret", {"finding_id": finding_id, "fix": fix},
                  {"applied": True, "files": sorted({e.file for e in plan.edits}), "file_ops": [o.summary for o in plan.file_ops], "notes": plan.notes})


@server.tool()
def rescan_workspace(session_id: str) -> dict:
    """Red-team a workspace after fixes: re-scan and report which of the session's original findings still exist."""
    from ..codescan import scan

    s = _session(session_id)
    res = scan(s.src, engines=["secrets", "pii", "sast", "config"], ocr=False)
    now = {(f["rule"], f["file"]) for f in res["findings"]}
    remaining = [fid for fid, f in s.code_findings.items() if (f["rule"], f["file"]) in now]
    s.last_attack = {"clean": not [fid for fid in remaining if s.code_findings[fid]["severity"] in {"critical", "high"}],
                     "remaining": remaining, "cycle": s.cycles}
    return _audit(s, "rescan_workspace", {}, s.last_attack)


@server.tool()
async def run_agent_swarm(session_id: str) -> dict:
    """Run the full LLM agent swarm (planner, specialists, personas, optimizers, adjudicator, red team) on a session.
    Needs SHIELD_LLM_PROVIDER and the provider key in the server environment. Returns decisions, attacks and token use."""
    from .. import llm
    from ..swarm import run_agentic

    cfg = llm.from_env()
    if cfg.provider == "none" or not cfg.api_key:
        return {"error": "set SHIELD_LLM_PROVIDER and GROQ_API_KEY / ANTHROPIC_API_KEY for the MCP server"}
    return await run_agentic(session_id, cfg)


# ---------------------------------------------------------------- resources
@server.resource("shield://doc/{doc_id}/metadata")
def doc_metadata(doc_id: str) -> dict:
    """Structural breakdown of an open document/workspace session."""
    s = _session(doc_id)
    return {"kind": s.kind, "format": s.src.suffix.lstrip(".") or "dir", "layers": {k: len(v) for k, v in s.layers.items()},
            "findings": len(s.findings) or len(s.code_findings), "cycles": s.cycles}


@server.resource("shield://doc/{doc_id}/layers")
def doc_layers(doc_id: str) -> dict:
    """Extracted layer text, masked."""
    s = _session(doc_id)
    return {k: _mask_text(v)[:20000] for k, v in s.layers.items()}


@server.resource("shield://ledger/{job_id}/chain")
def ledger_chain(job_id: str) -> dict:
    """SHA-256 hash-chain status of an API job (available when MCP is mounted in the API process)."""
    from ..api import server as api

    job = api.JOBS.get(job_id)
    if job is None:
        return {"error": "unknown job"}
    bad = job.ledger.verify()
    return {"blocks": len(job.ledger.blocks), "valid": bad is None, "first_bad_block": bad,
            "head": job.ledger.blocks[-1]["current_hash"] if job.ledger.blocks else None}


def main() -> None:
    server.run("stdio")
