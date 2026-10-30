"""Versioned API contract for dashboards: /api/v1/... Thin layer over server.py; no duplicate logic."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import shutil
from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from .. import uploads
from ..dossier import build_dossier
from ..review import deliberate_stream
from . import server
from .server import DiscoveryRequest, RedactRequest, Selection, app

router = APIRouter(prefix="/api/v1")


class RedactBody(BaseModel):
    job_id: str
    selections: list[Selection] = Field(min_length=1, max_length=1000)
    dry_run: bool = False


class ScoutBody(BaseModel):
    org: str = Field(min_length=2, max_length=100, pattern=r"^[\w .&'-]+$")
    domain: str = Field(default="", max_length=253, pattern=r"^([a-z0-9-]+\.)*[a-z0-9-]*$")
    entity_types: list[str] = Field(default_factory=list, max_length=20)
    job_id: str | None = None
    use_faces: bool = False


@router.post("/shield/analyze", status_code=202, tags=["shield"])
async def analyze(file: UploadFile | None = File(None), text: str | None = Form(None)):
    """Start analysis of text or a PDF/DOCX/XLSX/PNG/JPG/TXT upload. Poll GET /api/v1/shield/jobs/{job_id}."""
    res = await server.create_job(file, text)
    return {"job_id": res["id"]}


@router.get("/shield/jobs/{job_id}", tags=["shield"])
def job(job_id: str):
    return server.get_job(job_id)


@router.post("/shield/redact", tags=["shield"])
def redact(body: RedactBody):
    """Object-level redaction + red-team verification (or a preview with dry_run)."""
    return server.redact_job(body.job_id, RedactRequest(selections=body.selections, dry_run=body.dry_run))


def _scout(body: ScoutBody, crawl: bool) -> dict:
    req = DiscoveryRequest(org=body.org, domain=body.domain, entity_types=body.entity_types, crawl=crawl,
                           use_faces=body.use_faces, job_id=body.job_id)
    return {"job_id": server.start_discovery(req)["id"]}


@router.post("/scout/search", status_code=202, tags=["scout"])
def scout_search(body: ScoutBody):
    """Firewalled search-provider queries (org/domain + entity types only)."""
    return _scout(body, crawl=False)


@router.post("/scout/crawl", status_code=202, tags=["scout"])
def scout_crawl(body: ScoutBody):
    """Search plus a polite registry crawl matched against reference PDQ hashes (and, opt-in, enrolled faces)."""
    if not len(server.REFERENCES) and not (body.use_faces and server.ENROLLED):
        raise HTTPException(409, "add a reference image (POST /api/references) or enrol (POST /api/v1/scout/enroll) first")
    return _scout(body, crawl=True)


@router.post("/scout/enroll", tags=["scout"])
async def enroll(photo: UploadFile = File(...), selfie: UploadFile = File(...), consent: bool = Form(False)):
    """Consented likeness enrolment: one face in the photo, a live selfie that matches it. Keeps an int8 vector in memory only."""
    from .. import face

    blobs = []
    for f in (photo, selfie):
        data = await f.read(uploads.MAX_UPLOAD_BYTES + 1)
        try:
            uploads.validate(f.filename or "", data)
        except uploads.UploadError as exc:
            raise HTTPException(422, str(exc)) from None
        blobs.append(data)
    try:
        vec = face.enroll(blobs[0], blobs[1], consent)
    except face.EnrollError as exc:
        raise HTTPException(422, str(exc)) from None
    finally:
        del blobs
    server.ENROLLED.append(vec)
    return {"enrolled": len(server.ENROLLED), "stored": "128-byte int8 vector in memory; images discarded"}


@router.delete("/scout/enroll", tags=["scout"])
def unenroll():
    server.ENROLLED.clear()
    return {"enrolled": 0}


@router.get("/swarm/deliberate", tags=["swarm"])
async def deliberate(job_id: str):
    """Server-sent events: each persona turn and verdict as the 2-round deliberation runs over the job's detections."""
    j = server._get(job_id)
    if not j.raw:
        raise HTTPException(409, "analysis has not reached the deliberate stage")
    entities, layers = j.raw

    async def events():
        for ev in deliberate_stream(entities, layers):
            yield {"event": ev["event"], "data": json.dumps(ev)}
            await asyncio.sleep(0)  # let the client render turn by turn

    return EventSourceResponse(events())


@router.get("/dossier/export", tags=["dossier"])
def dossier(job_id: str):
    """ZIP: dossier.pdf (NCRP / CERT-In / IT Rules / Section 63 BSA Part A drafts), ledger.json, verify_ledger.py."""
    j = server._get(job_id)
    if j.ledger.verify() is not None:
        raise HTTPException(500, "ledger integrity check failed; refusing to export")
    red = j.redaction or {}
    disc = j.discovery or {}
    report = {
        "job": {"id": j.id, "kind": j.kind, "state": j.state, "input_type": j.suffix.lstrip(".")},
        "doc": {"status": red.get("status"), "checks": red.get("checks"), "output_sha256": red.get("sha256"),
                "finding_types": sorted({f["type"] for f in j.findings})},
        "scout": {"provider": disc.get("provider"), "text_hits": [{k: r.get(k) for k in ("source_url", "title", "evidence_status")} for r in disc.get("results", []) if r["match_type"] == "text_search" and r.get("provider") != "offline"],
                  "matches": [{**r, "page_url": r["source_url"], "verdict": r.get("review") or r["evidence_status"]} for r in disc.get("results", []) if r.get("thumb_b64")]},
        "ledger_head": j.ledger.blocks[-1]["current_hash"] if j.ledger.blocks else None,
    }
    out = j.workdir / "dossier"
    shutil.rmtree(out, ignore_errors=True)
    path = build_dossier(report, j.ledger, out)
    j.ledger.append("dossier", "DOSSIER_EXPORTED", {"zip_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return FileResponse(path, filename=f"shield_dossier_{j.id[:8]}.zip", content_disposition_type="attachment")


class SwarmRunBody(BaseModel):
    job_id: str


def _swarm_job(j: "server.Job") -> None:
    """Binding agent swarm on an analysed job: MCP tools act on the job's own findings, graph and ledger."""
    import time as _t

    from .. import llm
    from ..mcp.tools import SESSIONS, register_session
    from ..swarm import run_agentic

    run = j.agent_run
    src = j.workdir / f"input{j.suffix}"

    def on_tool(tool: str, args: dict, result: dict) -> None:
        safe = {k: v for k, v in args.items() if k in {"finding_id", "strategy", "page", "decisions", "fix", "k"}}
        try:
            j.ledger.append(f"agent_tool:{tool}", "TOOL_CALL", {"args": safe, "ok": "error" not in result})
        except ValueError:
            j.ledger.append(f"agent_tool:{tool}", "TOOL_CALL", {"ok": "error" not in result})

    def on_event(ev: dict) -> None:
        # observations are already masked by the tools; trimmed so the event log stays small
        run["events"].append({k: (json.dumps(v, default=str)[:1500] if k == "observation" else v) for k, v in ev.items()})

    sess = register_session(src, j.raw[1] if j.raw else {}, dict(j.entities), j.workdir / "agentic",
                            on_tool=on_tool, on_stage=lambda st, d: server._advance(j, st, d))
    t = _t.monotonic()
    try:
        res = asyncio.run(run_agentic(sess.id, server.LLM_CFG, on_event))
        out = sess.output
        if out and out.exists():
            final = j.workdir / "out" / f"input_sanitized{j.suffix}"
            final.parent.mkdir(exist_ok=True)
            shutil.copyfile(out, final)
            j.redaction = {
                "status": "CLEAN" if res["clean"] else "FAILED",
                "checks": [{"name": a["name"], "passed": a["passed"], "evidence": a["evidence"]} for a in res["attacks"]],
                "retried_aggressive": res["cycles"] > 1, "selected": sum(d["action"] != "keep" for d in res["decisions"]),
                "output_name": f"sanitized{j.suffix}", "sha256": hashlib.sha256(final.read_bytes()).hexdigest(),
                "preview_text": "", "has_preview_image": j.suffix in {".pdf", ".png", ".jpg", ".jpeg"},
                "ms": int((_t.monotonic() - t) * 1000), "note": "Produced by the binding agent swarm.",
            }
            try:
                from .. import verify

                j.redaction["preview_text"] = verify._extract_text(final)[:20000]
            except Exception:
                j.redaction["preview_text"] = "(preview unavailable)"
            server._advance(j, "consensus_ledger", {"status": j.redaction["status"], "output_sha256": j.redaction["sha256"], "by": "agent_swarm"})
            j.redaction["ledger_head"], j.redaction["ledger_valid"] = j.ledger.blocks[-1]["current_hash"], j.ledger.verify() is None
        run.update(status="done", result={k: v for k, v in res.items() if k != "output"})
    except Exception as exc:
        run.update(status="failed", error=type(exc).__name__ + (f": {exc}" if isinstance(exc, (llm.LLMError, HTTPException)) else ""))
    finally:
        SESSIONS.pop(sess.id, None)


@router.post("/swarm/run", status_code=202, tags=["swarm"])
def swarm_run(body: SwarmRunBody):
    """Run the binding LLM agent swarm (planner, specialists, personas, FormatGuard, adjudicator, red team) on an analysed job."""
    j = server._get(body.job_id)
    if j.kind != "analysis" or j.status != "ready":
        raise HTTPException(409, "analysis must finish first")
    if server.LOCAL_ONLY or server.LLM_CFG.provider == "none" or not server.LLM_CFG.api_key:
        raise HTTPException(409, "configure Groq or Claude in the AI provider tab first")
    if j.agent_run and j.agent_run["status"] == "running":
        raise HTTPException(409, "a swarm run is already in progress")
    j.agent_run = {"status": "running", "events": [], "result": None, "error": ""}
    server.SWARM_POOL.submit(_swarm_job, j)
    return {"job_id": j.id, "status": "running"}


@router.get("/ledger", tags=["dossier"])
def ledger(job_id: str):
    """The job's SHA-256 hash chain. `first_bad` is null while the chain verifies."""
    j = server._get(job_id)
    return {"blocks": j.ledger.blocks, "first_bad": j.ledger.verify()}


@router.post("/ledger/tamper-demo", tags=["dossier"])
def ledger_tamper_demo(job_id: str):
    """Edits a copy of the chain to prove verification catches it. The real ledger is never touched."""
    j = server._get(job_id)
    blocks = copy.deepcopy(j.ledger.blocks)
    if not blocks:
        raise HTTPException(409, "ledger is empty")
    victim = blocks[len(blocks) // 2]
    victim["actor"] = "tampered"
    return {"tampered_seq": victim["seq"], "first_bad": j.ledger.verify(blocks)}


@router.get("/scout/registry", tags=["scout"])
def scout_registry():
    """Sites the crawler is allowed to visit."""
    from ..registry import load_registry

    return [{k: r.get(k) for k in ("domain", "category", "tier", "entry_urls")} for r in load_registry(server.REGISTRY)]


class ReviewBody(BaseModel):
    job_id: str
    match_id: str
    decision: Literal["confirm", "reject"]


@router.post("/scout/review", tags=["scout"])
async def scout_review(body: ReviewBody):
    """Human verdict on a crawl match, sealed in the ledger. Reject drops the thumbnail; confirm looks up the hosting IPs."""
    from ..evidence import infra

    j = server._get(body.job_id)
    match = next((r for r in (j.discovery or {}).get("results", []) if r.get("id") == body.match_id), None)
    if match is None:
        raise HTTPException(404, "unknown match")
    match["review"] = "confirmed" if body.decision == "confirm" else "rejected"
    if body.decision == "reject":
        match.pop("thumb_b64", None)
    else:
        match["infra"] = await infra(match["source_url"], {})
    j.ledger.append("human", "MATCH_REVIEW", {"match_id": body.match_id, "decision": match["review"]})
    return match


@router.get("/swarm/events", tags=["swarm"])
async def swarm_events(job_id: str, since: int = 0):
    """SSE: live agent steps (tool calls with masked observations, spawns, verdicts) until the run ends."""
    j = server._get(job_id)
    if not j.agent_run:
        raise HTTPException(409, "no swarm run for this job")

    async def gen():
        i = since
        while True:
            evs = j.agent_run["events"]
            while i < len(evs):
                yield {"event": "agent", "data": json.dumps(evs[i], default=str)}
                i += 1
            if j.agent_run["status"] != "running":
                yield {"event": "end", "data": json.dumps({"status": j.agent_run["status"], "result": j.agent_run.get("result"), "error": j.agent_run.get("error")})}
                return
            await asyncio.sleep(0.3)

    return EventSourceResponse(gen())


@router.get("/scout/events", tags=["scout"])
async def scout_events(job_id: str, since: int = 0):
    """SSE: live discovery steps (firewall verdicts, search hits, pages fetched/blocked, image matches)."""
    j = server._get(job_id)
    if j.kind != "discovery":
        raise HTTPException(409, "not a discovery job")

    async def gen():
        i = since
        while True:
            evs = (j.discovery or {}).get("events", [])
            while i < len(evs):
                yield {"event": "scout", "data": json.dumps(evs[i], default=str)}
                i += 1
            if j.status not in {"queued", "running"}:
                yield {"event": "end", "data": json.dumps({"status": j.status, "crawl": (j.discovery or {}).get("crawl")})}
                return
            await asyncio.sleep(0.3)

    return EventSourceResponse(gen())


app.include_router(router)

# MCP over Streamable HTTP at /mcp (same tools as `python -m shield.mcp` stdio); guarded by SHIELD_API_TOKEN like /api
from contextlib import asynccontextmanager  # noqa: E402

from ..mcp.tools import server as mcp_server  # noqa: E402

def _mcp_app():
    return mcp_server.streamable_http_app(streamable_http_path="/", stateless_http=True, json_response=True)


app.mount("/mcp", _mcp_app())
_mcp_route = app.router.routes[-1]
_inner_lifespan = app.router.lifespan_context


@asynccontextmanager
async def _lifespan(a):
    # a session manager runs once per instance: build a fresh MCP app for every startup (tests restart the app)
    _mcp_route.app = _mcp_app()
    async with mcp_server.session_manager.run():
        async with _inner_lifespan(a) as state:
            yield state


app.router.lifespan_context = _lifespan
