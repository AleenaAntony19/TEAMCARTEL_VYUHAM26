"""Versioned API contract for dashboards: /api/v1/... Thin layer over server.py; no duplicate logic."""
from __future__ import annotations

import asyncio
import hashlib
import json
import shutil

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
        "scout": {"provider": disc.get("provider"), "text_hits": [{k: r.get(k) for k in ("source_url", "title", "evidence_status")} for r in disc.get("results", []) if not r.get("thumb_b64")],
                  "matches": [r for r in disc.get("results", []) if r.get("thumb_b64")]},
        "ledger_head": j.ledger.blocks[-1]["current_hash"] if j.ledger.blocks else None,
    }
    out = j.workdir / "dossier"
    shutil.rmtree(out, ignore_errors=True)
    path = build_dossier(report, j.ledger, out)
    j.ledger.append("dossier", "DOSSIER_EXPORTED", {"zip_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return FileResponse(path, filename=f"shield_dossier_{j.id[:8]}.zip", content_disposition_type="attachment")


app.include_router(router)
