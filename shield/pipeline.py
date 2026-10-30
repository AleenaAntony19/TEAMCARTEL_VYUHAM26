from __future__ import annotations

import asyncio
from dataclasses import asdict
import tempfile
from pathlib import Path
from typing import AsyncIterator, Iterator

import cv2
import numpy as np

from . import face, pdq
from .crawl import Job, Scheduler
from .deliberate import deliberate
from .detect import audit_all_extracted_text, severity, variants
from .ledger import Ledger, sha256_file
from .matcher import Matcher
from .models import Entity
from .net import Fetcher
from .profile import AgentFactory, extract_images, profile
from .redact import redact
from .registry import load_registry
from .textscout import build_queries, firewall, search
from . import verify


def _counts(entities):
    out: dict[str, int] = {}
    for e in entities:
        out[e.type] = out.get(e.type, 0) + 1
    return out


def run_document(src: str | Path, work: str | Path, ledger: Ledger) -> Iterator[dict]:
    src = Path(src)
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)

    prof = profile(src)
    ledger.append("PROFILE", {"format": prof.file_format, "tags": prof.domain_tags})
    yield {"kind": "profile", "profile": prof}

    agents = AgentFactory.spawn(prof, src)
    ledger.append("AGENTS_SPAWNED", {"agents": [a.name for a in agents]})
    for a in agents:
        yield {"kind": "agent", "agent": a.name, "status": "ready"}

    entities = list(prof.entities)

    for name, img, bbox in extract_images(src):
        if img is None:
            continue
        try:
            for vec, box in face.vectors(img):
                x, y, w, h = box
                layer = f"bbox:{x},{y},{x+w},{y+h}"
                if bbox and len(bbox) >= 5:
                    layer += f"@{bbox[4]}"
                entities.append(Entity("FACE", "", 0, 0, 1.0, layer))
        except FileNotFoundError:
            break
        except Exception:
            continue

    # Multi-Persona Dialectic Deliberation Swarm
    entities, debate_logs = deliberate(entities, prof.text)
    ledger.append(
        "CONSENSUS_REACHED",
        {"debated_count": len(debate_logs), "confirmed_count": len(entities)},
    )
    yield {
        "kind": "deliberation",
        "logs": [
            {
                "val": log.entity_val,
                "type": log.initial_type,
                "verdict": log.final_verdict,
                "score": log.final_score,
                "turns": [
                    {
                        "persona": t.persona,
                        "avatar": t.avatar,
                        "action": t.action,
                        "argument": t.argument,
                        "confidence": t.confidence,
                    }
                    for t in log.turns
                ],
            }
            for log in debate_logs
        ],
    }

    ledger.append("DETECT", {"counts": _counts(entities)})
    sev = severity(entities)
    score, band_str, types = sev[0], sev[1], sev[2]
    ranked_entities = [asdict(r) for r in getattr(sev, "ranked_entities", [])]
    yield {
        "kind": "detect",
        "counts": _counts(entities),
        "severity": band_str,
        "score": score,
        "ranked_entities": ranked_entities,
    }

    # Full-Document Word Verification & Audit Pass
    audit_rep = audit_all_extracted_text(prof.layers or {"visible": prof.text}, entities)
    ledger.append(
        "VERIFICATION_AUDIT",
        {
            "scanned": audit_rep.total_tokens_scanned,
            "captured": audit_rep.captured_count,
            "misses": len(audit_rep.potential_misses),
            "completeness_pct": audit_rep.verification_completeness_pct,
            "passed": audit_rep.audit_passed,
        },
    )
    yield {
        "kind": "verification_audit",
        "report": asdict(audit_rep),
    }

    # Self-healing: auto-merge high-risk misses into redaction entities
    for miss in audit_rep.potential_misses:
        if miss.severity_score >= 60.0:
            entities.append(Entity("POTENTIAL_LEAK", miss.token, miss.start, miss.end, 0.90, miss.layer))

    out = redact(src, entities, work, aggressive=False)
    yield {"kind": "redact", "output": str(out), "sha256": sha256_file(out)}

    originals = [e.value for e in entities if e.type != "FACE" and e.value]
    attacks = verify.attack(out, originals)
    status = "CLEAN" if all(a.passed for a in attacks) else "FAILED"
    ledger.append(
        "ATTACK",
        {"results": [{"name": a.name, "passed": a.passed} for a in attacks], "status": status},
    )
    for a in attacks:
        yield {"kind": "attack", "name": a.name, "passed": a.passed, "evidence": a.evidence}

    if status == "FAILED":
        yield {"kind": "retry", "reason": "initial attack failed"}
        out = redact(src, entities, work, aggressive=True)
        attacks = verify.attack(out, originals)
        status = "CLEAN" if all(a.passed for a in attacks) else "FAILED"
        ledger.append(
            "RETRY",
            {"results": [{"name": a.name, "passed": a.passed} for a in attacks], "status": status},
        )

    report = {
        "output": str(out),
        "entities": _counts(entities),
        "severity": band_str,
        "score": score,
        "types": types,
        "ranked_entities": ranked_entities,
        "verification_audit": asdict(audit_rep),
        "deliberation": [
            {"val": l.entity_val, "type": l.initial_type, "verdict": l.final_verdict, "score": l.final_score}
            for l in debate_logs
        ],
        "attacks": [{"name": a.name, "passed": a.passed, "evidence": a.evidence} for a in attacks],
        "status": status,
        "face_vectors_count": sum(1 for e in entities if e.type == "FACE"),
        "input_sha256": sha256_file(src),
        "output_sha256": sha256_file(out),
    }
    yield {"kind": "done", "report": report}


async def run_scout(
    enrolled: list[face.FaceVec],
    bank: pdq.HashBank | None,
    registry_path: str | Path,
    org: str,
    types: list[str],
    domain: str,
    ledger: Ledger,
) -> AsyncIterator[dict]:
    ledger.append("SESSION_START", {"org": org, "domain": domain})
    registry = load_registry(registry_path)
    agents = AgentFactory.spawn_scout(registry, bool(enrolled))
    ledger.append("AGENTS_SPAWNED", {"agents": [a.name for a in agents], "scout": True})
    yield {"kind": "agents", "agents": [a.name for a in agents]}

    queries = build_queries(org, types, domain)
    text_hits: list[dict] = []
    for q in queries:
        allowed = firewall(q, [org] if org else [])
        yield {"kind": "query", "query": q, "allowed": allowed}
        if not allowed:
            continue
        for hit in search(q):
            text_hits.append(hit)
            yield {"kind": "search_hit", "hit": hit}

    fetcher = Fetcher()
    matcher = Matcher(enrolled, bank)
    sched = Scheduler(rps_per_domain=1.0, global_concurrency=8, budget_pages=500)

    for row in registry:
        for url in row.get("entry_urls", []):
            sched.push(row.get("tier", 2), 0.5, Job(url, "page", 0, row["domain"], seed_category=row["category"]))

    queue: asyncio.Queue = asyncio.Queue()

    async def on_event_q(ev):
        await queue.put(ev)

    async def on_image(ref):
        m = await matcher.on_image(ref, fetcher)
        if m:
            await queue.put({"kind": "match", "match": m})

    task = asyncio.create_task(sched.run(fetcher, on_image, on_event_q))
    while True:
        if task.done() and queue.empty():
            break
        try:
            ev = await asyncio.wait_for(queue.get(), timeout=0.25)
        except asyncio.TimeoutError:
            continue
        yield ev
    counters = await task

    ledger.append(
        "CRAWL_DONE",
        {"matches": len(matcher.matches), "text_hits": len(text_hits), **counters},
    )
    report = {
        "matches": [
            {
                "id": m.id,
                "page_url": m.page_url,
                "image_url": m.image_url,
                "kind": m.kind,
                "pdq_distance": m.pdq_distance,
                "similarity": m.similarity,
                "band": m.band,
                "verdict": m.verdict,
                "region": m.region,
                "sha256": m.sha256,
                "status": m.status,
                "thumb_b64": __import__("base64").b64encode(m.thumb_jpeg).decode(),
            }
            for m in matcher.matches
        ],
        "text_hits": text_hits,
        "counters": counters,
    }
    yield {"kind": "done", "report": {"scout": report}}


def wipe(session_state: dict, ledger: Ledger | None = None):
    session_state.pop("enrolled", None)
    for m in session_state.get("matches", []):
        m.thumb_jpeg = b""
    if ledger:
        ledger.append("SESSION_WIPED", {"ok": True})

