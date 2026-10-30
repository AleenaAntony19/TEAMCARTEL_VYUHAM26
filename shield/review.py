"""Deterministic persona deliberation over detector output (max 2 rounds, no loops, no LLM).

Round 1
  PrivacyHawk      CLAIM      records the detector match (precautionary: keep unless disproved)
  PragmaticDev     CHALLENGE  RFC 2606 / mock e-mail domains; invoice/order context near a non-ID number
  StatutoryAuditor CHECK      Verhoeff (Aadhaar, D5 dihedral group) and Luhn mod-10 (cards); cites DPDP 2023
Round 2
  SwarmAdjudicator VERDICT    Rule of Mathematical Superiority: a checksum result overrides context
                              arguments; otherwise an upheld challenge dismisses; otherwise keep.
Every turn names the rule it ran and carries masked evidence. Personas are labelled rule sets,
not free text generation, so the "dialogue" is reproducible and auditable.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterator

from .detect import luhn_valid, verhoeff_valid
from .models import Entity

MOCK_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", ".test", ".invalid", "sample.com", "placeholder", "fake")
NON_ID_CONTEXT = ("inv", "invoice", "order", "txn", "ref", "bill", "shipment", "item")
MAX_ROUNDS = 2
PERSONAS = {
    "PrivacyHawk": "🦅",
    "PragmaticDev": "💻",
    "StatutoryAuditor": "⚖️",
    "SwarmAdjudicator": "🧠",
}
# SwarmAdjudicator always runs; the others can be switched off (comma list)
ENABLED = {p for p in os.getenv("SHIELD_PERSONAS", ",".join(PERSONAS)).split(",") if p in PERSONAS} | {"SwarmAdjudicator"}


def mask_value(value: str) -> str:
    """Show only the last 4 alphanumerics; never the full value."""
    keep = 4 if len(value) > 8 else 0
    head = "".join("•" if c.isalnum() else c for c in value[: len(value) - keep])
    return head + value[len(value) - keep :]


@dataclass
class Check:
    reviewer: str  # persona name
    rule: str
    passed: bool  # True = supports keeping the entity
    evidence: str
    round: int = 1
    action: str = "CHECK"  # CLAIM | CHALLENGE | CHECK | VERDICT
    avatar: str = ""


@dataclass
class ReviewRecord:
    type: str
    masked: str
    verdict: str = "confirmed"  # confirmed | dismissed
    confidence: float = 0.0
    checks: list[Check] = field(default_factory=list)
    location: str = ""  # layer:start-end of the entity


def review_entity(entity: Entity, full_text: str) -> tuple[Entity | None, ReviewRecord]:
    loc = f"{entity.layer}:{entity.start}-{entity.end}"
    rec = ReviewRecord(entity.type, mask_value(entity.value), confidence=entity.score, location=loc)
    ctx = full_text[max(0, entity.start - 50) : entity.end + 50].lower()
    digits = re.sub(r"\D", "", entity.value)

    def turn(persona: str, action: str, rule: str, passed: bool, evidence: str, rnd: int = 1):
        if persona in ENABLED:
            rec.checks.append(Check(persona, rule, passed, evidence, rnd, action, PERSONAS[persona]))

    # ---- round 1 ----
    turn("PrivacyHawk", "CLAIM", "detector_match", True, f"{entity.type} pattern matched at {loc} (score {entity.score:.2f}); keep unless disproved")

    challenge: str | None = None
    if entity.type == "EMAIL_ADDRESS":
        domain = entity.value.split("@")[-1].lower()
        mock = next((d for d in MOCK_EMAIL_DOMAINS if d in domain), None)
        if mock:
            challenge = f"domain matches reserved/mock '{mock}' (RFC 2606)"
        turn("PragmaticDev", "CHALLENGE", "mock_email_domain", mock is None, challenge or "domain is not a documentation placeholder")

    checksum: bool | None = None
    if entity.type == "CREDIT_CARD":
        checksum = luhn_valid(entity.value)
        turn("StatutoryAuditor", "CHECK", "luhn", checksum, "Luhn mod-10 passed: card data (PCI-DSS)" if checksum else "Luhn mod-10 failed")
    if len(digits) == 12 and entity.type in {"IN_AADHAAR", "IN_BANK_ACCOUNT"}:
        ok = verhoeff_valid(digits)
        turn("StatutoryAuditor", "CHECK", "verhoeff", ok, "Verhoeff (D5) checksum passed: Aadhaar is personal data under DPDP Act 2023" if ok else "Verhoeff (D5) checksum failed")
        if entity.type == "IN_AADHAAR":
            checksum = ok
            if not ok:
                hit = next((k for k in NON_ID_CONTEXT if k in ctx), None)
                if hit:
                    challenge = f"nearby keyword '{hit}' suggests an invoice/order reference"
                turn("PragmaticDev", "CHALLENGE", "non_id_context", hit is None, challenge or "no invoice/order keyword nearby")

    # ---- round 2 (final; MAX_ROUNDS = 2) ----
    if checksum is not None and "StatutoryAuditor" in ENABLED:
        keep, why = checksum, "checksum decides (Rule of Mathematical Superiority)"
    elif challenge and "PragmaticDev" in ENABLED:
        keep, why = False, f"challenge upheld: {challenge}"
    else:
        keep, why = True, "no disproof; precautionary keep"
    if checksum:
        rec.confidence = max(rec.confidence, 0.99 if entity.type == "IN_AADHAAR" else 0.95)
    elif not keep:
        rec.confidence = 0.15 if challenge else 0.05
    turn("SwarmAdjudicator", "VERDICT", "adjudication", keep, f"{'CONFIRMED' if keep else 'DISMISSED'} at {loc}: {why}", MAX_ROUNDS)

    if not keep:
        rec.verdict = "dismissed"
        return None, rec
    return Entity(entity.type, entity.value, entity.start, entity.end, rec.confidence, entity.layer, entity.action), rec


def _text_for(ent: Entity, texts: str | dict[str, str]) -> str:
    return texts if isinstance(texts, str) else texts.get(ent.layer, "")


def review(entities: list[Entity], texts: str | dict[str, str]) -> tuple[list[Entity], list[ReviewRecord]]:
    """`texts` is one string, or layer name -> text (entity offsets are per layer)."""
    kept: list[Entity] = []
    records: list[ReviewRecord] = []
    for ent in entities:
        if ent.type == "FACE":
            kept.append(ent)
            continue
        resolved, rec = review_entity(ent, _text_for(ent, texts))
        records.append(rec)
        if resolved is not None:
            kept.append(resolved)
    return kept, records


def deliberate_stream(entities: list[Entity], texts: str | dict[str, str]) -> Iterator[dict]:
    """Turn-by-turn events as each entity is deliberated (for SSE/WebSocket dashboards)."""
    yield {"event": "start", "entities": sum(e.type != "FACE" for e in entities), "max_rounds": MAX_ROUNDS}
    for i, ent in enumerate(e for e in entities if e.type != "FACE"):
        _, rec = review_entity(ent, _text_for(ent, texts))
        for c in rec.checks:
            yield {"event": "turn", "entity": i, "type": rec.type, "masked": rec.masked, **c.__dict__}
        yield {"event": "verdict", "entity": i, "type": rec.type, "masked": rec.masked, "verdict": rec.verdict, "confidence": rec.confidence, "location": rec.location}
    yield {"event": "end"}
