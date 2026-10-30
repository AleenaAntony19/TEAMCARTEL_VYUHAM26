from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Tuple

from .detect import verhoeff_valid, luhn_valid, variants
from .models import Entity


@dataclass
class DebateTurn:
    persona: str
    avatar: str
    action: str  # "PROPOSAL" | "CHALLENGE" | "DEFENSE" | "VERDICT"
    argument: str
    confidence: float


@dataclass
class DebateLog:
    entity_val: str
    initial_type: str
    turns: List[DebateTurn] = field(default_factory=list)
    final_verdict: str = "CONFIRMED"  # "CONFIRMED" | "OVERRULED" | "RECLASSIFIED"
    final_type: str = ""
    final_score: float = 0.0


def _context_slice(text: str, start: int, end: int, window: int = 50) -> str:
    s = max(0, start - window)
    e = min(len(text), end + window)
    return text[s:e].lower()


def deliberate_entity(entity: Entity, full_text: str) -> Tuple[Entity | None, DebateLog]:
    log = DebateLog(
        entity_val=entity.value,
        initial_type=entity.type,
        final_type=entity.type,
        final_score=entity.score,
    )
    ctx = _context_slice(full_text, entity.start, entity.end)

    # 1. Round 1: Privacy Hawk proposals
    log.turns.append(
        DebateTurn(
            persona="PrivacyHawk",
            avatar="🦅",
            action="PROPOSAL",
            argument=f"Flagged potential sensitive entity {entity.type} ('{entity.value}') with initial score {entity.score:.2f}.",
            confidence=entity.score,
        )
    )

    # Fast-path for mathematically verified high-confidence sovereign entities
    if entity.type == "IN_AADHAAR" and verhoeff_valid(entity.value):
        log.turns.append(
            DebateTurn(
                persona="StatutoryAuditor",
                avatar="⚖️",
                action="DEFENSE",
                argument="Mathematical Verhoeff checksum verified. This is a sovereign UIDAI identifier under mandatory DPDP 2023 protection.",
                confidence=0.99,
            )
        )
        log.turns.append(
            DebateTurn(
                persona="SwarmAdjudicator",
                avatar="🧠",
                action="VERDICT",
                argument="Mathematical checksum conclusive. Immediate object-level redaction approved.",
                confidence=0.99,
            )
        )
        log.final_verdict = "CONFIRMED"
        log.final_type = "IN_AADHAAR"
        log.final_score = 0.99
        return Entity(entity.type, entity.value, entity.start, entity.end, 0.99, entity.layer), log

    # Check for Documentation Mocks / Benign Developer Placeholders
    if entity.type == "EMAIL_ADDRESS":
        is_mock = any(d in entity.value.lower() for d in ("example.com", ".test", "sample.com", "placeholder", "fake"))
        if is_mock:
            log.turns.append(
                DebateTurn(
                    persona="PragmaticDev",
                    avatar="💻",
                    action="CHALLENGE",
                    argument=f"Domain '{entity.value.split('@')[-1]}' is a standardized RFC 2606 mock documentation domain. Not a live privacy leak.",
                    confidence=0.95,
                )
            )
            log.turns.append(
                DebateTurn(
                    persona="SwarmAdjudicator",
                    avatar="🧠",
                    action="VERDICT",
                    argument="Overruled: Documentation placeholder domain detected. Excluded from redaction to preserve code/doc readability.",
                    confidence=0.10,
                )
            )
            log.final_verdict = "OVERRULED"
            log.final_score = 0.10
            return None, log

    # Check for 12-digit number ambiguity (Invoice / Order ID vs Aadhaar)
    digits_only = re.sub(r"\D", "", entity.value)
    if len(digits_only) == 12 and not verhoeff_valid(entity.value):
        is_invoice = any(k in ctx for k in ("inv", "invoice", "order", "txn", "ref", "bill", "shipment", "item"))
        if is_invoice:
            log.turns.append(
                DebateTurn(
                    persona="PragmaticDev",
                    avatar="💻",
                    action="CHALLENGE",
                    argument=f"Value '{entity.value}' appears in commercial invoice/order context ('{ctx[:40]}...').",
                    confidence=0.85,
                )
            )
            log.turns.append(
                DebateTurn(
                    persona="StatutoryAuditor",
                    avatar="⚖️",
                    action="DEFENSE",
                    argument="Verhoeff dihedral checksum test executed = INVALID. Statutory UIDAI identity rules do not apply.",
                    confidence=0.90,
                )
            )
            log.turns.append(
                DebateTurn(
                    persona="SwarmAdjudicator",
                    avatar="🧠",
                    action="VERDICT",
                    argument="Checksum failure + invoice context confirms business ID. Downclassified to non-PII invoice reference.",
                    confidence=0.20,
                )
            )
            log.final_verdict = "OVERRULED"
            log.final_score = 0.20
            return None, log

    # Check for Credit Card Luhn verification
    if entity.type == "CREDIT_CARD":
        if not luhn_valid(entity.value):
            log.turns.append(
                DebateTurn(
                    persona="PragmaticDev",
                    avatar="💻",
                    action="CHALLENGE",
                    argument="Luhn Mod-10 algorithm check failed. This is a sequence of numbers, not an active payment card.",
                    confidence=0.90,
                )
            )
            log.turns.append(
                DebateTurn(
                    persona="SwarmAdjudicator",
                    avatar="🧠",
                    action="VERDICT",
                    argument="Mathematical checksum failure. Discarding invalid card candidate.",
                    confidence=0.15,
                )
            )
            log.final_verdict = "OVERRULED"
            log.final_score = 0.15
            return None, log
        else:
            log.turns.append(
                DebateTurn(
                    persona="StatutoryAuditor",
                    avatar="⚖️",
                    action="DEFENSE",
                    argument="Luhn Mod-10 algorithm PASSED. Severe PCI-DSS and financial fraud risk.",
                    confidence=0.95,
                )
            )
            log.turns.append(
                DebateTurn(
                    persona="SwarmAdjudicator",
                    avatar="🧠",
                    action="VERDICT",
                    argument="Verified payment card number. Immediate object-level redaction confirmed.",
                    confidence=0.95,
                )
            )
            log.final_verdict = "CONFIRMED"
            log.final_score = 0.95
            return Entity(entity.type, entity.value, entity.start, entity.end, 0.95, entity.layer), log

    # Default fallback: Privacy Hawk mandate applies for any surviving high-risk categories
    log.turns.append(
        DebateTurn(
            persona="StatutoryAuditor",
            avatar="⚖️",
            action="DEFENSE",
            argument=f"Entity {entity.type} carries statutory liability under data protection regulations.",
            confidence=entity.score,
        )
    )
    log.turns.append(
        DebateTurn(
            persona="SwarmAdjudicator",
            avatar="🧠",
            action="VERDICT",
            argument="No disqualifying non-PII evidence found. Redaction confirmed under precautionary principle.",
            confidence=entity.score,
        )
    )
    log.final_verdict = "CONFIRMED"
    return entity, log


def deliberate(entities: list[Entity], full_text: str) -> Tuple[list[Entity], list[DebateLog]]:
    """
    Executes multi-persona dialectic deliberation over detected entities.
    Returns the consensus-approved entity list and complete debate audit logs.
    """
    confirmed_entities: list[Entity] = []
    logs: list[DebateLog] = []

    for ent in entities:
        if ent.type == "FACE":
            confirmed_entities.append(ent)
            continue

        resolved, log = deliberate_entity(ent, full_text)
        logs.append(log)
        if resolved is not None:
            confirmed_entities.append(resolved)

    return confirmed_entities, logs

