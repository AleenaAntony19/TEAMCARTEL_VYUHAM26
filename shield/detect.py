from __future__ import annotations

import re

from .models import Entity, RankedEntity, SeverityFactors

# ---------- Verhoeff ----------
_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def verhoeff_valid(s: str) -> bool:
    s = _digits(s)
    if not s:
        return False
    c = 0
    for i, ch in enumerate(reversed(s)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(s: str) -> int:
    s = _digits(s)
    c = 0
    for i, ch in enumerate(reversed(s)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return _INV[c]


def luhn_valid(s: str) -> bool:
    s = _digits(s)
    if not (13 <= len(s) <= 19):
        return False
    total = 0
    for i, ch in enumerate(reversed(s)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ---------- patterns ----------
PATTERNS: dict[str, re.Pattern] = {
    "IN_AADHAAR": re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b"),
    "IN_PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "IN_UPI": re.compile(
        r"(?<![\w.])[\w.\-]{2,256}@(?:okaxis|oksbi|okicici|okhdfcbank|ybl|ibl|axl|paytm|upi|apl|axisbank|sbi|icici|hdfcbank)\b(?![\w.])",
        re.I,
    ),
    "IN_IFSC": re.compile(
        r"\b(?:SBIN|HDFC|ICIC|PUNB|KKBK|BARB|UTIB|CNRB|UBIN|IDIB|BKID|YESB)0[A-Z0-9]{6}\b"
    ),
    "MOBILE_IN": re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"),
    "EMAIL_ADDRESS": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "IN_BANK_ACCOUNT": re.compile(r"\b\d{9,18}\b"),
    "PERSON": re.compile(
        r"(?:Employee[ \t]+Name:?|Employee(?:[ \t]+ID)?:?|Name[ \t]*:|Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Shri|Smt\.?)[ \t]+"
        r"([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){0,2})"  # names never span lines
    ),
    "ORG": re.compile(r"\b[A-Z][A-Za-z&]+(?:\s+(?:Corp|Ltd|Inc|Pvt|LLP|Bank|Technologies|Solutions))\b"),
    "DATE_TIME": re.compile(r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})\b"),
}


def detect(text: str, layer: str = "visible") -> list[Entity]:
    if not text:
        return []
    cands: list[Entity] = []

    for typ, pat in PATTERNS.items():
        for m in pat.finditer(text):
            val = m.group(0)
            score = 0.60
            if typ == "IN_AADHAAR":
                if not verhoeff_valid(val):
                    continue
                score = 0.99
            elif typ == "IN_PAN":
                score = 0.95
            elif typ == "IN_UPI":
                score = 0.95
            elif typ == "IN_IFSC":
                score = 0.95
            elif typ == "MOBILE_IN":
                score = 0.85
            elif typ == "EMAIL_ADDRESS":
                score = 0.90
            elif typ == "CREDIT_CARD":
                if not luhn_valid(val):
                    continue
                score = 0.95
            elif typ == "IN_BANK_ACCOUNT":
                ctx = text[max(0, m.start() - 40) : m.end() + 40].lower()
                if not any(k in ctx for k in ("account", "a/c", "acct", "bank")):
                    continue
                score = 0.55
            elif typ == "PERSON":
                val = m.group(1).strip()
                if val in {"Name", "Employee", "Organisation", "Company", "Title", "Date", "Address"}:
                    continue
                score = 0.70
                cands.append(Entity(typ, val, m.start(1), m.end(1), score, layer))
                continue
            elif typ == "ORG":
                score = 0.50
            elif typ == "DATE_TIME":
                score = 0.50

            cands.append(Entity(typ, val, m.start(), m.end(), score, layer))

    cands = [c for c in cands if c.score >= 0.40]

    # exact dedupe
    seen = set()
    uniq: list[Entity] = []
    for c in cands:
        key = (c.type, c.value, c.start, c.end)
        if key not in seen:
            seen.add(key)
            uniq.append(c)

    # overlap: highest score wins
    uniq.sort(key=lambda e: (-e.score, -(e.end - e.start), e.start))
    chosen: list[Entity] = []
    for e in uniq:
        if not any(not (e.end <= o.start or e.start >= o.end) for o in chosen):
            chosen.append(e)
    chosen.sort(key=lambda e: (e.start, e.end))
    return chosen


def variants(value: str) -> set[str]:
    out = {value}
    stripped = re.sub(r"[\s\-]", "", value)
    out.add(stripped)
    if len(stripped) == 12 and stripped.isdigit():
        out.add(f"{stripped[:4]} {stripped[4:8]} {stripped[8:]}")
        out.add(f"{stripped[:4]}-{stripped[4:8]}-{stripped[8:]}")
    if len(stripped) == 10 and stripped.isdigit():
        out.add(f"+91 {stripped[:5]} {stripped[5:]}")
        out.add(f"+91-{stripped[:5]}-{stripped[5:]}")
        out.add(f"+91{stripped}")
    return {v for v in out if v}


ACTIONS = ("token", "mask", "remove")


def replacement(e: Entity, matched: str) -> str:
    """Text that replaces `matched` (one variant of e.value) under the entity's action."""
    if e.action == "remove":
        return ""
    if e.action == "mask":
        return "".join("X" if c.isalnum() else c for c in matched)
    return f"[REDACTED-{e.type}]"


# ---------- 5-Factor Privacy Severity & Ranking Engine ----------
# Weights: Intrinsic Sensitivity (30%), Exploitability (20%), Linkability (25%), Exposure Context (15%), Frequency (10%)
WEIGHT_SENSITIVITY = 0.30
WEIGHT_EXPLOITABILITY = 0.20
WEIGHT_LINKABILITY = 0.25
WEIGHT_CONTEXT = 0.15
WEIGHT_FREQUENCY = 0.10

INTRINSIC_SENSITIVITY: dict[str, float] = {
    "FACE": 100.0,
    "IN_AADHAAR": 100.0,
    "CREDIT_CARD": 95.0,
    "IN_BANK_ACCOUNT": 90.0,
    "IN_PAN": 85.0,
    "IN_PASSPORT": 85.0,
    "IN_UPI": 75.0,
    "IN_IFSC": 60.0,
    "IN_GSTIN": 55.0,
    "MOBILE_IN": 60.0,
    "EMAIL_ADDRESS": 50.0,
    "PERSON": 30.0,
    "LOCATION": 25.0,
    "ORG": 20.0,
    "DATE_TIME": 15.0,
}

EXPLOITABILITY: dict[str, float] = {
    "CREDIT_CARD": 95.0,
    "IN_UPI": 90.0,
    "IN_AADHAAR": 90.0,
    "IN_BANK_ACCOUNT": 85.0,
    "IN_PAN": 75.0,
    "IN_PASSPORT": 70.0,
    "FACE": 70.0,
    "MOBILE_IN": 65.0,
    "EMAIL_ADDRESS": 50.0,
    "IN_GSTIN": 45.0,
    "IN_IFSC": 40.0,
    "PERSON": 25.0,
    "LOCATION": 15.0,
    "ORG": 15.0,
    "DATE_TIME": 15.0,
}


def mask_value(value: str, entity_type: str) -> str:
    """Mask sensitive value for privacy-safe reporting and logs."""
    if not value:
        return ""
    val = value.strip()
    if entity_type == "FACE":
        return "[BIOMETRIC EMBEDDING]"
    if entity_type == "IN_AADHAAR":
        digits = re.sub(r"\D", "", val)
        if len(digits) == 12:
            return f"XXXX XXXX {digits[-4:]}"
        return "XXXX XXXX " + val[-4:] if len(val) >= 4 else "****"
    if entity_type == "IN_PAN":
        if len(val) == 10:
            return f"{val[:2]}****{val[-1]}"
        return val[:2] + "****" if len(val) >= 2 else "****"
    if entity_type == "CREDIT_CARD":
        digits = re.sub(r"\D", "", val)
        if len(digits) >= 4:
            return f"****-****-****-{digits[-4:]}"
        return "****-****-****-****"
    if entity_type == "IN_BANK_ACCOUNT":
        if len(val) > 4:
            return "*" * (len(val) - 4) + val[-4:]
        return "****"
    if entity_type == "MOBILE_IN":
        digits = re.sub(r"\D", "", val)
        if len(digits) >= 10:
            return f"+91 {digits[-10:-7]}*** **{digits[-2:]}"
        return val[:4] + "****" if len(val) >= 4 else "****"
    if entity_type == "EMAIL_ADDRESS":
        if "@" in val:
            user, domain = val.split("@", 1)
            masked_user = f"{user[0]}***{user[-1]}" if len(user) > 2 else user[:1] + "***"
            return f"{masked_user}@{domain}"
        return val[:2] + "***"
    if entity_type == "IN_UPI":
        if "@" in val:
            user, domain = val.split("@", 1)
            masked_user = f"{user[0]}***" if user else "***"
            return f"{masked_user}@{domain}"
        return val[:2] + "***"
    if entity_type == "PERSON":
        parts = val.split()
        masked_parts = [f"{p[0]}***" if p else "*" for p in parts]
        return " ".join(masked_parts)
    if len(val) > 4:
        return f"{val[:2]}****{val[-2:]}"
    return "****"


def _calc_linkability(typ: str, types: set[str]) -> float:
    has_person = "PERSON" in types
    has_contact = bool({"MOBILE_IN", "EMAIL_ADDRESS"} & types)
    has_gov_id = bool({"IN_AADHAAR", "IN_PAN", "IN_PASSPORT"} & types)
    has_finance = bool({"IN_BANK_ACCOUNT", "CREDIT_CARD", "IN_UPI"} & types)
    has_datetime = "DATE_TIME" in types
    has_ifsc = "IN_IFSC" in types

    if typ == "IN_AADHAAR":
        return 100.0 if (has_person or has_contact) else (90.0 if has_finance else 70.0)
    if typ == "IN_PAN":
        if has_person and has_datetime:
            return 100.0
        return 90.0 if (has_person or has_contact) else 65.0
    if typ == "IN_BANK_ACCOUNT":
        if has_ifsc and has_person:
            return 100.0
        return 85.0 if (has_ifsc or has_person) else 55.0
    if typ == "CREDIT_CARD":
        return 95.0 if has_person else 75.0
    if typ == "IN_UPI":
        return 85.0 if (has_person or has_contact) else 60.0
    if typ == "FACE":
        return 100.0 if has_person else (90.0 if has_gov_id else 70.0)
    if typ in ("MOBILE_IN", "EMAIL_ADDRESS"):
        return 90.0 if has_person else (80.0 if (has_gov_id or has_finance) else (50.0 if len(types) > 1 else 30.0))
    if typ == "PERSON":
        return 95.0 if (has_gov_id or has_finance) else (80.0 if has_contact else (40.0 if len(types) > 1 else 20.0))
    if typ == "IN_IFSC":
        return 80.0 if has_finance else 30.0
    return 50.0 if (has_person or has_gov_id) else 20.0


def _calc_exposure_context(layer: str) -> float:
    l = (layer or "visible").lower()
    if any(k in l for k in ("metadata", "exif", "gps")):
        return 100.0
    if any(k in l for k in ("embedded", "hidden", "veryhidden", "del")):
        return 95.0
    if any(k in l for k in ("annotation", "comment")):
        return 80.0
    if "ocr" in l:
        return 70.0
    if "bbox" in l:
        return 75.0
    return 65.0


def _calc_frequency(count: int) -> float:
    if count <= 1:
        return 40.0
    if count == 2:
        return 60.0
    if count == 3:
        return 80.0
    return 100.0


def _get_band(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 10:
        return "LOW"
    return "NONE"


class SeverityResult(tuple):
    score: int
    band: str
    types: list[str]
    ranked_entities: list[RankedEntity]

    def __new__(
        cls,
        score: int,
        band: str,
        types: list[str],
        ranked_entities: list[RankedEntity] | None = None,
    ):
        instance = super().__new__(cls, (score, band, types))
        instance.score = score
        instance.band = band
        instance.types = types
        instance.ranked_entities = ranked_entities or []
        return instance


def rank_entities(entities: list[Entity]) -> list[RankedEntity]:
    if not entities:
        return []

    types = {e.type for e in entities}
    # Group entities by (type, value) to calculate frequency and find highest risk exposure context
    groups: dict[tuple[str, str], list[Entity]] = {}
    for e in entities:
        key = (e.type, e.value)
        groups.setdefault(key, []).append(e)

    ranked: list[RankedEntity] = []
    for (typ, val), items in groups.items():
        occ = len(items)
        # pick highest exposure context layer
        best_layer = "visible"
        best_c = 0.0
        for it in items:
            c = _calc_exposure_context(it.layer)
            if c > best_c:
                best_c = c
                best_layer = it.layer

        s = INTRINSIC_SENSITIVITY.get(typ, 25.0)
        e = EXPLOITABILITY.get(typ, 20.0)
        l = _calc_linkability(typ, types)
        c = best_c
        f = _calc_frequency(occ)

        # Contextual boosts for critical combinations
        if typ == "IN_PAN" and "PERSON" in types and "DATE_TIME" in types:
            s = max(s, 90.0)
            e = max(e, 95.0)
            l = 100.0
        elif typ == "IN_BANK_ACCOUNT" and "IN_IFSC" in types:
            e = max(e, 95.0)
            l = max(l, 95.0)
        elif typ == "CREDIT_CARD" and "PERSON" in types:
            s = max(s, 98.0)
            e = max(e, 95.0)
            l = max(l, 95.0)

        raw_score = (
            WEIGHT_SENSITIVITY * s
            + WEIGHT_EXPLOITABILITY * e
            + WEIGHT_LINKABILITY * l
            + WEIGHT_CONTEXT * c
            + WEIGHT_FREQUENCY * f
        )
        final_score = round(raw_score, 2)
        band = _get_band(final_score)

        factors = SeverityFactors(
            intrinsic_sensitivity=s,
            exploitability=e,
            linkability=l,
            exposure_context=c,
            frequency=f,
        )
        ranked.append(
            RankedEntity(
                rank=1,  # will be assigned after sorting
                entity_type=typ,
                value=val,
                masked_value=mask_value(val, typ),
                severity_score=final_score,
                band=band,
                factors=factors,
                occurrences=occ,
                layer=best_layer,
            )
        )

    # Sort descending by severity score, then sensitivity, then exploitability
    ranked.sort(
        key=lambda r: (
            -r.severity_score,
            -r.factors.intrinsic_sensitivity,
            -r.factors.exploitability,
            r.entity_type,
        )
    )
    for idx, r in enumerate(ranked, 1):
        r.rank = idx

    return ranked


def severity(entities: list[Entity]) -> SeverityResult:
    types = {e.type for e in entities}
    if not types:
        return SeverityResult(0, "NONE", [], [])

    ranked = rank_entities(entities)
    top_score = max(r.severity_score for r in ranked) if ranked else 0.0

    # Ensure document score reflects compounding critical combinations
    doc_score = int(round(top_score))
    if any(
        (
            "IN_AADHAAR" in types,
            "CREDIT_CARD" in types,
            ("IN_BANK_ACCOUNT" in types and "IN_IFSC" in types),
            ("IN_PAN" in types and "PERSON" in types and "DATE_TIME" in types),
        )
    ):
        doc_score = max(doc_score, 85)
    elif any(
        (
            ("MOBILE_IN" in types and "PERSON" in types),
            "IN_PAN" in types,
            "IN_PASSPORT" in types,
            "IN_UPI" in types,
        )
    ):
        doc_score = max(doc_score, 65)
    elif any(("MOBILE_IN" in types, "EMAIL_ADDRESS" in types, "IN_GSTIN" in types)):
        doc_score = max(doc_score, 50)
    elif any(("PERSON" in types, "LOCATION" in types)):
        doc_score = max(doc_score, 25)

    band = _get_band(doc_score)
    return SeverityResult(doc_score, band, sorted(types), ranked)
