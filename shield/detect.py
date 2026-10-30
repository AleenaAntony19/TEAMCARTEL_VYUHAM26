from __future__ import annotations

import re

from .models import Entity

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


def severity(entities: list[Entity]) -> tuple[int, str, list[str]]:
    types = {e.type for e in entities}
    if not types:
        return 0, "NONE", []

    score = 0
    if "PERSON" in types:
        score = max(score, 25)
    if "LOCATION" in types:
        score = max(score, 25)
    if "IN_GSTIN" in types:
        score = max(score, 50)
    if "MOBILE_IN" in types:
        score = max(score, 50)
    if "EMAIL_ADDRESS" in types:
        score = max(score, 50)
    if "IN_UPI" in types:
        score = max(score, 75)
    if "IN_PASSPORT" in types:
        score = max(score, 75)
    if "IN_PAN" in types:
        score = max(score, 75)
    if "MOBILE_IN" in types and "PERSON" in types:
        score = max(score, 75)
    if "IN_PAN" in types and "PERSON" in types and "DATE_TIME" in types:
        score = max(score, 95)
    if "IN_BANK_ACCOUNT" in types and "IN_IFSC" in types:
        score = max(score, 95)
    if "CREDIT_CARD" in types:
        score = max(score, 95)
    if "IN_AADHAAR" in types:
        score = max(score, 95)

    if score >= 85:
        band = "CRITICAL"
    elif score >= 65:
        band = "HIGH"
    elif score >= 40:
        band = "MEDIUM"
    elif score >= 10:
        band = "LOW"
    else:
        band = "NONE"
    return score, band, sorted(types)

