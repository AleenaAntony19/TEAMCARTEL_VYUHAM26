from __future__ import annotations

from pathlib import Path

from shield.detect import detect

from .fix import FAKE_VALUES
from . import Finding, evidence, fingerprint, mask, record_error

KEEP = {"IN_AADHAAR", "IN_PAN", "IN_GSTIN", "IN_PASSPORT", "IN_UPI", "IN_BANK_ACCOUNT", "CREDIT_CARD", "EMAIL_ADDRESS", "MOBILE_IN", "GEO_COORDINATES"}


def scan_pii(files: list[Path], root: Path, existing: list[Finding] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(errors="ignore")
        except OSError as exc:
            record_error(rel, "pii", exc)
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            for ent in detect(line):
                if ent.type not in KEEP or ent.value == FAKE_VALUES.get(ent.type):
                    continue  # our own synthetic test values (fake_pii) are not findings
                if ent.type == "EMAIL_ADDRESS" and any(
                    d in ent.value for d in ("example.com", ".test", "noreply")
                ):
                    continue
                out.append(
                    Finding(
                        id=fingerprint(ent.type, rel, line, ent.value),
                        engine="pii",
                        rule=ent.type,
                        severity="critical" if ent.type == "IN_AADHAAR" else "high",
                        file=rel,
                        line=i,
                        col=ent.start + 1,
                        end_line=i,
                        end_col=ent.end + 1,
                        message=f"{ent.type} in source",
                        masked=mask(ent.value, ent.type),
                        fixes=["fake_pii", "redact_pii", "ignore"],
                        confidence=round(ent.score, 2),
                        evidence=evidence(line, ent.value, ent.type),
                    )
                )
    return out

