from __future__ import annotations

from pathlib import Path

from shield.detect import detect

from . import Finding, fingerprint, mask

KEEP = {"IN_AADHAAR", "IN_PAN", "IN_GSTIN", "IN_PASSPORT", "IN_UPI", "IN_BANK_ACCOUNT", "CREDIT_CARD", "EMAIL_ADDRESS", "MOBILE_IN"}


def scan_pii(files: list[Path], root: Path, existing: list[Finding] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            for ent in detect(line):
                if ent.type not in KEEP:
                    continue
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
                    )
                )
    return out

