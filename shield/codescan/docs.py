"""PDF/DOCX/XLSX in the workspace: every layer (text, comments, hidden sheets, metadata) plus OCR of embedded images."""
from __future__ import annotations

from pathlib import Path

from shield.detect import detect

from . import Finding, evidence, fingerprint, mask, record_error

KEEP = {"IN_AADHAAR", "IN_PAN", "IN_GSTIN", "IN_PASSPORT", "IN_UPI", "IN_BANK_ACCOUNT", "CREDIT_CARD", "EMAIL_ADDRESS", "MOBILE_IN"}


def _embedded_ocr(path: Path) -> str:
    import pytesseract
    from PIL import Image

    from shield.profile import extract_images

    return "\n".join(pytesseract.image_to_string(Image.fromarray(img[:, :, ::-1])) for _, img, _ in extract_images(path))


def scan_documents(files: list[Path], root: Path, ocr: bool = True) -> list[Finding]:
    from shield.profile import layer_texts

    out: list[Finding] = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            layers = layer_texts(path)
        except Exception as exc:
            record_error(rel, "document", exc)
            continue
        if ocr:
            try:
                layers["embedded_image_ocr"] = _embedded_ocr(path)
            except Exception as exc:
                record_error(rel, "ocr", exc)
        for layer, text in layers.items():
            for ent in detect(text):
                if ent.type not in KEEP or (ent.type == "EMAIL_ADDRESS" and "example." in ent.value):
                    continue
                ctx = text[max(0, ent.start - 40) : ent.end + 40]
                out.append(Finding(
                    fingerprint(ent.type, rel, f"{layer}:{ctx}", ent.value), "document", ent.type,
                    "critical" if ent.type in {"IN_AADHAAR", "CREDIT_CARD", "IN_BANK_ACCOUNT"} else "high",
                    rel, 0, 0, 0, 0, f"{ent.type} in document layer '{layer}'", mask(ent.value, ent.type), ["ignore"],
                    confidence=round(ent.score, 2), evidence=evidence(ctx, ent.value, ent.type),
                ))
    return out
