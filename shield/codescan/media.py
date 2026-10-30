from __future__ import annotations

from pathlib import Path

import cv2
import numpy as np
from PIL import Image

from shield import face, pdq
from shield.redact.image import ocr_words
from shield.detect import detect

from . import Finding, fingerprint, mask, record_error

BANK_REL = Path(".shield/bank.json")  # team-shared PDQ hashes (no pixels), relative to the scan root


def _bank(root: Path = Path(".")) -> pdq.HashBank:
    path = root / BANK_REL
    return pdq.HashBank.load(path) if path.exists() else pdq.HashBank()


def bank_add(path: Path, label: str, root: Path = Path(".")):
    (root / BANK_REL).parent.mkdir(parents=True, exist_ok=True)
    bank = _bank(root)
    img = cv2.imread(str(path))
    if img is None:
        raise ValueError(f"cannot read image {path}")
    bank.add_reference(path.name, label, cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
    bank.save(root / BANK_REL)


def bank_list(root: Path = Path(".")):
    return [{"id": m["id"], "label": m["label"], "region": m["region"]} for m in _bank(root)._meta]


def bank_rm(path: str, root: Path = Path(".")):
    bank = _bank(root)
    keep = [(r, m) for r, m in zip(bank._rows, bank._meta) if m["id"] != path]
    bank._rows = [r for r, _ in keep]
    bank._meta = [m for _, m in keep]
    bank.save(root / BANK_REL)


OCR_TYPES = {"IN_AADHAAR", "IN_PAN", "IN_UPI", "IN_IFSC", "MOBILE_IN", "CREDIT_CARD", "EMAIL_ADDRESS"}


def _ocr_findings(path: Path, rel: str) -> list[Finding]:
    """One finding per OCR'd value, pointing at the words' bounding box."""
    words = ocr_words(path)
    text, spans, pos = "", [], 0
    for w, box in words:
        spans.append((pos, pos + len(w), box))
        text += w + " "
        pos += len(w) + 1
    out = []
    for ent in detect(text):
        if ent.type not in OCR_TYPES:
            continue
        boxes = [b for a, z, b in spans if a < ent.end and z > ent.start]
        x0, y0 = min(b[0] for b in boxes), min(b[1] for b in boxes)
        x1, y1 = max(b[0] + b[2] for b in boxes), max(b[1] + b[3] for b in boxes)
        out.append(Finding(
            fingerprint("OCR_PII", rel, f"{ent.type}@{x0},{y0}", ent.value), "media", "OCR_PII",
            "critical" if ent.type in {"IN_AADHAAR", "CREDIT_CARD"} else "high", rel, 0, 0, 0, 0,
            f"{ent.type} visible in image (OCR) at x={x0} y={y0} w={x1 - x0} h={y1 - y0}", mask(ent.value, ent.type),
            ["redact_image", "hash_pdq", "ignore"], confidence=round(min(ent.score, 0.8), 2), bbox=[x0, y0, x1 - x0, y1 - y0],
        ))
    return out


def scan_media(images: list[Path], root: Path, ocr: bool = True, stats: dict | None = None) -> list[Finding]:
    out: list[Finding] = []
    bank = _bank(root)
    hashes: dict[str, list[pdq.RegionHash]] = {}

    for path in images:
        rel = path.relative_to(root).as_posix()
        try:
            img = Image.open(path)
            exif = img.getexif()
        except Exception as exc:
            record_error(rel, "media", exc)
            continue

        if exif and (exif.get(0x8825) or exif.get(0x013B)):
            out.append(Finding(fingerprint("EXIF_GPS", rel, rel, "exif"), "media", "EXIF_GPS", "high", rel, 0, 0, 0, 0, "image carries GPS/author EXIF", "", ["strip_exif", "hash_pdq", "ignore"]))

        if ocr:
            try:
                out.extend(_ocr_findings(path, rel))
            except Exception as exc:  # tesseract missing or image unreadable: report, never pass silently
                record_error(rel, "ocr", exc)

        arr = cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2BGR)
        try:
            # presence detection only (YuNet); no recognition or identity comparison happens here
            for row in face.detect_faces(arr):
                x, y, w, h = (int(v) for v in row[:4])
                out.append(Finding(fingerprint("FACE_IN_REPO", rel, f"{x},{y}", "face"), "media", "FACE_IN_REPO", "medium", rel, 0, 0, 0, 0, f"a person's face is committed at x={x} y={y}; is there consent?", "", ["redact_image", "hash_pdq", "ignore"], bbox=[x, y, w, h]))
        except Exception as exc:
            record_error(rel, "face_detection", exc)

        rgb = cv2.cvtColor(arr, cv2.COLOR_BGR2RGB)
        rh = pdq.pdq_regions(rgb)
        hashes[rel] = rh
        nearest = bank.nearest(rh) if len(bank) else None
        if nearest and nearest[1] <= 45:
            out.append(Finding(fingerprint("PDQ_BANK_MATCH", rel, rel, nearest[0]["id"]), "media", "PDQ_BANK_MATCH", "critical", rel, 0, 0, 0, 0, f"matches sensitive reference {nearest[0]['label']} (d={nearest[1]})", "", ["ignore"]))

    # near-duplicate groups
    rels = list(hashes)
    for i in range(len(rels)):
        for j in range(i + 1, len(rels)):
            a, b = rels[i], rels[j]
            if not hashes[a] or not hashes[b]:
                continue
            d = min(pdq.hamming(x.hex, y.hex) for x in hashes[a] for y in hashes[b])
            if d <= 31:
                msg = f"near-duplicate of {b} (d={d})"
                out.append(Finding(fingerprint("PDQ_NEAR_DUP", a, a, b), "media", "PDQ_NEAR_DUP", "medium", a, 0, 0, 0, 0, msg, "", ["ignore"]))
    return out

