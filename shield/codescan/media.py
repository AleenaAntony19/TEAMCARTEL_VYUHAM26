from __future__ import annotations

import json
import shutil
from pathlib import Path

import cv2
import numpy as np
from PIL import Image

from shield import face, pdq
from shield.redact.image import ocr_words
from shield.detect import detect

from . import Finding, fingerprint

BANK_PATH = Path(".shield/bank.json")


def _bank() -> pdq.HashBank:
    if BANK_PATH.exists():
        return pdq.HashBank.load(BANK_PATH)
    return pdq.HashBank()


def bank_add(path: Path, label: str):
    BANK_PATH.parent.mkdir(parents=True, exist_ok=True)
    bank = _bank()
    img = cv2.cvtColor(cv2.imread(str(path)), cv2.COLOR_BGR2RGB)
    bank.add_reference(path.name, label, img)
    bank.save(BANK_PATH)


def bank_list():
    bank = _bank()
    return [{"id": m["id"], "label": m["label"], "region": m["region"]} for m in bank._meta]


def bank_rm(path: str):
    bank = _bank()
    keep = [(r, m) for r, m in zip(bank._rows, bank._meta) if m["id"] != path]
    bank._rows = [r for r, _ in keep]
    bank._meta = [m for _, m in keep]
    bank.save(BANK_PATH)


def scan_media(images: list[Path], root: Path) -> list[Finding]:
    out: list[Finding] = []
    bank = _bank()
    hashes: dict[str, list[pdq.RegionHash]] = {}

    for path in images:
        rel = path.relative_to(root).as_posix()
        try:
            img = Image.open(path)
            exif = img.getexif()
        except Exception:
            continue

        if exif and (exif.get(0x8825) or exif.get(0x013B)):
            out.append(Finding(fingerprint("EXIF_GPS", rel, rel, "exif"), "media", "EXIF_GPS", "high", rel, 0, 0, 0, 0, "image carries GPS/author EXIF", "", ["strip_exif", "ignore"]))

        try:
            words = ocr_words(path)
            text = " ".join(w for w, _ in words)
            for ent in detect(text):
                if ent.type in {"IN_AADHAAR", "IN_PAN", "IN_UPI", "IN_IFSC", "MOBILE_IN"}:
                    out.append(Finding(fingerprint("OCR_PII", rel, text, ent.value), "media", "OCR_PII", "critical", rel, 0, 0, 0, 0, f"{ent.type} visible in image OCR", "", ["redact_image", "ignore"]))
                    break
        except Exception:
            pass

        arr = cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2BGR)
        try:
            if len(face.detect_faces(arr)):
                out.append(Finding(fingerprint("FACE_IN_REPO", rel, rel, "face"), "media", "FACE_IN_REPO", "medium", rel, 0, 0, 0, 0, "a person's photo is committed; is there consent?", "", ["redact_image", "ignore"]))
        except Exception:
            pass

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

