from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

import pymupdf
try:
    import pytesseract
except ImportError:
    pytesseract = None
from PIL import Image

from .detect import detect, variants
from .models import AttackResult
from .redact.docx import ooxml_text


def _extract_text(path: Path) -> str:
    """Independent extraction. Raises if the extractor cannot run: an empty string must never mean 'clean'."""
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        try:
            res = subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, timeout=30, check=False)
            if res.returncode == 0:
                return res.stdout
        except (OSError, subprocess.TimeoutExpired):
            pass
        with pymupdf.open(path) as doc:  # pdftotext missing or failed: second, different extractor
            return "".join(p.get_text() for p in doc)
    if suffix in {".docx", ".xlsx"}:
        return ooxml_text(path)
    if suffix in {".jpg", ".jpeg", ".png"}:
        return pytesseract.image_to_string(Image.open(path))
    return path.read_bytes().decode("utf-8", "ignore")


def _binary(path: Path) -> bytes:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        doc = pymupdf.open(path)
        blob = doc.tobytes(expand=255)
        for name in doc.embfile_names():
            try:
                blob += doc.embfile_get(name)
            except Exception:
                pass
        return blob
    if suffix in {".docx", ".xlsx"}:
        out = b""
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.endswith(".xml"):
                    out += z.read(name)
        return out
    return path.read_bytes()


def _metadata_bad(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        doc = pymupdf.open(path)
        meta = doc.metadata or {}
        if any((meta.get(k) or "").strip() for k in ("author", "creator", "producer", "subject", "keywords")):
            return True
        try:
            if (doc.get_xml_metadata() or "").strip():
                return True
        except Exception:
            pass
        return bool(doc.embfile_names())
    if suffix in {".docx", ".xlsx"}:
        with zipfile.ZipFile(path) as z:
            for name in ("docProps/core.xml", "docProps/app.xml"):
                if name in z.namelist():
                    text = z.read(name).decode("utf-8", "ignore")
                    for marker in ("<dc:creator>", "<cp:lastModifiedBy>", "<Company>"):
                        if marker in text:
                            start = text.find(marker) + len(marker)
                            end = text.find("<", start)
                            if text[start:end].strip():
                                return True
        return False
    if suffix in {".jpg", ".jpeg", ".png"}:
        img = Image.open(path)
        try:
            exif = img.getexif()
            if exif:
                if exif.get(0x013B) or exif.get(0x8825):
                    return True
        except Exception:
            pass
        for key in ("Author", "artist", "GPS", "exif"):
            if img.info.get(key):
                return True
        return False
    return False


def attack(path: str | Path, originals: list[str]) -> list[AttackResult]:
    path = Path(path)
    results: list[AttackResult] = []

    try:
        text = _extract_text(path)
    except Exception as exc:
        results.append(AttackResult("text_extraction", False, [f"check could not run ({type(exc).__name__}); not verified"]))
        text = None

    # 1. text extraction
    hits = 0
    if text is not None:
        for original in originals:
            if any(v in text for v in variants(original)):
                hits += 1
        for ent in detect(text):
            if any(ent.value == original for original in originals):
                hits += 1
        results.append(
            AttackResult(
                "text_extraction",
                hits == 0,
                [] if hits == 0 else [f"{hits} original value(s) recoverable from text"],
            )
        )

    # 2. binary grep (decompressed)
    blob = _binary(path)
    bhits = 0
    for original in originals:
        if any(v.encode("utf-8") in blob for v in variants(original)):
            bhits += 1
    results.append(
        AttackResult(
            "binary_grep",
            bhits == 0,
            [] if bhits == 0 else [f"{bhits} original value(s) found in binary stream"],
        )
    )

    # 3. metadata
    try:
        bad = _metadata_bad(path)
    except Exception as exc:
        results.append(AttackResult("metadata", False, [f"check could not run ({type(exc).__name__}); not verified"]))
        return results
    results.append(
        AttackResult(
            "metadata",
            not bad,
            [] if not bad else ["author/creator/GPS/embedded file metadata remains"],
        )
    )
    return results

