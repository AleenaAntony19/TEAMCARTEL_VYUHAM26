"""Validate untrusted uploads before any parser touches them."""
from __future__ import annotations

import io
import os
import zipfile
from pathlib import PurePosixPath

import pymupdf
from PIL import Image

MAX_UPLOAD_BYTES = int(os.getenv("SHIELD_MAX_UPLOAD_MB", "25")) * 1024 * 1024
MAX_TEXT_CHARS = int(os.getenv("SHIELD_MAX_TEXT_CHARS", "200000"))
MAX_PDF_PAGES = int(os.getenv("SHIELD_MAX_PDF_PAGES", "200"))
MAX_IMAGE_PIXELS = int(os.getenv("SHIELD_MAX_IMAGE_PIXELS", str(40_000_000)))
ZIP_MAX_MEMBERS = 2000
ZIP_MAX_TOTAL = 150 * 1024 * 1024
ZIP_MAX_RATIO = 100

SUFFIXES = {".pdf", ".docx", ".xlsx", ".png", ".jpg", ".jpeg", ".txt", ".csv", ".json"}
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS  # PIL raises DecompressionBombError above this


class UploadError(ValueError):
    pass


def _check_zip(data: bytes, required_prefix: str) -> None:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise UploadError("not a valid Office (zip) file") from None
    infos = z.infolist()
    if len(infos) > ZIP_MAX_MEMBERS:
        raise UploadError("too many parts in archive")
    total = 0
    for info in infos:
        name = PurePosixPath(info.filename)
        if name.is_absolute() or ".." in name.parts:
            raise UploadError("unsafe path inside archive")
        total += info.file_size
        if info.compress_size and info.file_size / info.compress_size > ZIP_MAX_RATIO:
            raise UploadError("archive compression ratio too high (possible zip bomb)")
    if total > ZIP_MAX_TOTAL:
        raise UploadError("archive expands too large")
    names = {i.filename for i in infos}
    if "[Content_Types].xml" not in names or not any(n.startswith(required_prefix) for n in names):
        raise UploadError("archive is not the declared Office type")


def validate(filename: str, data: bytes) -> str:
    """Return the safe suffix to store under; raise UploadError otherwise. Never trusts the client name beyond its suffix."""
    suffix = PurePosixPath(filename or "").suffix.lower()
    if suffix not in SUFFIXES:
        raise UploadError(f"unsupported type '{suffix or 'none'}'; allowed: {', '.join(sorted(SUFFIXES))}")
    if not data:
        raise UploadError("empty file")
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadError(f"file larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")

    if suffix == ".pdf":
        if not data.startswith(b"%PDF-"):
            raise UploadError("not a PDF")
        try:
            with pymupdf.open(stream=data, filetype="pdf") as doc:
                if doc.needs_pass:
                    raise UploadError("encrypted PDFs are not supported")
                if doc.page_count > MAX_PDF_PAGES:
                    raise UploadError(f"PDF has more than {MAX_PDF_PAGES} pages")
        except UploadError:
            raise
        except Exception:
            raise UploadError("malformed PDF") from None
    elif suffix == ".docx":
        _check_zip(data, "word/")
    elif suffix == ".xlsx":
        _check_zip(data, "xl/")
    elif suffix in {".png", ".jpg", ".jpeg"}:
        try:
            with Image.open(io.BytesIO(data)) as img:
                if img.format not in {"PNG", "JPEG"}:
                    raise UploadError("image content does not match PNG/JPEG")
                img.verify()
        except UploadError:
            raise
        except Exception:
            raise UploadError("malformed or oversized image") from None
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise UploadError("text must be UTF-8") from None
        if len(text) > MAX_TEXT_CHARS:
            raise UploadError(f"text longer than {MAX_TEXT_CHARS} characters")
        if suffix == ".json":
            import json

            try:
                json.loads(text)
            except ValueError:
                raise UploadError("invalid JSON") from None
    return suffix
