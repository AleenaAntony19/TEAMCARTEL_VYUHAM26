from __future__ import annotations

from pathlib import Path

from .docx import redact_docx
from .image import redact_image
from .pdf import redact_pdf
from .xlsx import redact_xlsx


def redact(src: str | Path, entities, out_dir: str | Path, aggressive: bool = False) -> Path:
    src = Path(src)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    dst = out_dir / f"{src.stem}_sanitized{src.suffix}"
    suffix = src.suffix.lower()

    if suffix == ".pdf":
        return redact_pdf(src, entities, dst, aggressive)
    if suffix == ".docx":
        return redact_docx(src, entities, dst, aggressive)
    if suffix == ".xlsx":
        return redact_xlsx(src, entities, dst, aggressive)
    if suffix in {".jpg", ".jpeg", ".png"}:
        return redact_image(src, entities, dst, aggressive)
    raise ValueError(f"Unsupported format: {src.suffix}")

