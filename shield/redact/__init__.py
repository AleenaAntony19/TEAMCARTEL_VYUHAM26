from __future__ import annotations

from pathlib import Path

from .docx import redact_docx
from .image import redact_image
from .pdf import redact_pdf
from .xlsx import redact_xlsx


def redact_text(text: str, entities) -> str:
    """Replace every variant of each entity value per its action (token/mask/remove)."""
    from .docx import _apply, _targets

    return _apply(text, _targets(entities))


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
    if suffix == ".txt":
        dst.write_text(redact_text(src.read_text(encoding="utf-8"), entities), encoding="utf-8")
        return dst
    raise ValueError(f"Unsupported format: {src.suffix}")

