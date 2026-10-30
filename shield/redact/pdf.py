from __future__ import annotations

from pathlib import Path

import pymupdf

from ..detect import variants


def _targets(entities) -> dict[str, str]:
    out: dict[str, str] = {}
    for e in entities:
        if e.type == "FACE":
            continue
        for v in variants(e.value):
            out[v] = e.type
    return out


def _rasterize(path: Path) -> None:
    tmp = path.with_suffix(".tmp.pdf")
    doc = pymupdf.open(path)
    new = pymupdf.open()
    for page in doc:
        pix = page.get_pixmap(dpi=150)
        p = new.new_page(width=page.rect.width, height=page.rect.height)
        p.insert_image(p.rect, pixmap=pix)
    new.save(tmp, garbage=4, deflate=True)
    new.close()
    doc.close()
    tmp.replace(path)


def redact_pdf(
    src: str | Path,
    entities,
    out: str | Path,
    aggressive: bool = False,
) -> Path:
    import os

    src = Path(src)
    out = Path(out)
    doc = pymupdf.open(src)
    targets = _targets(entities)

    face_boxes: dict[int, list[pymupdf.Rect]] = {}
    for e in entities:
        if e.type == "FACE" and e.layer.startswith("bbox:"):
            spec = e.layer[5:]
            coords, _, page_s = spec.partition("@")
            pno = int(page_s) if page_s else 0
            try:
                x0, y0, x1, y1 = map(float, coords.split(","))
            except ValueError:
                continue
            face_boxes.setdefault(pno, []).append(pymupdf.Rect(x0, y0, x1, y1))

    for pno, page in enumerate(doc):
        rects: list[pymupdf.Rect] = []
        for v in targets:
            rects.extend(page.search_for(v))
        rects.extend(face_boxes.get(pno, []))

        for r in rects:
            page.add_redact_annot(r, fill=(0, 0, 0))

        # remove annotations carrying targets
        for annot in list(page.annots() or []):
            content = (annot.info or {}).get("content", "") or ""
            if any(v in content for v in targets):
                page.delete_annot(annot)

        # widgets / form fields
        for widget in list(page.widgets() or []):
            value = getattr(widget, "field_value", "") or ""
            if any(v in str(value) for v in targets):
                page.delete_widget(widget)

        page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_PIXELS)

    for name in list(doc.embfile_names()):
        doc.embfile_del(name)

    doc.set_metadata({})
    try:
        doc.del_xml_metadata()
    except Exception:
        pass

    tmp = out.with_suffix(".tmp.pdf")
    doc.save(tmp, garbage=4, deflate=True, clean=True)
    doc.close()
    os.replace(tmp, out)

    if aggressive:
        _rasterize(out)

    return out

