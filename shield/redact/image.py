from __future__ import annotations

from pathlib import Path

try:
    import pytesseract
except ImportError:
    pytesseract = None
from PIL import Image, ImageDraw

from ..detect import variants


def ocr_words(path: str | Path) -> list[tuple[str, tuple[int, int, int, int]]]:
    if pytesseract is None:
        return []
    img = Image.open(path).convert("RGB")
    # Adaptive OCR: try standard auto segmentation (better for ID cards/multi-column layouts)
    d_auto = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    w_auto = [
        (text.strip(), (int(d_auto["left"][i]), int(d_auto["top"][i]), int(d_auto["width"][i]), int(d_auto["height"][i])))
        for i, text in enumerate(d_auto["text"]) if (text or "").strip()
    ]
    # Also test PSM 6 (single uniform text block)
    d_6 = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT, config="--psm 6")
    w_6 = [
        (text.strip(), (int(d_6["left"][i]), int(d_6["top"][i]), int(d_6["width"][i]), int(d_6["height"][i])))
        for i, text in enumerate(d_6["text"]) if (text or "").strip()
    ]
    words = w_auto if len(w_auto) >= len(w_6) else w_6
    return words


def _ocr_lines(path: str | Path):
    img = Image.open(path).convert("RGB")
    data = pytesseract.image_to_data(
        img, output_type=pytesseract.Output.DICT, config="--psm 6"
    )
    lines: dict[tuple[int, int, int], list[tuple[str, tuple[int, int, int, int]]]] = {}
    for i, text in enumerate(data["text"]):
        text = (text or "").strip()
        if not text:
            continue
        key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
        lines.setdefault(key, []).append(
            (
                text,
                (
                    int(data["left"][i]),
                    int(data["top"][i]),
                    int(data["width"][i]),
                    int(data["height"][i]),
                ),
            )
        )
    return [((" ".join(t for t, _ in words)), words) for words in lines.values()]


def _alnum(s: str) -> str:
    return "".join(c for c in s if c.isalnum()).upper()


def _close(a: str, b: str) -> bool:
    # OCR runs disagree on single glyphs (3 vs 8); allow a few substitutions on long values only
    if len(a) != len(b):
        return False
    budget = 2 if len(b) >= 8 else 0
    return sum(x != y for x, y in zip(a, b)) <= budget


def _line_has(line_text: str, variant: str) -> bool:
    """OCR-tolerant containment: alphanumerics only (drops OCR'd em-dashes/stray spaces), <= 2 misread glyphs."""
    target, hay = _alnum(variant), _alnum(line_text)
    return bool(target) and any(_close(hay[k : k + len(target)], target) for k in range(len(hay) - len(target) + 1))


def _fill_entity(draw, line_text: str, words, variant: str, pad: int) -> bool:
    """Fill every run of consecutive OCR words whose alphanumerics match `variant`."""
    target = _alnum(variant)
    if not target:
        return False
    hit = False
    for i in range(len(words)):
        acc = ""
        for j in range(i, min(i + 6, len(words))):
            acc += _alnum(words[j][0])
            if len(acc) > len(target) + 2:
                break
            # allow stray punctuation-like glyphs at the ends (e.g. "Aadhaar." glued to digits)
            if any(_close(acc[k : k + len(target)], target) for k in range(0, len(acc) - len(target) + 1)):
                for _, (x, y, w, h) in words[i : j + 1]:
                    draw.rectangle([x - pad, y - pad, x + w + pad, y + h + pad], fill=(0, 0, 0))
                hit = True
                break
    return hit


def redact_image(
    src: str | Path,
    entities,
    out: str | Path,
    aggressive: bool = False,
) -> Path:
    src = Path(src)
    out = Path(out)

    img = Image.open(src).convert("RGB")
    clean = img.copy()
    draw = ImageDraw.Draw(clean)
    lines = _ocr_lines(src)

    for e in entities:
        if e.type == "FACE" and e.layer.startswith("bbox:"):
            try:
                coords = e.layer[5:].split("@")[0]
                x0, y0, x1, y1 = map(float, coords.split(","))
                draw.rectangle([x0, y0, x1, y1], fill=(0, 0, 0))
            except ValueError:
                pass
            continue

        if aggressive:
            for line_text, words in lines:
                if any(_line_has(line_text, v) for v in variants(e.value)):
                    for _, (x, y, w, h) in words:
                        draw.rectangle([x - 4, y - 4, x + w + 4, y + h + 4], fill=(0, 0, 0))
        else:
            # every line, not just the first hit: a value can appear more than once
            for line_text, words in lines:
                any(_fill_entity(draw, line_text, words, v, 0) for v in variants(e.value))

    # fresh image without exif/pnginfo/iptc; format follows the output suffix (jpg, png, webp, tiff)
    if out.suffix.lower() in {".jpg", ".jpeg", ".webp"}:
        clean.save(out, quality=95)
    else:
        clean.save(out)
    return out

