from __future__ import annotations

import re
import zipfile
from pathlib import Path

try:
    from lxml import etree
except ImportError:
    import xml.etree.ElementTree as etree

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
DC = "{http://purl.org/dc/elements/1.1/}"
CP = "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}"
EP = "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}"
REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"


def _targets(entities) -> dict[str, str]:
    from ..detect import replacement, variants

    out: dict[str, str] = {}
    for e in entities:
        if e.type == "FACE":
            continue
        for v in variants(e.value):
            out[v] = replacement(e, v)
    return out


def _apply(text: str, repl: dict[str, str]) -> str:
    if not text or not repl:
        return text
    pat = re.compile("|".join(re.escape(k) for k in sorted(repl, key=len, reverse=True)))
    return pat.sub(lambda m: repl[m.group(0)], text)


def _process_xml(name: str, data: bytes, repl: dict[str, str]) -> bytes | None:
    if name == "docProps/custom.xml":
        return None

    if name.endswith(".rels"):
        root = etree.fromstring(data)
        for rel in list(root):
            target = rel.get("Target") or ""
            if "custom.xml" in target:
                root.remove(rel)
        return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)

    if name == "docProps/core.xml":
        root = etree.fromstring(data)
        for tag in (f"{DC}creator", f"{CP}lastModifiedBy"):
            for el in root.iter(tag):
                el.text = ""
        return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)

    if name == "docProps/app.xml":
        root = etree.fromstring(data)
        for el in root.iter(f"{EP}Company"):
            el.text = ""
        return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)

    if not (name.startswith("word/") or name.startswith("docProps/")):
        return data

    try:
        root = etree.fromstring(data)
    except etree.XMLSyntaxError:
        return data

    # remove tracked deletions
    for el in list(root.iter(f"{W}del")):
        parent = el.getparent()
        if parent is not None:
            parent.remove(el)

    # unwrap insertions
    for el in list(root.iter(f"{W}ins")):
        parent = el.getparent()
        if parent is None:
            continue
        idx = parent.index(el)
        for child in list(el):
            parent.insert(idx, child)
            idx += 1
        parent.remove(el)

    # paragraph-level join handles run splitting
    for p in root.iter(f"{W}p"):
        ts = list(p.iter(f"{W}t"))
        if not ts:
            continue
        full = "".join(t.text or "" for t in ts)
        new = _apply(full, repl)
        if new != full:
            ts[0].text = new
            ts[0].set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            for t in ts[1:]:
                t.text = ""

    # any remaining text nodes (text boxes, comments, footnotes)
    for el in root.iter():
        if el.tag.endswith("}t") and el.text:
            el.text = _apply(el.text, repl)

    # strip author identity
    for el in root.iter():
        for attr in (f"{W}author", f"{W}initials"):
            if attr in el.attrib:
                el.attrib.pop(attr, None)

    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)


def _rewrite_zip(src: Path, out: Path, repl: dict[str, str], aggressive: bool) -> None:
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.is_dir():
                continue
            data = zin.read(item.filename)

            if aggressive and item.filename.endswith((".xml", ".rels")):
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    pass
                else:
                    data = _apply(text, repl).encode("utf-8")

            if item.filename.endswith((".xml", ".rels")):
                try:
                    new = _process_xml(item.filename, data, repl)
                except Exception:
                    new = data
                if new is None:
                    continue
                data = new

            zout.writestr(item, data)


def ooxml_text(path: str | Path) -> str:
    out: list[str] = []
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if not name.endswith(".xml"):
                continue
            try:
                root = etree.fromstring(z.read(name))
            except Exception:
                continue
            for el in root.iter():
                if (el.tag.endswith("}t") or el.tag.endswith("}v")) and el.text:
                    out.append(el.text)
    return "\n".join(out)


def redact_docx(
    src: str | Path,
    entities,
    out: str | Path,
    aggressive: bool = False,
) -> Path:
    src = Path(src)
    out = Path(out)
    repl = _targets(entities)
    _rewrite_zip(src, out, repl, aggressive)
    return out

