from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import cv2
import numpy as np
import pymupdf
import pytesseract
from PIL import Image

from .detect import detect
from .models import Entity


@dataclass
class Profile:
    file_format: str
    domain_tags: list[str] = field(default_factory=list)
    locale_hints: list[str] = field(default_factory=list)
    has_images: bool = False
    layers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    entities: list[Entity] = field(default_factory=list)


@dataclass
class Agent:
    id: str
    name: str
    target_layer: str
    protocol: str
    run: Callable[[], Any]


DOMAIN_KEYWORDS = {
    "FINANCIAL_BANKING": {"bank", "account", "ifsc", "statement", "loan", "card"},
    "HR_PAYROLL": {"employee", "salary", "payroll", "aadhaar", "pan", "joining"},
    "GOVT_KYC": {"aadhaar", "kyc", "passport", "voter", "ration"},
    "HEALTHCARE_MEDICAL": {"patient", "diagnosis", "hospital", "prescription", "medical"},
    "TECHNICAL_SECRETS": {"api_key", "secret", "token", "password", "private key"},
}


def layer_texts(path: Path) -> dict[str, str]:
    """Text per document layer. Entity offsets are relative to their layer's text."""
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        with pymupdf.open(path) as doc:
            visible = "".join(p.get_text() for p in doc)
            annots = "\n".join(
                (a.info or {}).get("content", "") or "" for p in doc for a in (p.annots() or [])
            )
            embedded = "\n".join(
                doc.embfile_get(n).decode("utf-8", "ignore") for n in doc.embfile_names()
            )
            meta = "\n".join(str(v) for v in (doc.metadata or {}).values() if v)
            meta += "\n" + (doc.get_xml_metadata() or "")
        return {"visible": visible, "annotations": annots, "embedded": embedded, "metadata": meta}
    if suffix in {".docx", ".xlsx"}:
        from .redact.docx import ooxml_text

        with zipfile.ZipFile(path) as z:
            meta = "\n".join(
                z.read(n).decode("utf-8", "ignore") for n in z.namelist() if n.startswith("docProps/")
            )
        return {"ooxml": ooxml_text(path), "metadata": meta}
    if suffix in {".jpg", ".jpeg", ".png"}:
        img = Image.open(path)
        exif = "\n".join(str(v) for v in img.getexif().values() if isinstance(v, (str, bytes)))
        exif += "\n" + "\n".join(str(v) for v in img.info.values() if isinstance(v, str))
        try:
            ocr = pytesseract.image_to_string(img)
        except Exception:
            ocr = ""
        return {"ocr": ocr, "exif": exif}
    return {"text": path.read_text(errors="ignore")}


def _has_images(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        doc = pymupdf.open(path)
        return any(page.get_images() for page in doc)
    if suffix in {".docx", ".xlsx", ".png", ".jpg", ".jpeg"}:
        return True
    return False


def extract_images(path: str | Path) -> list[tuple[str, np.ndarray, tuple | None]]:
    path = Path(path)
    suffix = path.suffix.lower()
    out: list[tuple[str, np.ndarray, tuple | None]] = []

    if suffix == ".pdf":
        doc = pymupdf.open(path)
        for pno, page in enumerate(doc):
            for img in page.get_images(full=True):
                xref = img[0]
                pix = doc.extract_image(xref)
                arr = cv2.imdecode(np.frombuffer(pix["image"], np.uint8), cv2.IMREAD_COLOR)
                if arr is None:
                    continue
                bbox = None
                try:
                    r = page.get_image_bbox(img)
                    bbox = (r.x0, r.y0, r.x1, r.y1, pno)
                except Exception:
                    pass
                out.append((f"pdf_p{pno}_x{xref}", arr, bbox))
        return out

    if suffix in {".docx", ".xlsx"}:
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if "/media/" in name and name.lower().endswith(
                    (".png", ".jpg", ".jpeg", ".webp", ".bmp")
                ):
                    arr = cv2.imdecode(np.frombuffer(z.read(name), np.uint8), cv2.IMREAD_COLOR)
                    if arr is not None:
                        out.append((name, arr, None))
        return out

    if suffix in {".jpg", ".jpeg", ".png"}:
        arr = cv2.imread(str(path))
        if arr is not None:
            out.append((path.name, arr, None))
    return out


def profile(path: str | Path) -> Profile:
    path = Path(path)
    layers = layer_texts(path)
    text = "\n".join(layers.values())
    entities = [e for name, t in layers.items() for e in detect(t, layer=name)]
    tags = []
    lower = text.lower()
    for tag, words in DOMAIN_KEYWORDS.items():
        if sum(1 for w in words if w in lower) >= 2:
            tags.append(tag)
    locale = ["INDIA"] if any(e.type.startswith("IN_") for e in entities) else []

    return Profile(
        file_format=path.suffix.lstrip(".").upper() or "UNKNOWN",
        domain_tags=tags,
        locale_hints=locale,
        has_images=_has_images(path),
        layers=layers,
        text=text,
        entities=entities,
    )


class AgentFactory:
    @staticmethod
    def spawn(p: Profile, path: str | Path) -> list[Agent]:
        agents: list[Agent] = []
        fmt = p.file_format
        if fmt == "PDF":
            agents.append(Agent("fmt_pdf", "PdfStreamInspector", "visible", "stream", lambda: None))
        elif fmt == "DOCX":
            agents.append(Agent("fmt_docx", "DocxXmlInspector", "ooxml", "xml", lambda: None))
        elif fmt == "XLSX":
            agents.append(Agent("fmt_xlsx", "SheetCacheInspector", "ooxml", "xml", lambda: None))
        else:
            agents.append(Agent("fmt_img", "OcrVisualInspector", "ocr", "vision", lambda: None))

        if "INDIA" in p.locale_hints:
            agents.append(Agent("in_kyc", "IndiaKycSpecialist", "visible", "regex", lambda: None))
        if "FINANCIAL_BANKING" in p.domain_tags:
            agents.append(Agent("fin", "FinSecSpecialist", "visible", "regex", lambda: None))
        if "HEALTHCARE_MEDICAL" in p.domain_tags:
            agents.append(Agent("health", "HealthSpecialist", "visible", "regex", lambda: None))
        if p.has_images:
            agents.append(
                Agent("visual", "VisualLikenessAgent", "images", "face", lambda: None)
            )
        agents.append(Agent("meta", "MetadataInspector", "metadata", "meta", lambda: None))
        agents.append(Agent("redteam", "RedTeamAttacker", "output", "attack", lambda: None))
        return agents

    @staticmethod
    def spawn_scout(registry: list[dict], enrolled: bool) -> list[Agent]:
        agents: list[Agent] = []
        for row in registry:
            agents.append(
                Agent(
                    f"crawl_{row['domain']}_{row['category']}",
                    f"{row['category'].title()}Crawler@{row['domain']}",
                    "web",
                    "crawl",
                    lambda: None,
                )
            )
        agents.append(Agent("pdq", "PdqMatcher", "images", "pdq", lambda: None))
        if enrolled:
            agents.append(Agent("face", "FaceMatcher", "images", "face", lambda: None))
        agents.append(Agent("firewall", "QueryFirewall", "queries", "text", lambda: None))
        agents.append(Agent("evidence", "EvidenceAgent", "review", "capture", lambda: None))
        return agents

