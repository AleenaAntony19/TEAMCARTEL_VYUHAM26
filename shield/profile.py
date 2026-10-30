from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import cv2
import numpy as np
import pymupdf
try:
    import pytesseract
except ImportError:
    pytesseract = None
from PIL import Image

from . import face
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


def _text_for(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        doc = pymupdf.open(path)
        return "".join(p.get_text() for p in doc)
    if suffix in {".docx", ".xlsx"}:
        from .redact.docx import ooxml_text

        return ooxml_text(path)
    if suffix in {".jpg", ".jpeg", ".png"}:
        try:
            return pytesseract.image_to_string(Image.open(path))
        except Exception:
            return ""
    return path.read_text(errors="ignore")


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
    text = _text_for(path)
    entities = detect(text)
    tags = []
    lower = text.lower()
    for tag, words in DOMAIN_KEYWORDS.items():
        if sum(1 for w in words if w in lower) >= 2:
            tags.append(tag)
    locale = ["INDIA"] if any(e.type.startswith("IN_") for e in entities) else []

    layers: dict[str, str] = {}
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        layers = {"visible": text, "annotations": "", "embedded": "", "metadata": ""}
    elif suffix in {".docx", ".xlsx"}:
        layers = {"ooxml": text, "metadata": ""}
    elif suffix in {".jpg", ".jpeg", ".png"}:
        layers = {"ocr": text, "exif": ""}

    return Profile(
        file_format=suffix.lstrip(".").upper() or "UNKNOWN",
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

