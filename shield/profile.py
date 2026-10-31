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
    if suffix in {".csv", ".json"}:
        from .extractor import ExtractorAgent  # owns the CSV/JSON normalisation ("data" layer)

        return ExtractorAgent()._extract(path).layers
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
        # no try: a failed OCR must fail the job, because "0 findings" would read as a clean file
        return {"ocr": pytesseract.image_to_string(img, config="--psm 6"), "exif": exif}  # row-wise: keeps table rows (lat/long pairs) together
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


def _layer_job(path: Path, wanted: set[str] | None = None, types: set[str] | None = None, prefix: str = "") -> Callable[[], dict]:
    """A specialist's real work: extract its layers and count the detections it owns (no values)."""

    def run() -> dict:
        layers = layer_texts(path)
        if wanted:
            layers = {k: v for k, v in layers.items() if k in wanted}
        counts: dict[str, int] = {}
        for name, text in layers.items():
            for e in detect(text, layer=name):
                if (types is None or e.type in types) and e.type.startswith(prefix):
                    counts[e.type] = counts.get(e.type, 0) + 1
        return {"layers": {k: len(v) for k, v in layers.items()}, "detections": counts}

    return run


def _faces_job(path: Path) -> Callable[[], dict]:
    def run() -> dict:
        from . import face

        found = 0
        for _, img, _ in extract_images(path):
            try:
                found += len(face.detect_faces(img))
            except FileNotFoundError:
                return {"error": "face models missing (scripts/get_models.sh)"}
        return {"images": len(extract_images(path)), "face_regions": found}

    return run


def _health_job(path: Path) -> Callable[[], dict]:
    def run() -> dict:
        text = "\n".join(layer_texts(path).values()).lower()
        return {"keywords": {w: text.count(w) for w in DOMAIN_KEYWORDS["HEALTHCARE_MEDICAL"] if w in text}}

    return run


class AgentFactory:
    """Spawns only the specialists a document needs; each `run` performs that specialist's extraction/detection."""

    @staticmethod
    def spawn(p: Profile, path: str | Path) -> list[Agent]:
        path = Path(path)
        fmt = p.file_format
        fmt_agent = {
            "PDF": ("fmt_pdf", "PdfStreamInspector", {"visible", "annotations", "embedded"}),
            "DOCX": ("fmt_docx", "DocxXmlInspector", {"ooxml"}),
            "XLSX": ("fmt_xlsx", "SheetCacheInspector", {"ooxml"}),
        }.get(fmt, ("fmt_img", "OcrVisualInspector", {"ocr", "text", "data"}))
        agents = [Agent(fmt_agent[0], fmt_agent[1], ",".join(sorted(fmt_agent[2])), "extract+detect", _layer_job(path, fmt_agent[2]))]
        if "INDIA" in p.locale_hints:
            agents.append(Agent("in_kyc", "IndiaKycSpecialist", "all", "detect", _layer_job(path, prefix="IN_")))
        if "FINANCIAL_BANKING" in p.domain_tags:
            agents.append(Agent("fin", "FinSecSpecialist", "all", "detect", _layer_job(path, types={"CREDIT_CARD", "IN_IFSC", "IN_BANK_ACCOUNT", "IN_UPI"})))
        if "HEALTHCARE_MEDICAL" in p.domain_tags:
            agents.append(Agent("health", "HealthSpecialist", "all", "keywords", _health_job(path)))
        if p.has_images:
            agents.append(Agent("visual", "VisualLikenessAgent", "images", "face-regions", _faces_job(path)))
        agents.append(Agent("meta", "MetadataInspector", "metadata,exif", "detect", _layer_job(path, {"metadata", "exif"})))
        return agents

    @staticmethod
    def spawn_scout(registry: list[dict], enrolled: bool) -> list[str]:
        """Names of the scout stages that actually run in run_scout (crawlers per seed, matchers, firewall)."""
        names = [f"{row['category'].title()}Crawler@{row['domain']}" for row in registry]
        return names + ["PdqMatcher"] + (["FaceMatcher"] if enrolled else []) + ["QueryFirewall"]
