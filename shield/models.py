from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
MODELS = BASE / "models"
YUNET = MODELS / "face_detection_yunet_2023mar.onnx"
SFACE = MODELS / "face_recognition_sface_2021dec.onnx"


@dataclass(frozen=True)
class Entity:
    type: str
    value: str
    start: int
    end: int
    score: float
    layer: str = "visible"
    action: str = "token"  # token | mask | remove; see detect.replacement


@dataclass
class AttackResult:
    name: str
    passed: bool
    evidence: list[str] = field(default_factory=list)


@dataclass
class ImageRef:
    page_url: str
    image_url: str
    domain: str


@dataclass
class Match:
    id: str
    page_url: str
    image_url: str
    kind: str
    pdq_distance: int | None
    similarity: float | None
    band: str | None
    verdict: str
    region: str
    sha256: str
    thumb_jpeg: bytes
    discovered_at: str
    etag: str | None = None
    last_modified: str | None = None
    status: str = "pending"


@dataclass
class FetchResult:
    status: int
    headers: dict[str, str]
    body: bytes
    final_url: str
    blocked_reason: str | None = None
    error: str | None = None

