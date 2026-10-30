from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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


@dataclass
class SeverityFactors:
    intrinsic_sensitivity: float  # 30%
    exploitability: float         # 20%
    linkability: float            # 25%
    exposure_context: float       # 15%
    frequency: float              # 10%


@dataclass
class RankedEntity:
    rank: int
    entity_type: str
    value: str
    masked_value: str
    severity_score: float
    band: str
    factors: SeverityFactors
    occurrences: int = 1
    layer: str = "visible"


@dataclass
class TokenAuditResult:
    token: str
    masked_token: str
    layer: str
    start: int
    end: int
    severity_score: float
    band: str
    factors: SeverityFactors
    is_captured_by_detector: bool
    suspected_category: str


@dataclass
class VerificationAuditReport:
    total_tokens_scanned: int
    captured_count: int
    potential_misses: list[TokenAuditResult] = field(default_factory=list)
    verification_completeness_pct: float = 100.0
    audit_passed: bool = True

