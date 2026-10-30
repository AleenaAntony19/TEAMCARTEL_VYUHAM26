from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from dataclasses import asdict

from .review import ReviewRecord, review
from .detect import detect, severity, variants, verhoeff_valid, luhn_valid
from .models import Entity

DETECTOR_PROMPT = """You are the Shield·Scout Detector Agent.
Purpose: detect PII and privacy-risk signals from normalized extraction layers.
Rules:
- Reuse the existing detection engine in shield.detect.
- Keep source-layer and offsets when available.
- Validate duplicate/overlap cases using the same filtering logic already used in the repository.
- Resolve ambiguous entities with the existing deliberation swarm where applicable.
- Never perform extraction or redaction.
- Never log raw PII values in the agent output; keep structured findings only.
- Only escalate to retries for recoverable processing failures.
"""

_VALID_LAYERS = {"visible", "annotations", "embedded", "metadata", "ooxml", "data", "ocr", "exif", "text"}


def _mask_value(entity_type: str, index: int) -> str:
    return f"[{entity_type}_{index + 1}]"


@dataclass
class DetectionResult:
    file_format: str
    source: str = ""
    entities: list[Entity] = field(default_factory=list)  # kept after deliberation (internal; raw values)
    debate_logs: list[dict[str, Any]] = field(default_factory=list)  # masked persona records
    detected: list[Entity] = field(default_factory=list)  # all detector hits before deliberation (internal)
    reviews: list[ReviewRecord] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    severity_score: int = 0
    severity_band: str = "NONE"
    types: list[str] = field(default_factory=list)
    status: str = "ok"
    error: str | None = None
    attempts: int = 1
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    retry_count: int = 0
    execution_ms: int | None = None

    def validate(self) -> None:
        if not self.file_format:
            raise ValueError("Detection file_format is required.")
        if self.status not in {"ok", "failed", "partial"}:
            raise ValueError(f"Invalid detection status: {self.status!r}")
        if self.attempts < 1:
            raise ValueError("attempts must be >= 1")
        if self.retry_count < 0:
            raise ValueError("retry_count cannot be negative")
        if self.execution_ms is not None and self.execution_ms < 0:
            raise ValueError("execution_ms cannot be negative")
        if self.status == "failed" and not self.error:
            raise ValueError("Failed detection output must include an error message.")
        if self.status != "failed":
            for entity in self.entities:
                if not isinstance(entity.type, str) or not entity.type:
                    raise ValueError("Entity type is required.")
                if not isinstance(entity.value, str):
                    raise ValueError(f"Entity value must be a string for {entity.type!r}.")
                if not isinstance(entity.start, int) or not isinstance(entity.end, int):
                    raise ValueError(f"Entity offsets must be integers for {entity.type!r}.")
                if entity.start < 0 or entity.end < entity.start:
                    raise ValueError(f"Invalid offsets for {entity.type!r}: {entity.start}..{entity.end}")
                if not 0.0 <= float(entity.score) <= 1.0:
                    raise ValueError(f"Entity confidence must be in [0, 1] for {entity.type!r}.")
                if entity.layer not in _VALID_LAYERS:
                    raise ValueError(f"Unsupported layer for {entity.type!r}: {entity.layer!r}")
            seen: set[tuple[str, str, int, int]] = set()
            by_layer: dict[str, list[Entity]] = {}
            for entity in self.entities:
                key = (entity.type, entity.layer, entity.start, entity.end)
                if key in seen:
                    raise ValueError(f"Duplicate finding detected: {entity.type!r} at {entity.start}-{entity.end}")
                seen.add(key)
                by_layer.setdefault(entity.layer, []).append(entity)
            for layer_name, items in by_layer.items():
                items.sort(key=lambda item: (item.start, item.end))
                for prev, curr in zip(items, items[1:]):
                    if curr.start <= prev.end:
                        raise ValueError(f"Overlapping findings detected in layer {layer_name!r}.")

    def as_dict(self, *, safe: bool = True) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for index, entity in enumerate(self.entities):
            if safe:
                value_masked = _mask_value(entity.type, index)
                raw_value = None
            else:
                value_masked = entity.value
                raw_value = entity.value
            findings.append(
                {
                    "entity_type": entity.type,
                    "value_masked": value_masked,
                    "layer": entity.layer,
                    "start": entity.start,
                    "end": entity.end,
                    "confidence": float(entity.score),
                    "source": "detect",
                    "reason": "deterministic recognizer + persona deliberation",
                    "validation_status": "passed",
                    "warnings": [],
                    "errors": [],
                    **({"value": raw_value} if not safe else {}),
                }
            )
        payload = {
            "source": self.source or self.file_format,
            "file_format": self.file_format,
            "status": self.status,
            "findings": findings,
            "counts": self.counts,
            "severity_score": self.severity_score,
            "severity_band": self.severity_band,
            "types": self.types,
            "deliberation": self.debate_logs,
            "error": self.error,
            "errors": self.errors,
            "attempts": self.attempts,
            "warnings": self.warnings,
            "retry_count": self.retry_count,
            "execution_ms": self.execution_ms,
        }
        return payload

    def safe_dict(self) -> dict[str, Any]:
        return self.as_dict(safe=True)


class DetectorAgent:
    """Deterministic detector stage used by the pipeline to convert extracted text into structured findings."""

    max_retries = 2

    def execute(self, extraction_result: Any, *, max_retries: int | None = None) -> DetectionResult:
        retry_limit = self.max_retries if max_retries is None else max_retries
        started_at = time.perf_counter()
        for attempt in range(1, retry_limit + 2):
            try:
                result = self._run(extraction_result)
                result.attempts = attempt
                result.retry_count = max(0, attempt - 1)
                result.execution_ms = int((time.perf_counter() - started_at) * 1000)
                if self.validate(result):
                    return result
                raise ValueError("Detection validation failed.")
            except Exception as exc:  # pragma: no cover - recoverable path
                if attempt > retry_limit:
                    return DetectionResult(
                        file_format=getattr(extraction_result, "file_format", "unknown"),
                        source=getattr(extraction_result, "source", ""),
                        status="failed",
                        error=str(exc),
                        attempts=attempt,
                        warnings=["retries_exhausted"],
                        errors=[str(exc)],
                        retry_count=max(0, attempt - 1),
                        execution_ms=int((time.perf_counter() - started_at) * 1000),
                    )
        return DetectionResult(
            file_format=getattr(extraction_result, "file_format", "unknown"),
            source=getattr(extraction_result, "source", ""),
            status="failed",
            error="Detection validation failed.",
            attempts=retry_limit + 1,
            warnings=["retries_exhausted"],
            errors=["Detection validation failed."],
            retry_count=retry_limit,
            execution_ms=int((time.perf_counter() - started_at) * 1000),
        )

    def validate(self, result: DetectionResult) -> bool:
        try:
            result.validate()
            return True
        except ValueError:
            return False

    def _run(self, extraction_result: Any) -> DetectionResult:
        layers = getattr(extraction_result, "layers", {})
        if isinstance(extraction_result, dict):
            layers = extraction_result.get("layers", {})
        layers = {n: t for n, t in layers.items() if isinstance(t, str)}
        if not any(t.strip() for t in layers.values()):
            return DetectionResult(
                file_format=getattr(extraction_result, "file_format", "unknown"),
                source=getattr(extraction_result, "source", ""),
                status="failed",
                error="No extractable text available.",
                errors=["No extractable text available."],
            )

        # per layer, so offsets stay relative to their own layer text
        detected = [e for name, text in layers.items() for e in detect(text, layer=name)]
        entities, records = review(detected, layers) if detected else ([], [])
        score, band, types = severity(entities)
        counts: dict[str, int] = {}
        for entity in entities:
            counts[entity.type] = counts.get(entity.type, 0) + 1

        result = DetectionResult(
            file_format=getattr(extraction_result, "file_format", getattr(extraction_result, "source", "unknown")),
            source=getattr(extraction_result, "source", ""),
            entities=entities,
            debate_logs=[asdict(r) for r in records],
            detected=detected,
            reviews=records,
            counts=counts,
            severity_score=score,
            severity_band=band,
            types=types,
        )
        result.validate()
        return result


def detect_entities(*, extraction_result: Any | None = None, text: str | None = None) -> DetectionResult:
    if text is not None:
        detection = DetectorAgent()._run(type("E", (), {"layers": {"visible": text}, "file_format": "text"})())
        return detection
    if extraction_result is None:
        raise ValueError("An extraction result or text must be provided.")
    return DetectorAgent().execute(extraction_result)


__all__ = [
    "DETECTOR_PROMPT",
    "DetectionResult",
    "DetectorAgent",
    "detect_entities",
    "detect",
    "severity",
    "variants",
    "verhoeff_valid",
    "luhn_valid",
]
