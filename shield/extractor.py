from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detect import detect

EXTRACTOR_PROMPT = """You are the Shield·Scout Extractor Agent.
Purpose: convert a document or structured file into normalized extraction layers without PII detection.
Rules:
- Detect file format and call the matching extraction handler.
- Preserve visible text, metadata, and structured text layers.
- Keep source-layer names stable: visible, ooxml, data, ocr, metadata.
- Return a validation status and a clear failure reason if extraction cannot proceed.
- Never redact or classify PII. Only normalize content and ancestry.
- Only use deterministic Python parsing/OCR logic; do not rely on externally hosted LLM services.
- Preserve privacy by never logging raw PII values in the agent output.
"""

_VALID_LAYERS = {
    "visible",
    "annotations",
    "embedded",
    "metadata",
    "ooxml",
    "data",
    "ocr",
    "exif",
    "text",
}


def _flatten_json(value, prefix: str = "") -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            out.extend(_flatten_json(child, child_prefix))
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            child_prefix = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            out.extend(_flatten_json(child, child_prefix))
    elif value is None:
        return [prefix] if prefix else []
    else:
        text = str(value)
        if prefix:
            out.append(f"{prefix}={text}")
        else:
            out.append(text)
    return out


@dataclass
class ExtractionResult:
    source: str
    file_format: str
    layers: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    status: str = "ok"
    error: str | None = None
    attempts: int = 1
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source_locations: dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    execution_ms: int | None = None

    def validate(self) -> None:
        if not self.source:
            raise ValueError("Extraction source is required.")
        if not self.file_format:
            raise ValueError("Extraction file_format is required.")
        if self.status not in {"ok", "failed", "partial"}:
            raise ValueError(f"Invalid extraction status: {self.status!r}")
        if self.status != "failed" and not self.layers:
            raise ValueError("Extraction results must include at least one normalized layer.")
        for layer_name, layer_value in self.layers.items():
            if layer_name not in _VALID_LAYERS:
                raise ValueError(f"Unsupported extraction layer: {layer_name!r}")
            if not isinstance(layer_value, str):
                raise ValueError(f"Extraction layer {layer_name!r} must be a string.")
        if self.attempts < 1:
            raise ValueError("attempts must be >= 1")
        if self.retry_count < 0:
            raise ValueError("retry_count cannot be negative")
        if self.execution_ms is not None and self.execution_ms < 0:
            raise ValueError("execution_ms cannot be negative")
        if not isinstance(self.warnings, list):
            raise ValueError("warnings must be a list")
        if not isinstance(self.errors, list):
            raise ValueError("errors must be a list")
        if self.status == "failed" and not self.error:
            raise ValueError("Failed extraction output must include an error message.")

    def as_dict(self, *, safe: bool = True) -> dict[str, Any]:
        layers = self.layers
        if safe:
            layers = {name: "[LAYER_REDACTED]" if value else "" for name, value in self.layers.items()}
        payload = {
            "source": self.source,
            "file_format": self.file_format,
            "layers": layers,
            "metadata": self.metadata,
            "status": self.status,
            "error": self.error,
            "errors": self.errors,
            "attempts": self.attempts,
            "warnings": self.warnings,
            "source_locations": self.source_locations,
            "retry_count": self.retry_count,
            "execution_ms": self.execution_ms,
        }
        if self.status == "failed" and self.error is None:
            payload["error"] = "unknown failure"
        return payload

    def safe_dict(self) -> dict[str, Any]:
        return self.as_dict(safe=True)


class ExtractorAgent:
    """Deterministic extraction stage used by the pipeline to normalize input layers."""

    max_retries = 2

    def execute(self, path: str | Path, *, max_retries: int | None = None) -> ExtractionResult:
        source = str(Path(path))
        retry_limit = self.max_retries if max_retries is None else max_retries
        last_error: str | None = None
        started_at = time.perf_counter()

        for attempt in range(1, retry_limit + 2):
            try:
                result = self._extract(path)
                result.attempts = attempt
                result.retry_count = max(0, attempt - 1)
                result.execution_ms = int((time.perf_counter() - started_at) * 1000)
                if self.validate(result):
                    return result
                last_error = "Extraction validation failed."
            except Exception as exc:  # pragma: no cover - recoverable path
                last_error = str(exc)
                if attempt > retry_limit:
                    break

        failed = ExtractionResult(
            source=source,
            file_format=Path(source).suffix.lower().lstrip("." if "." else "") or "unknown",
            layers={},
            metadata={"attempts": retry_limit + 1},
            status="failed",
            error=last_error or "Unknown extraction failure.",
            attempts=retry_limit + 1,
            warnings=["retries_exhausted"],
            errors=[last_error or "Unknown extraction failure."],
            retry_count=retry_limit,
            execution_ms=int((time.perf_counter() - started_at) * 1000),
        )
        return failed

    def validate(self, result: ExtractionResult) -> bool:
        try:
            result.validate()
            return True
        except ValueError:
            return False

    def _extract(self, path: str | Path) -> ExtractionResult:
        path = Path(path)
        suffix = path.suffix.lower()
        if suffix == ".csv":
            rows: list[str] = []
            with path.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
                reader = csv.reader(fh)
                for row in reader:
                    rows.append(" | ".join(row))
            text = "\n".join(rows)
            return ExtractionResult(
                source=str(path),
                file_format="csv",
                layers={"data": text},
                metadata={"rows": len(rows)},
                source_locations={"rows": list(range(1, len(rows) + 1))},
            )

        if suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            text = "\n".join(_flatten_json(data))
            return ExtractionResult(
                source=str(path),
                file_format="json",
                layers={"data": text},
                metadata={"keys": list(data.keys()) if isinstance(data, dict) else []},
                source_locations={"elements": ["root"]},
            )

        # PDF / Office / images / text: the shared per-layer extractor (annotations, embedded files,
        # comments, hidden sheets, docProps, EXIF and OCR are real layers, not placeholders)
        from .profile import layer_texts

        layers = layer_texts(path)
        meta: dict[str, Any] = {}
        if suffix == ".pdf":
            import pymupdf

            with pymupdf.open(path) as doc:
                meta["pages"] = doc.page_count
        return ExtractionResult(
            source=str(path),
            file_format=suffix.lstrip(".") or "text",
            layers=layers,
            metadata=meta,
            source_locations={"pages": list(range(meta["pages"]))} if "pages" in meta else {"elements": ["document"]},
            warnings=[f"empty_layer:{n}" for n, t in layers.items() if not t.strip()],
        )


def extract_text(path: str | Path) -> str:
    layers = ExtractorAgent().execute(path).layers
    return layers.get("visible") or next(iter(layers.values()), "")


def extract_entities(path: str | Path, layer: str = "visible") -> list:
    return detect(extract_text(path), layer=layer)
