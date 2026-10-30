# Agent interfaces

This document describes the stable contract for the Shield·Scout extractor and detector agents.

## Design goals

- Preserve the existing shared model in `shield/models.py`.
- Keep `shield/detect.py` as the single detection engine.
- Standardize wrapper output for downstream teammates without breaking internal processing.
- Never serialize raw PII in agent output or exported reports.

## Extractor output contract

The extractor returns an `ExtractionResult` instance from `shield/extractor.py`.

```python
from shield.extractor import ExtractorAgent

result = ExtractorAgent().execute("demo.csv")
print(result.status)
print(result.file_format)
print(result.layers.keys())
```

Canonical serialized shape:

```python
{
    "source": "demo.csv",
    "file_format": "csv",
    "layers": {
        "data": "[LAYER_REDACTED]"
    },
    "metadata": {"rows": 2},
    "status": "ok",
    "error": None,
    "errors": [],
    "warnings": [],
    "source_locations": {"rows": [1, 2]},
    "retry_count": 0,
    "execution_ms": 15,
}
```

Required fields:
- `source`
- `file_format`
- `layers`
- `status`
- `warnings`
- `errors`

Optional fields:
- `metadata`
- `source_locations`
- `retry_count`
- `execution_ms`
- `error`

Privacy rule:
- `layers` may contain raw extracted text only in controlled in-memory processing.
- `as_dict(safe=True)` (default) masks all layer text in exported payloads.
- Do not log raw layer values or persist them unnecessarily.

## Detector output contract

The detector returns a `DetectionResult` instance from `shield/detector.py`.

```python
from shield.extractor import ExtractorAgent
from shield.detector import DetectorAgent

extract = ExtractorAgent().execute("demo.csv")
detect = DetectorAgent().execute(extract)
print(detect.status)
print(detect.safe_dict())
```

Canonical serialized shape:

```python
{
    "source": "demo.csv",
    "file_format": "csv",
    "status": "ok",
    "findings": [
        {
            "entity_type": "IN_PAN",
            "value_masked": "[IN_PAN_1]",
            "layer": "visible",
            "start": 5,
            "end": 17,
            "confidence": 0.99,
            "source": "detect",
            "reason": "deterministic recognizer",
            "validation_status": "passed",
            "warnings": [],
            "errors": []
        }
    ],
    "counts": {"IN_PAN": 1},
    "severity_score": 1,
    "severity_band": "LOW",
    "types": ["IN_PAN"],
    "warnings": [],
    "errors": [],
    "retry_count": 0,
    "execution_ms": 12,
}
```

Required fields:
- `source`
- `file_format`
- `status`
- `findings`

Per-finding required fields:
- `entity_type`
- `value_masked`
- `layer`
- `start`
- `end`
- `confidence`
- `source`
- `validation_status`

Privacy rule:
- The raw `Entity.value` remains available internally for redaction and verification.
- The serialized payload never emits raw entity values.
- `DetectionResult.safe_dict()` is the export-safe representation.

## Validation rules

The wrapper validation logic rejects invalid results before they reach downstream stages.

- missing source or file format
- invalid status values
- empty extraction layers for a successful extraction
- invalid layer names
- negative offsets
- end before start
- confidence outside `[0.0, 1.0]`
- duplicate findings in the same layer and range
- overlapping findings in the same layer
- failed detection without an error message

## Retry and execution metadata

Both agent wrappers track:
- `attempts`
- `retry_count`
- `execution_ms`
- `warnings`
- `errors`

Retries are only used for recoverable failures. A successful stage is returned without repeated execution.
