# Team integration

This document describes how teammates should consume the extractor and detector contracts without altering the existing architecture.

## Pipeline flow

The current execution flow remains:

```text
Document Input -> Extractor -> Extraction Validation -> Detector -> Detection Validation -> Severity / Redaction / Verification
```

Do not add a competing orchestration framework. Reuse the existing pipeline in `shield/pipeline.py` and the shared detection engine in `shield/detect.py`.

## Downstream compatibility

### Severity and linkability

Expected input:
- validated `DetectionResult.entities`

Required fields:
- `entity.type`
- `entity.score`
- `entity.layer`

Output:
- severity band and score summary

### Redaction

Expected input:
- validated in-memory `Entity` objects from `DetectionResult.entities`

Required fields:
- `Entity.type`
- `Entity.value`
- `Entity.start`
- `Entity.end`
- `Entity.layer`

The redaction stage must not consume masked serialized findings. It must operate on the original internal values.

### Verification / recovery attacker

Expected input:
- sanitized output artifact
- original values for attack comparison (in-memory only)

Output:
- pass/fail attack result objects

Privacy rule:
- do not serialize the original values into logs or ledger payloads

### Ledger and auditing

Expected input:
- execution status, counts, severity summary, and event metadata

Output:
- append-only audit record

Privacy rule:
- ledger data must contain no raw entity values

### Main pipeline

Expected input:
- document path
- work directory
- optional ledger

Output:
- extraction result
- detection result
- redaction output
- verification results
- final report

## Example: extractor then detector

```python
from pathlib import Path
from shield.extractor import ExtractorAgent
from shield.detector import DetectorAgent

source = Path("demo.csv")
extract = ExtractorAgent().execute(source)
if extract.status == "failed":
    raise RuntimeError(extract.error)

detect = DetectorAgent().execute(extract)
if detect.status == "failed":
    raise RuntimeError(detect.error)

print(extract.safe_dict())
print(detect.safe_dict())
```

## Example: downstream redaction integration

```python
from shield.redact import redact
from shield.models import Entity

entities: list[Entity] = detect.entities
output_path = redact("demo.csv", entities, "./work")
print(output_path)
```

The redaction step receives the original `Entity` values, not the masked detector export payload.

## Privacy guardrails

- never log raw PII values
- never include raw entity values in serialized reports
- never send raw values to external services
- use `safe_dict()` and masked values for exported payloads
- keep original values only in memory for validation and redaction
