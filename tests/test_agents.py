import json

import pytest

from shield.detect import detect
from shield.redact import redact


# Ported from origin/development test_core.py (agent contracts); demo Aadhaar fixed to a Verhoeff-valid value.
def test_gstin_and_passport_detected():
    text = "GSTIN 27ABCDE1234F1Z5 and passport K1234567 for Ravi Kumar"
    types = {e.type for e in detect(text)}
    assert {"IN_GSTIN", "IN_PASSPORT"} <= types


def test_csv_and_json_extraction_and_redaction(tmp_path):
    from shield.profile import profile

    csv_path = tmp_path / "records.csv"
    csv_path.write_text("name,pan,aadhaar\nRavi Kumar,ABCPK1234F,2345 6789 0124\n", encoding="utf-8")

    json_path = tmp_path / "records.json"
    json_path.write_text(
        json.dumps({"employee": {"name": "Ravi Kumar", "pan": "ABCPK1234F", "aadhaar": "2345 6789 0124"}}),
        encoding="utf-8",
    )

    csv_prof = profile(csv_path)
    json_prof = profile(json_path)
    assert any(e.type == "IN_AADHAAR" for e in csv_prof.entities)
    assert any(e.type == "IN_AADHAAR" for e in json_prof.entities)

    csv_out = redact(csv_path, csv_prof.entities, tmp_path)
    json_out = redact(json_path, json_prof.entities, tmp_path)
    assert csv_out.exists()
    assert json_out.exists()
    assert "2345 6789 0124" not in csv_out.read_text(encoding="utf-8")
    assert "2345 6789 0124" not in json_out.read_text(encoding="utf-8")


def test_extractor_and_detector_agent_contracts(tmp_path):
    from shield.detector import DetectorAgent
    from shield.extractor import ExtractorAgent

    csv_path = tmp_path / "agent_records.csv"
    csv_path.write_text("name,pan\nRavi Kumar,ABCPK1234F\n", encoding="utf-8")

    extraction = ExtractorAgent().execute(csv_path)
    assert extraction.status == "ok"
    assert extraction.layers["data"].startswith("name")

    detection = DetectorAgent().execute(extraction)
    assert detection.status == "ok"
    assert any(entity.type == "IN_PAN" for entity in detection.entities)



def test_extraction_result_validation_and_privacy(tmp_path):
    from shield.extractor import ExtractionResult

    result = ExtractionResult(
        source=str(tmp_path / "demo.csv"),
        file_format="csv",
        layers={"data": "name,pan\nRavi Kumar,ABCPK1234F"},
        metadata={"rows": 2},
        status="ok",
        errors=[],
        warnings=[],
    )
    result.validate()
    payload = result.as_dict(safe=True)
    assert payload["layers"]["data"] == "[LAYER_REDACTED]"
    assert "ABCPK1234F" not in str(payload)

    with pytest.raises(ValueError):
        bad = ExtractionResult(source="", file_format="", layers={}, status="ok")
        bad.validate()


def test_detection_result_validation_and_safe_serialization():
    from shield.detector import DetectionResult
    from shield.models import Entity

    good = DetectionResult(
        file_format="text",
        source="demo.txt",
        entities=[Entity("IN_PAN", "ABCPK1234F", 10, 20, 0.99, "visible")],
        counts={"IN_PAN": 1},
        severity_score=1,
        severity_band="LOW",
        types=["IN_PAN"],
    )
    good.validate()
    payload = good.as_dict(safe=True)
    assert payload["findings"][0]["value_masked"] == "[IN_PAN_1]"
    assert "ABCPK1234F" not in str(payload)

    with pytest.raises(ValueError):
        bad = DetectionResult(
            file_format="text",
            entities=[Entity("IN_AADHAAR", "2345 6789 0124", -1, 2, 1.5, "visible")],
        )
        bad.validate()

    with pytest.raises(ValueError):
        dup = DetectionResult(
            file_format="text",
            entities=[
                Entity("IN_AADHAAR", "2345 6789 0124", 5, 12, 0.9, "visible"),
                Entity("IN_AADHAAR", "2345 6789 0124", 5, 12, 0.8, "visible"),
            ],
        )
        dup.validate()

    with pytest.raises(ValueError):
        overlap = DetectionResult(
            file_format="text",
            entities=[
                Entity("IN_AADHAAR", "2345 6789 0124", 5, 12, 0.9, "visible"),
                Entity("IN_AADHAAR", "234567890124", 10, 18, 0.8, "visible"),
            ],
        )
        overlap.validate()


def test_detector_retry_and_pipeline_regression(tmp_path):
    from shield.detector import DetectionResult, DetectorAgent
    from shield.extractor import ExtractorAgent
    from shield.models import Entity

    csv_path = tmp_path / "agent_retry.csv"
    csv_path.write_text("name,pan\nRavi Kumar,ABCPK1234F\n", encoding="utf-8")

    extraction = ExtractorAgent().execute(csv_path)
    result = DetectorAgent().execute(extraction, max_retries=1)
    assert result.status == "ok"
    assert result.retry_count in {0, 1}

    invalid = DetectionResult(file_format="csv", status="ok", entities=[Entity("IN_PAN", "ABCPK1234F", 5, 20, 0.7, "visible")])
    assert invalid.status == "ok"
    assert invalid.entities[0].value == "ABCPK1234F"



def test_detector_safe_dict_has_no_raw_values_and_masked_deliberation(fx):
    from shield.detector import DetectorAgent
    from shield.extractor import ExtractorAgent

    ex = ExtractorAgent().execute(fx["pdf"])
    assert ex.status == "ok" and set(ex.layers) == {"visible", "annotations", "embedded", "metadata"}
    assert ex.layers["embedded"] and ex.layers["annotations"], "real layers, not placeholders"
    d = DetectorAgent().execute(ex)
    out = json.dumps(d.safe_dict())
    assert "2345 6789 0124" not in out and "ABCPK1234F" not in out
    assert d.safe_dict()["deliberation"] and d.detected and d.reviews
