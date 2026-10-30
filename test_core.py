import json
from pathlib import Path

import pytest

from shield.detect import detect, severity, variants, verhoeff_valid
from shield.ledger import Ledger
from shield.redact import redact
from shield import verify


def test_aadhaar_verhoeff():
    assert verhoeff_valid("2345 6789 0128")
    assert not verhoeff_valid("2345 6789 0120")
    assert [e.type for e in detect("Aadhaar: 2345 6789 0128")] == ["IN_AADHAAR"]
    assert not [e for e in detect("Aadhaar: 2345 6789 0120") if e.type == "IN_AADHAAR"]


def test_pan_upi_ifsc_and_email():
    types = {e.type for e in detect("PAN ABCPK1234F upi ravi.kumar@okaxis IFSC SBIN0001234")}
    assert {"IN_PAN", "IN_UPI", "IN_IFSC"} <= types
    assert "IN_UPI" not in {e.type for e in detect("mail ravi.kumar@acme.in")}


def test_bank_account_needs_context():
    assert "IN_BANK_ACCOUNT" in {e.type for e in detect("A/c No 123456789012 IFSC SBIN0001234")}
    assert "IN_BANK_ACCOUNT" not in {e.type for e in detect("Invoice 123456789012")}


def test_person_and_variants():
    assert any(e.type == "PERSON" and e.value == "Ravi Kumar" for e in detect("Employee Ravi Kumar joined"))
    assert {"2345 6789 0128", "234567890128"} <= variants("2345 6789 0128")


def test_severity():
    from shield.models import Entity

    name = [Entity("PERSON", "Ravi Kumar", 0, 10, 0.7)]
    mobile = name + [Entity("MOBILE_IN", "+91 98765 43210", 11, 28, 0.85)]
    aadhaar = mobile + [Entity("IN_AADHAAR", "2345 6789 0128", 29, 43, 0.99)]
    assert severity(name)[1] == "LOW"
    assert severity(mobile)[1] == "HIGH"
    assert severity(aadhaar)[1] == "CRITICAL"
    assert severity([]) == (0, "NONE", [])


def test_gstin_and_passport_detected():
    text = "GSTIN 27ABCDE1234F1Z5 and passport K1234567 for Ravi Kumar"
    types = {e.type for e in detect(text)}
    assert {"IN_GSTIN", "IN_PASSPORT"} <= types


def test_csv_and_json_extraction_and_redaction(tmp_path):
    from shield.profile import profile

    csv_path = tmp_path / "records.csv"
    csv_path.write_text("name,pan,aadhaar\nRavi Kumar,ABCPK1234F,2345 6789 0128\n", encoding="utf-8")

    json_path = tmp_path / "records.json"
    json_path.write_text(
        json.dumps({"employee": {"name": "Ravi Kumar", "pan": "ABCPK1234F", "aadhaar": "2345 6789 0128"}}),
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
    assert "2345 6789 0128" not in csv_out.read_text(encoding="utf-8")
    assert "2345 6789 0128" not in json_out.read_text(encoding="utf-8")


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


def test_ledger_chain_and_pii_guard():
    led = Ledger()
    for i in range(4):
        led.append("test", "ACT", {"i": i})
    assert led.verify() is None
    assert led.blocks[0]["prev_hash"] == "0" * 64
    import copy

    bad = copy.deepcopy(led.blocks)
    bad[2]["details"]["i"] = 999
    assert led.verify(bad) == 2
    with pytest.raises(ValueError):
        led.append("test", "ACT", {"note": "2345 6789 0128"})
    with pytest.raises(ValueError):
        led.append("test", "ACT", {"vec": [0.1] * 128})


@pytest.mark.parametrize("key", ["pdf", "docx", "xlsx", "jpg", "png"])
def test_redaction_attacks(fx, key, tmp_path):
    from shield.profile import profile

    src = fx[key]
    prof = profile(src)
    out = redact(src, prof.entities, tmp_path)
    assert src.exists()
    assert out != src
    originals = [e.value for e in prof.entities if e.value]
    results = verify.attack(out, originals)
    assert all(r.passed for r in results), [(r.name, r.evidence) for r in results]


def test_naive_pdf_fails_text_attack(fx, tmp_path):
    from shield.profile import profile

    prof = profile(fx["naive_pdf"])
    originals = [e.value for e in prof.entities if e.value]
    results = verify.attack(fx["naive_pdf"], originals)
    assert any(r.name == "text_extraction" and not r.passed for r in results)


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
            entities=[Entity("IN_AADHAAR", "2345 6789 0128", -1, 2, 1.5, "visible")],
        )
        bad.validate()

    with pytest.raises(ValueError):
        dup = DetectionResult(
            file_format="text",
            entities=[
                Entity("IN_AADHAAR", "2345 6789 0128", 5, 12, 0.9, "visible"),
                Entity("IN_AADHAAR", "2345 6789 0128", 5, 12, 0.8, "visible"),
            ],
        )
        dup.validate()

    with pytest.raises(ValueError):
        overlap = DetectionResult(
            file_format="text",
            entities=[
                Entity("IN_AADHAAR", "2345 6789 0128", 5, 12, 0.9, "visible"),
                Entity("IN_AADHAAR", "234567890128", 10, 18, 0.8, "visible"),
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

