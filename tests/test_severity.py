from __future__ import annotations

import pytest

from shield.detect import (
    WEIGHT_CONTEXT,
    WEIGHT_EXPLOITABILITY,
    WEIGHT_FREQUENCY,
    WEIGHT_LINKABILITY,
    WEIGHT_SENSITIVITY,
    mask_value,
    rank_entities,
    severity,
)
from shield.models import Entity


def test_weights_sum_to_one():
    total_weights = (
        WEIGHT_SENSITIVITY
        + WEIGHT_EXPLOITABILITY
        + WEIGHT_LINKABILITY
        + WEIGHT_CONTEXT
        + WEIGHT_FREQUENCY
    )
    assert pytest.approx(total_weights, 0.001) == 1.0
    assert pytest.approx(WEIGHT_SENSITIVITY, 0.001) == 0.30
    assert pytest.approx(WEIGHT_EXPLOITABILITY, 0.001) == 0.20
    assert pytest.approx(WEIGHT_LINKABILITY, 0.001) == 0.25
    assert pytest.approx(WEIGHT_CONTEXT, 0.001) == 0.15
    assert pytest.approx(WEIGHT_FREQUENCY, 0.001) == 0.10


def test_severity_ranking_order():
    entities = [
        Entity("PERSON", "Ravi Kumar", 0, 10, 0.70),
        Entity("MOBILE_IN", "+91 98765 43210", 15, 30, 0.85),
        Entity("IN_AADHAAR", "2345 6789 0128", 35, 49, 0.99),
    ]
    ranked = rank_entities(entities)
    assert len(ranked) == 3

    # Ranking must be strictly descending by severity score
    assert ranked[0].rank == 1
    assert ranked[0].entity_type == "IN_AADHAAR"
    assert ranked[0].band == "CRITICAL"

    assert ranked[1].rank == 2
    assert ranked[1].entity_type == "MOBILE_IN"
    assert ranked[1].band == "HIGH"

    assert ranked[2].rank == 3
    assert ranked[2].entity_type == "PERSON"
    assert ranked[0].severity_score >= ranked[1].severity_score >= ranked[2].severity_score


def test_linkability_increases_with_co_occurring_context():
    # Isolated phone number
    isolated_phone = [Entity("MOBILE_IN", "+91 98765 43210", 0, 15, 0.85)]
    ranked_isolated = rank_entities(isolated_phone)[0]

    # Phone number co-occurring with person name
    linked_phone = [
        Entity("PERSON", "Ravi Kumar", 0, 10, 0.70),
        Entity("MOBILE_IN", "+91 98765 43210", 15, 30, 0.85),
    ]
    ranked_linked = [r for r in rank_entities(linked_phone) if r.entity_type == "MOBILE_IN"][0]

    # Linkability and overall severity score should be higher when linked
    assert ranked_linked.factors.linkability > ranked_isolated.factors.linkability
    assert ranked_linked.severity_score > ranked_isolated.severity_score


def test_exposure_context_increases_with_hidden_layers():
    visible_entity = [Entity("IN_PAN", "ABCPK1234F", 0, 10, 0.95, layer="visible")]
    metadata_entity = [Entity("IN_PAN", "ABCPK1234F", 0, 10, 0.95, layer="metadata")]

    r_vis = rank_entities(visible_entity)[0]
    r_meta = rank_entities(metadata_entity)[0]

    assert r_meta.factors.exposure_context > r_vis.factors.exposure_context
    assert r_meta.severity_score > r_vis.severity_score


def test_frequency_increases_with_occurrences():
    single_entity = [Entity("IN_UPI", "ravi.kumar@okaxis", 0, 17, 0.95)]
    multi_entity = [
        Entity("IN_UPI", "ravi.kumar@okaxis", 0, 17, 0.95),
        Entity("IN_UPI", "ravi.kumar@okaxis", 50, 67, 0.95),
        Entity("IN_UPI", "ravi.kumar@okaxis", 100, 117, 0.95),
        Entity("IN_UPI", "ravi.kumar@okaxis", 150, 167, 0.95),
    ]

    r_single = rank_entities(single_entity)[0]
    r_multi = rank_entities(multi_entity)[0]

    assert r_multi.occurrences == 4
    assert r_multi.factors.frequency > r_single.factors.frequency
    assert r_multi.severity_score > r_single.severity_score


def test_mask_value():
    assert mask_value("2345 6789 0128", "IN_AADHAAR") == "XXXX XXXX 0128"
    assert mask_value("ABCPK1234F", "IN_PAN") == "AB****F"
    assert mask_value("123456789012", "IN_BANK_ACCOUNT") == "********9012"
    assert mask_value("ravi.kumar@acme.in", "EMAIL_ADDRESS").endswith("@acme.in")
    assert mask_value("any_face", "FACE") == "[BIOMETRIC EMBEDDING]"


def test_severity_tuple_and_attribute_access():
    entities = [
        Entity("PERSON", "Ravi Kumar", 0, 10, 0.70),
        Entity("IN_AADHAAR", "2345 6789 0128", 15, 29, 0.99),
    ]
    res = severity(entities)

    # Unpacking as 3-tuple
    score, band, types = res
    assert score >= 85
    assert band == "CRITICAL"
    assert "IN_AADHAAR" in types
    assert "PERSON" in types

    # Object-oriented access
    assert res.score == score
    assert res.band == band
    assert len(res.ranked_entities) == 2
    assert res.ranked_entities[0].rank == 1
    assert res.ranked_entities[0].entity_type == "IN_AADHAAR"

    # Empty entities
    empty_res = severity([])
    assert empty_res == (0, "NONE", [])
    assert empty_res.ranked_entities == []


def test_shannon_entropy():
    from shield.detect import _shannon_entropy

    low = _shannon_entropy("aaaaaaa")
    med = _shannon_entropy("standard")
    high = _shannon_entropy("AKIAIOSFODNN7EXAMPLE")
    assert low == 0.0
    assert high > med > low


def test_audit_clean_document_passes_100_percent():
    from shield.detect import audit_all_extracted_text, detect

    clean_text = "This is a quarterly review document published for internal company purposes."
    entities = detect(clean_text)
    rep = audit_all_extracted_text({"visible": clean_text}, entities)

    assert rep.audit_passed is True
    assert rep.verification_completeness_pct == 100.0
    assert len(rep.potential_misses) == 0
    assert rep.total_tokens_scanned > 0


def test_audit_catches_unflagged_12digit_and_secret_tokens():
    from shield.detect import audit_all_extracted_text, detect

    text = """
    Employee: Ravi Kumar
    Valid Aadhaar: 2345 6789 0128
    Unflagged Number: 2345 6789 0120
    Access Key: AKIAIOSFODNN7EXAMPLE
    """
    entities = detect(text)
    rep = audit_all_extracted_text({"visible": text}, entities)

    # Detector caught Ravi Kumar and the valid Aadhaar
    assert any(e.type == "IN_AADHAAR" for e in entities)
    assert not any(e.value == "2345 6789 0120" for e in entities)

    # But the all-word auditor caught the unflagged number and the access secret!
    assert rep.audit_passed is False
    assert rep.verification_completeness_pct < 100.0
    missed_tokens = {m.token for m in rep.potential_misses}
    assert "2345 6789 0120" in missed_tokens
    assert "AKIAIOSFODNN7EXAMPLE" in missed_tokens

    # Verify categories and scores
    miss_12 = [m for m in rep.potential_misses if m.token == "2345 6789 0120"][0]
    assert miss_12.suspected_category == "UNCLASSIFIED_12DIGIT_NUMERIC"
    assert miss_12.severity_score >= 65.0
    assert miss_12.band in ("HIGH", "CRITICAL")

    miss_sec = [m for m in rep.potential_misses if m.token == "AKIAIOSFODNN7EXAMPLE"][0]
    assert miss_sec.suspected_category == "HIGH_ENTROPY_SECRET"
    assert miss_sec.severity_score >= 65.0

