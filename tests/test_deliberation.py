import pytest
from shield.deliberate import deliberate, deliberate_entity
from shield.models import Entity


def test_debate_resolves_invoice_number():
    text = "Commercial Invoice INV-2024-99. Ref Number: 123456789012. Total amount: 5000 INR."
    # 123456789012 is 12 digits, but not a valid Aadhaar Verhoeff
    ent = Entity("IN_AADHAAR", "123456789012", 45, 57, 0.60)
    resolved, log = deliberate_entity(ent, text)
    assert resolved is None
    assert log.final_verdict == "OVERRULED"
    assert any(t.persona == "PragmaticDev" for t in log.turns)
    assert any(t.persona == "StatutoryAuditor" for t in log.turns)
    assert any(t.persona == "SwarmAdjudicator" for t in log.turns)


def test_debate_upholds_valid_aadhaar():
    text = "Employee UIDAI Record. Aadhaar Number: 2345 6789 0128. Verification verified."
    ent = Entity("IN_AADHAAR", "2345 6789 0128", 39, 53, 0.99)
    resolved, log = deliberate_entity(ent, text)
    assert resolved is not None
    assert resolved.value == "2345 6789 0128"
    assert log.final_verdict == "CONFIRMED"
    assert any(t.persona == "StatutoryAuditor" and t.action == "DEFENSE" for t in log.turns)


def test_debate_filters_mock_email():
    text = "Developer guide: send sample payload to user@example.com for testing."
    ent = Entity("EMAIL_ADDRESS", "user@example.com", 40, 56, 0.90)
    resolved, log = deliberate_entity(ent, text)
    assert resolved is None
    assert log.final_verdict == "OVERRULED"
    assert any(t.persona == "PragmaticDev" for t in log.turns)


def test_debate_credit_card_luhn():
    # Invalid card sequence
    bad_card = Entity("CREDIT_CARD", "4111 1111 1111 1112", 10, 29, 0.70)
    res_bad, log_bad = deliberate_entity(bad_card, "Card details: 4111 1111 1111 1112")
    assert res_bad is None
    assert log_bad.final_verdict == "OVERRULED"

    # Valid Luhn card (Standard Visa test card: 4111 1111 1111 1111)
    good_card = Entity("CREDIT_CARD", "4111 1111 1111 1111", 10, 29, 0.70)
    res_good, log_good = deliberate_entity(good_card, "Card details: 4111 1111 1111 1111")
    assert res_good is not None
    assert log_good.final_verdict == "CONFIRMED"


def test_deliberate_batch():
    text = "Aadhaar: 2345 6789 0128. Contact: test@example.com. Invoice: 987654321098."
    ents = [
        Entity("IN_AADHAAR", "2345 6789 0128", 9, 23, 0.99),
        Entity("EMAIL_ADDRESS", "test@example.com", 34, 50, 0.90),
        Entity("IN_AADHAAR", "987654321098", 61, 73, 0.60),
    ]
    confirmed, logs = deliberate(ents, text)
    # Only valid Aadhaar should survive; mock email & invoice number should be filtered out
    assert len(confirmed) == 1
    assert confirmed[0].value == "2345 6789 0128"
    assert len(logs) == 3

