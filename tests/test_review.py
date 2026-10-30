from shield.models import Entity
from shield.review import review, review_entity


def test_invoice_number_dismissed_with_evidence():
    text = "Commercial Invoice INV-2024-99. Ref Number: 123456789012. Total amount: 5000 INR."
    resolved, rec = review_entity(Entity("IN_AADHAAR", "123456789012", 45, 57, 0.60), text)
    assert resolved is None and rec.verdict == "dismissed"
    assert any(c.rule == "verhoeff" and not c.passed for c in rec.checks)
    assert any(c.rule == "non_id_context" for c in rec.checks)


def test_valid_aadhaar_confirmed_and_masked():
    text = "Aadhaar Number: 2345 6789 0124."
    resolved, rec = review_entity(Entity("IN_AADHAAR", "2345 6789 0124", 16, 30, 0.9), text)
    assert resolved is not None and rec.verdict == "confirmed" and rec.confidence == 0.99
    assert "2345" not in rec.masked and rec.masked.endswith("0124")
    assert all("2345 6789" not in c.evidence for c in rec.checks)


def test_mock_email_dismissed():
    _, rec = review_entity(Entity("EMAIL_ADDRESS", "user@example.com", 0, 16, 0.9), "user@example.com")
    assert rec.verdict == "dismissed"


def test_luhn():
    assert review_entity(Entity("CREDIT_CARD", "4111 1111 1111 1112", 0, 19, 0.7), "")[0] is None
    assert review_entity(Entity("CREDIT_CARD", "4111 1111 1111 1111", 0, 19, 0.7), "")[0] is not None


def test_batch_keeps_only_real():
    text = "Aadhaar: 2345 6789 0124. Contact: test@example.com. Invoice: 987654321098."
    ents = [
        Entity("IN_AADHAAR", "2345 6789 0124", 9, 23, 0.99),
        Entity("EMAIL_ADDRESS", "test@example.com", 34, 50, 0.90),
        Entity("IN_AADHAAR", "987654321098", 61, 73, 0.60),
    ]
    kept, records = review(ents, text)
    assert [e.value for e in kept] == ["2345 6789 0124"] and len(records) == 3


def test_persona_ring_two_rounds_and_math_superiority():
    from shield.review import MAX_ROUNDS, deliberate_stream

    text = "Invoice ref Aadhaar 2345 6789 0124 order"  # context says 'invoice', checksum says real Aadhaar
    resolved, rec = review_entity(Entity("IN_AADHAAR", "2345 6789 0124", 20, 34, 0.9), text)
    assert resolved is not None, "checksum must beat context (Rule of Mathematical Superiority)"
    personas = [c.reviewer for c in rec.checks]
    assert personas[0] == "PrivacyHawk" and personas[-1] == "SwarmAdjudicator"
    assert {"StatutoryAuditor"} <= set(personas)
    assert max(c.round for c in rec.checks) == MAX_ROUNDS == 2
    assert all("2345 6789" not in c.evidence for c in rec.checks)

    events = list(deliberate_stream([Entity("EMAIL_ADDRESS", "a@example.com", 0, 13, 0.9)], "a@example.com"))
    assert events[0]["event"] == "start" and events[-1]["event"] == "end"
    verdict = next(e for e in events if e["event"] == "verdict")
    assert verdict["verdict"] == "dismissed"
    assert any(e.get("reviewer") == "PragmaticDev" and e.get("action") == "CHALLENGE" for e in events)
