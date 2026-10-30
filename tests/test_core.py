
import pytest

from shield.detect import detect, severity, variants, verhoeff_valid
from shield.ledger import Ledger
from shield.redact import redact
from shield import verify


def test_aadhaar_verhoeff():
    assert verhoeff_valid("2345 6789 0124")
    assert not verhoeff_valid("2345 6789 0120")
    assert [e.type for e in detect("Aadhaar: 2345 6789 0124")] == ["IN_AADHAAR"]
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
    assert {"2345 6789 0124", "234567890124"} <= variants("2345 6789 0124")


def test_severity():
    from shield.models import Entity

    name = [Entity("PERSON", "Ravi Kumar", 0, 10, 0.7)]
    mobile = name + [Entity("MOBILE_IN", "+91 98765 43210", 11, 28, 0.85)]
    aadhaar = mobile + [Entity("IN_AADHAAR", "2345 6789 0124", 29, 43, 0.99)]
    assert severity(name)[1] == "LOW"
    assert severity(mobile)[1] == "HIGH"
    assert severity(aadhaar)[1] == "CRITICAL"
    assert severity([]) == (0, "NONE", [])


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
        led.append("test", "ACT", {"note": "2345 6789 0124"})
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



def test_ledger_allows_hashes_but_not_pii():
    from shield.ledger import Ledger

    led = Ledger()
    led.append("t", "OK", {"sha256": "ab" * 4 + "9876543210" + "c" * 46})  # digit run inside a digest
    with pytest.raises(ValueError):
        led.append("t", "BAD", {"note": "call +91 98765 43210"})
    assert led.verify() is None
