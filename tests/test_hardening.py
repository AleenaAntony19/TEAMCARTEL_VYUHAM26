import asyncio

import httpx
import pytest

from shield import net, verify
from shield.models import BASE


def test_ip_allowed(monkeypatch):
    monkeypatch.delenv("SHIELD_ALLOW_LOCAL", raising=False)
    assert net.ip_allowed("93.184.216.34")
    for ip in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "::1", "fd00::1", "0.0.0.0", "not-an-ip"):
        assert not net.ip_allowed(ip), ip


def test_redirect_loop_and_scheme(monkeypatch):
    monkeypatch.setattr(net, "is_public", lambda h: True)

    def handler(req: httpx.Request):
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        if req.url.path == "/file":
            return httpx.Response(302, headers={"location": "file:///etc/passwd"})
        return httpx.Response(302, headers={"location": "/loop"})

    f = net.Fetcher(transport=httpx.MockTransport(handler))
    assert asyncio.run(f.get("http://example.com/loop")).blocked_reason == "too_many_redirects"
    assert asyncio.run(f.get("http://example.com/file")).blocked_reason == "private_ip"


def test_verify_fails_closed_when_ocr_breaks(fx, monkeypatch, tmp_path):
    def boom(*a, **k):
        raise RuntimeError("tesseract missing")

    monkeypatch.setattr(verify.pytesseract, "image_to_string", boom)
    res = verify.attack(fx["png"], ["ABCPK1234F"])
    te = next(r for r in res if r.name == "text_extraction")
    assert not te.passed and "could not run" in te.evidence[0]


def test_pca_beats_raw_baseline_without_false_positives():
    img_dir = BASE / "demo/mockweb/img"
    if not img_dir.exists():
        pytest.skip("run demo/make_mockweb.py first")
    from shield.pcamatch import evaluate

    r = evaluate(img_dir)
    assert r["pca"]["heldout_fpr"] == 0.0
    assert r["pca"]["recall"] >= r["raw_pixel_baseline"]["recall"]
    assert 0 < r["pca"]["threshold"] < 1
