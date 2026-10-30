import io
import json
import time
import zipfile

import httpx
import pytest
from fastapi.testclient import TestClient

from shield import llm, uploads
from shield.api import server as api
from shield.models import AttackResult

AADHAAR = "2345 6789 0124"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "WORK_ROOT", tmp_path / "work")
    monkeypatch.setenv("SHIELD_SEARCH_PROVIDER", "offline")
    with TestClient(api.app) as c:
        yield c
    api.clear_session()


def wait(c, jid, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        j = c.get(f"/api/jobs/{jid}").json()
        if j["status"] not in {"queued", "running"}:
            return j
        time.sleep(0.1)
    raise AssertionError("job did not finish")


def test_text_flow_preview_redact_download(client):
    jid = client.post("/api/jobs", data={"text": f"Name: Ravi Kumar\nAadhaar {AADHAAR}\nPAN ABCPK1234F"}).json()["id"]
    job = wait(client, jid)
    assert job["status"] == "ready"
    raw = json.dumps(job)
    assert AADHAAR not in raw and "234567890124" not in raw and "ABCPK1234F" not in raw  # findings are masked
    aad = next(f for f in job["findings"] if f["type"] == "IN_AADHAAR")
    assert aad["severity"] == "critical" and aad["masked"].endswith("0124") and aad["checks"]
    assert {s["name"] for s in job["stages"]} >= {"validate", "extract_layers", "detect", "review"}

    sel = [{"finding_id": f["id"], "action": "token"} for f in job["findings"]]
    dry = client.post(f"/api/jobs/{jid}/redact", json={"selections": sel, "dry_run": True}).json()
    assert "[REDACTED-IN_AADHAAR]" in dry["preview_text"] and AADHAAR not in dry["preview_text"]

    res = client.post(f"/api/jobs/{jid}/redact", json={"selections": sel}).json()
    assert res["status"] == "CLEAN" and all(c["passed"] for c in res["checks"])
    dl = client.get(f"/api/jobs/{jid}/download")
    assert dl.status_code == 200 and b"0124" not in dl.content


def test_mask_and_remove_actions(client):
    jid = client.post("/api/jobs", data={"text": f"Aadhaar {AADHAAR} ok"}).json()["id"]
    f = wait(client, jid)["findings"][0]
    masked = client.post(f"/api/jobs/{jid}/redact", json={"selections": [{"finding_id": f["id"], "action": "mask"}], "dry_run": True}).json()
    assert "XXXX XXXX XXXX" in masked["preview_text"]
    removed = client.post(f"/api/jobs/{jid}/redact", json={"selections": [{"finding_id": f["id"], "action": "remove"}], "dry_run": True}).json()
    assert removed["preview_text"] == "Aadhaar  ok"


def test_pdf_redaction_verified_and_original_kept(client, fx):
    jid = client.post("/api/jobs", files={"file": ("kyc.pdf", fx["pdf"].read_bytes(), "application/pdf")}).json()["id"]
    job = wait(client, jid)
    sel = [{"finding_id": f["id"], "action": f["actions"][-1]} for f in job["findings"] if f["actions"]]
    res = client.post(f"/api/jobs/{jid}/redact", json={"selections": sel}).json()
    assert res["status"] == "CLEAN", res["checks"]
    assert (api.JOBS[jid].workdir / "input.pdf").exists()
    assert client.get(f"/api/jobs/{jid}/preview.png").headers["content-type"] == "image/png"


def test_failed_verification_withholds_download(client, monkeypatch):
    monkeypatch.setattr(api.verify, "attack", lambda p, o: [AttackResult("text_extraction", False, ["1 value recoverable"])])
    jid = client.post("/api/jobs", data={"text": f"Aadhaar {AADHAAR}"}).json()["id"]
    f = wait(client, jid)["findings"][0]
    res = client.post(f"/api/jobs/{jid}/redact", json={"selections": [{"finding_id": f["id"], "action": "token"}]}).json()
    assert res["status"] == "FAILED"
    assert client.get(f"/api/jobs/{jid}/download").status_code == 409


@pytest.mark.parametrize(
    "name,data,msg",
    [
        ("x.exe", b"MZ", "unsupported"),
        ("fake.pdf", b"\x89PNG\r\n", "not a PDF"),
        ("../../etc/passwd.txt", b"\xff\xfe\x00", "UTF-8"),
    ],
)
def test_upload_rejections(client, name, data, msg):
    r = client.post("/api/jobs", files={"file": (name, data, "application/octet-stream")})
    assert r.status_code == 422 and msg in r.json()["detail"]


def test_zip_bomb_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<x/>")
        z.writestr("word/document.xml", b"0" * (20 * 1024 * 1024))
    with pytest.raises(uploads.UploadError, match="ratio"):
        uploads.validate("bomb.docx", buf.getvalue())


def test_token_auth(client, monkeypatch):
    monkeypatch.setattr(api, "API_TOKEN", "s3cret-test")
    assert client.get("/api/config").status_code == 401
    assert client.get("/api/config", headers={"Authorization": "Bearer s3cret-test"}).status_code == 200


def test_llm_settings_never_echo_key(client):
    key = "gsk_" + "t" * 40
    r = client.put("/api/llm", json={"provider": "groq", "api_key": key})
    assert r.status_code == 200 and key not in r.text and r.json()["key_set"] is True
    assert key not in client.get("/api/llm").text and key not in client.get("/api/config").text
    client.delete("/api/session")
    assert client.get("/api/llm").json()["provider"] in {"none", "groq"}


def test_discovery_firewall_blocks_job_values(client):
    jid = client.post("/api/jobs", data={"text": f"Organisation: Acme Corp\nAadhaar {AADHAAR}"}).json()["id"]
    wait(client, jid)
    did = client.post("/api/discovery", json={"org": "Acme Corp", "domain": "acme.in", "job_id": jid}).json()["id"]
    d = wait(client, did)["discovery"]
    assert d["provider"] == "offline" and all(q["allowed"] for q in d["queries"])  # templates hold no personal values
    from shield.textscout import firewall

    assert not firewall(f'"Acme Corp" {AADHAAR}', [AADHAAR])
    assert all(r["evidence_status"].startswith(("candidate", "confirmed")) for r in d["results"])


def test_cancelled_stage_stops():
    job = api.Job("x", "analysis", time.time(), api.WORK_ROOT)
    job.cancel.set()
    with pytest.raises(api.Cancelled):
        api._run_stage(job, "detect", lambda: 1)


def test_llm_providers_shape_retry_and_no_key_in_errors():
    calls = []

    def handler(req: httpx.Request):
        calls.append(req)
        if len(calls) == 1:
            return httpx.Response(429)
        body = json.loads(req.content)
        if "api.groq.com" in str(req.url):
            assert req.headers["authorization"].startswith("Bearer ")
            return httpx.Response(200, json={"choices": [{"message": {"content": "Rotate it."}}]})
        assert req.headers["anthropic-version"] and body["system"]
        return httpx.Response(200, json={"content": [{"type": "text", "text": "Remove it."}]})

    t = httpx.MockTransport(handler)
    g = llm.configure(llm.LLMConfig(retries=1), provider="groq", api_key="gsk_secret_value")
    out = llm.explain(g, {"type": "IN_AADHAAR", "masked": "•••• •••• 0124", "evidence": "raw context"}, t)
    assert out["explanation"] == "Rotate it." and out["is_evidence"] is False and "evidence" not in out["sent_fields"]
    calls.clear()
    a = llm.configure(llm.LLMConfig(retries=1), provider="anthropic", api_key="sk-ant-secret")
    assert llm.explain(a, {"type": "IN_PAN"}, t)["explanation"] == "Remove it."

    bad = httpx.MockTransport(lambda r: httpx.Response(401))
    with pytest.raises(llm.LLMError) as e:
        llm.complete(g, "s", "u", bad)
    assert "gsk_secret_value" not in str(e.value) and "401" in str(e.value)
    with pytest.raises(ValueError):
        llm.configure(llm.LLMConfig(), provider="groq", endpoint="http://insecure")


def test_evidence_masks_values_cut_by_window(client):
    text = "x" * 30 + " Card 4111 1111 1111 1111 " + "y" * 30 + f" Aadhaar {AADHAAR}"
    job = wait(client, client.post("/api/jobs", data={"text": text}).json()["id"])
    for f in job["findings"]:
        assert "4111 1111 1111" not in f["evidence"] and "2345 6789" not in f["evidence"]


def test_person_does_not_span_lines():
    from shield.detect import detect

    names = [e.value for e in detect("Employee Name: Ravi Kumar\nAadhaar 2345 6789 0124") if e.type == "PERSON"]
    assert names == ["Ravi Kumar"]
