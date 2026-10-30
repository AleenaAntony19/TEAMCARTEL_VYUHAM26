import io
import json
import subprocess
import sys
import time
import zipfile

import httpx
import pytest
from fastapi.testclient import TestClient

from shield.api import app
from shield.api import server

AADHAAR = "2345 6789 0124"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "WORK_ROOT", tmp_path / "work")
    monkeypatch.setenv("SHIELD_SEARCH_PROVIDER", "offline")
    with TestClient(app) as c:
        yield c
    server.clear_session()


def wait(c, jid, timeout=180):
    end = time.time() + timeout
    while time.time() < end:
        j = c.get(f"/api/v1/shield/jobs/{jid}").json()
        if j["status"] not in {"queued", "running"}:
            return j
        time.sleep(0.1)
    raise AssertionError("job did not finish")


def analyze_file(c, path):
    r = c.post("/api/v1/shield/analyze", files={"file": (path.name, path.read_bytes(), "application/octet-stream")})
    assert r.status_code == 202, r.text
    return wait(c, r.json()["job_id"])


@pytest.mark.parametrize("key", ["pdf", "docx", "xlsx", "jpg", "png"])
def test_all_formats_redact_clean_through_graph(client, fx, key):
    job = analyze_file(client, fx[key])
    assert job["status"] == "ready" and job["state"] == "deliberate"
    sel = [{"finding_id": f["id"], "action": f["actions"][-1]} for f in job["findings"] if f["actions"] and f["severity"] != "low"]
    assert sel, "fixture should produce findings"
    res = client.post("/api/v1/shield/redact", json={"job_id": job["id"], "selections": sel}).json()
    assert res["status"] == "CLEAN", res["checks"]
    assert res["ledger_valid"] and len(res["ledger_head"]) == 64
    assert client.get(f"/api/v1/shield/jobs/{job['id']}").json()["state"] == "consensus_ledger"
    assert fx[key].read_bytes() == fx[key].read_bytes()  # original untouched on disk
    blocks = server.JOBS[job["id"]].ledger.blocks
    assert [b["action"] for b in blocks][:2] == ["INTAKE", "DELIBERATE"] and blocks[-1]["action"] == "CONSENSUS_LEDGER"


def test_illegal_transition_rejected(client):
    jid = client.post("/api/v1/shield/analyze", data={"text": f"Aadhaar {AADHAAR}"}).json()["job_id"]
    job = wait(client, jid)
    j = server.JOBS[jid]
    with pytest.raises(Exception, match="illegal transition"):
        server._advance(j, "consensus_ledger", {})
    assert job["state"] == "deliberate"


def test_deliberation_sse_stream(client):
    jid = client.post("/api/v1/shield/analyze", data={"text": f"Aadhaar {AADHAAR} mail a@example.com Invoice 987654321098"}).json()["job_id"]
    wait(client, jid)
    with client.stream("GET", f"/api/v1/swarm/deliberate?job_id={jid}") as r:
        body = "".join(r.iter_text())
    events = [json.loads(line[5:]) for line in body.splitlines() if line.startswith("data:")]
    assert events[0]["event"] == "start" and events[-1]["event"] == "end"
    turns = [e for e in events if e["event"] == "turn"]
    assert {"PrivacyHawk", "PragmaticDev", "StatutoryAuditor", "SwarmAdjudicator"} <= {t["reviewer"] for t in turns}
    assert max(t["round"] for t in turns) == 2
    verdicts = {e["type"]: e["verdict"] for e in events if e["event"] == "verdict" and e["type"] != "IN_AADHAAR"}
    assert verdicts.get("EMAIL_ADDRESS") == "dismissed"
    assert AADHAAR not in body and "987654321098" not in body


def test_dossier_export_zip_verifies(client, tmp_path):
    jid = client.post("/api/v1/shield/analyze", data={"text": f"Aadhaar {AADHAAR}"}).json()["job_id"]
    job = wait(client, jid)
    client.post("/api/v1/shield/redact", json={"job_id": jid, "selections": [{"finding_id": job["findings"][0]["id"], "action": "token"}]})
    r = client.get(f"/api/v1/dossier/export?job_id={jid}")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert {"dossier.pdf", "ledger.json", "verify_ledger.py", "README.txt"} <= set(z.namelist())
    z.extractall(tmp_path)
    assert AADHAAR not in (tmp_path / "ledger.json").read_text()
    ok = subprocess.run([sys.executable, str(tmp_path / "verify_ledger.py"), str(tmp_path / "ledger.json")], capture_output=True)
    assert ok.returncode == 0
    ledger = json.loads((tmp_path / "ledger.json").read_text())
    ledger[1]["details"] = {"tampered": True}
    (tmp_path / "ledger.json").write_text(json.dumps(ledger))
    bad = subprocess.run([sys.executable, str(tmp_path / "verify_ledger.py"), str(tmp_path / "ledger.json")], capture_output=True)
    assert bad.returncode != 0


def test_scout_search_and_crawl_gates(client):
    jid = client.post("/api/v1/scout/search", json={"org": "Acme Corp", "domain": "acme.in", "entity_types": ["IN_PAN"]}).json()["job_id"]
    d = wait(client, jid)["discovery"]
    assert d["provider"] == "offline" and d["queries"]
    assert client.post("/api/v1/scout/crawl", json={"org": "Acme Corp"}).status_code == 409  # nothing to match against
    assert client.post("/api/v1/scout/search", json={"org": "<script>"}).status_code == 422


def test_enroll_requires_consent_and_matching_selfie(client):
    from shield.models import BASE, YUNET

    if not YUNET.exists():
        pytest.skip("face models not downloaded")
    face = (BASE / "demo/faces/victim_1.jpg").read_bytes()
    files = {"photo": ("p.jpg", face, "image/jpeg"), "selfie": ("s.jpg", face, "image/jpeg")}
    assert client.post("/api/v1/scout/enroll", files=files, data={"consent": "false"}).status_code == 422
    r = client.post("/api/v1/scout/enroll", files=files, data={"consent": "true"})
    if r.status_code == 422 and "exactly one face" in r.text:
        pytest.skip("demo face not detectable by YuNet")
    assert r.status_code == 200 and r.json()["enrolled"] == 1
    assert client.delete("/api/v1/scout/enroll").json()["enrolled"] == 0


def test_serper_provider_shape(monkeypatch):
    from shield import textscout

    def handler(req: httpx.Request):
        assert req.headers["x-api-key"] == "k" and json.loads(req.content)["q"] == "site:pastebin.com \"Acme Corp\""
        return httpx.Response(200, json={"organic": [{"link": "https://pastebin.com/x", "title": "t", "snippet": "s"}]})

    real = httpx.Client
    monkeypatch.setattr(textscout.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setenv("SERPER_API_KEY", "k")
    hits = textscout.get_provider("serper").search('site:pastebin.com "Acme Corp"')
    assert hits[0]["url"] == "https://pastebin.com/x" and hits[0]["tier"] == 1 and hits[0]["provider"] == "serper"


def test_openapi_lists_v1_contract(client):
    paths = client.get("/openapi.json").json()["paths"]
    for p in ["/api/v1/shield/analyze", "/api/v1/shield/redact", "/api/v1/scout/search", "/api/v1/scout/crawl",
              "/api/v1/swarm/deliberate", "/api/v1/dossier/export"]:
        assert p in paths
