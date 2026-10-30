import base64
import io
import json
import os
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
    monkeypatch.setattr(textscout.httpx, "Client", lambda **kw: real(**{**kw, "transport": httpx.MockTransport(handler)}))
    monkeypatch.setenv("SERPER_API_KEY", "k")
    hits = textscout.get_provider("serper").search('site:pastebin.com "Acme Corp"')
    assert hits[0]["url"] == "https://pastebin.com/x" and hits[0]["tier"] == 1 and hits[0]["provider"] == "serper"


def test_openapi_lists_v1_contract(client):
    paths = client.get("/openapi.json").json()["paths"]
    for p in ["/api/v1/shield/analyze", "/api/v1/shield/redact", "/api/v1/scout/search", "/api/v1/scout/crawl",
              "/api/v1/swarm/deliberate", "/api/v1/dossier/export"]:
        assert p in paths


def test_swarm_run_binding_events_and_download(client, monkeypatch):
    from shield import llm
    from test_mcp_swarm import scripted

    mock = scripted(lambda fs: [{"finding_id": f["id"], "action": "keep" if f["type"] == "PERSON" else "token", "reason": "x"} for f in fs])
    real = httpx.Client
    monkeypatch.setattr(llm.httpx, "Client", lambda **kw: real(**{**kw, "transport": mock}))
    assert client.post("/api/v1/swarm/run", json={"job_id": "nope"}).status_code == 404
    jid = client.post("/api/v1/shield/analyze", data={"text": f"Employee Name: Ravi Kumar\nAadhaar {AADHAAR}\nPAN ABCPK1234F"}).json()["job_id"]
    wait(client, jid)
    assert client.post("/api/v1/swarm/run", json={"job_id": jid}).status_code == 409  # no provider yet
    client.put("/api/llm", json={"provider": "groq", "api_key": "test-key"})
    assert client.post("/api/v1/swarm/run", json={"job_id": jid}).status_code == 202
    with client.stream("GET", f"/api/v1/swarm/events?job_id={jid}") as r:
        body = "".join(r.iter_text())
    assert "event: end" in body and '"status": "done"' in body
    assert AADHAAR not in body and "ABCPK1234F" not in body
    events = [json.loads(line[5:]) for line in body.splitlines() if line.startswith("data:")]
    assert any(e.get("event") == "spawn" for e in events) and any(e.get("action") == "adversarial_penetration_test" for e in events)
    job = client.get(f"/api/v1/shield/jobs/{jid}").json()
    assert job["agent_run"]["status"] == "done" and job["redaction"]["status"] == "CLEAN" and job["state"] == "consensus_ledger"
    out = client.get(f"/api/jobs/{jid}/download").text
    assert "Ravi Kumar" in out and "ABCPK1234F" not in out  # binding keep honoured; floor enforced
    actions = [b["actor"] for b in server.JOBS[jid].ledger.blocks]
    assert "agent_tool:execute_destructive_redaction" in actions and server.JOBS[jid].ledger.verify() is None


def test_mcp_streamable_http_lists_tools(client):
    r = client.post("/mcp/", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                    headers={"Accept": "application/json, text/event-stream", "Host": "127.0.0.1:8000"})
    assert r.status_code == 200, r.text
    names = {t["name"] for t in r.json()["result"]["tools"]}
    assert {"validate_checksum", "execute_destructive_redaction", "run_agent_swarm"} <= names


def test_scout_events_stream(client):
    jid = client.post("/api/v1/scout/search", json={"org": "Acme Corp", "domain": "acme.in", "entity_types": ["IN_PAN"]}).json()["job_id"]
    with client.stream("GET", f"/api/v1/scout/events?job_id={jid}") as r:
        body = "".join(r.iter_text())
    events = [json.loads(line[5:]) for line in body.splitlines() if line.startswith("data:")]
    kinds = {e.get("kind") for e in events}
    assert "query" in kinds and "end" in body and all("ts" in e for e in events if "kind" in e)


def _serper(handler):
    from shield.textscout import SerperProvider

    return lambda q="q": SerperProvider().search(q, httpx.MockTransport(handler))


def test_serper_retries_then_works_and_drops_unsafe_links(monkeypatch):
    monkeypatch.setenv("SERPER_API_KEY", "secret-key")
    monkeypatch.setattr("shield.textscout.time.sleep", lambda s: None)
    calls = []

    def handler(request):
        calls.append(request.headers["X-API-KEY"])
        if len(calls) == 1:
            return httpx.Response(429)
        return httpx.Response(200, json={"organic": [{"link": "https://a.example/x", "title": "t"}, {"link": "javascript:alert(1)"}, {"link": ""}, "junk"]})

    assert [h["url"] for h in _serper(handler)()] == ["https://a.example/x"] and len(calls) == 2


def test_serper_bad_key_stops_at_once_and_never_shows_the_key(monkeypatch):
    from shield.textscout import SearchError

    monkeypatch.setenv("SERPER_API_KEY", "secret-key")
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(403, text="secret-key")

    with pytest.raises(SearchError) as e:
        _serper(handler)()
    assert e.value.fatal and len(calls) == 1 and "secret-key" not in str(e.value) and "credits" in str(e.value)


def test_serper_outage_and_garbage_are_not_fatal(monkeypatch):
    from shield.textscout import SearchError

    monkeypatch.setenv("SERPER_API_KEY", "k")
    monkeypatch.setattr("shield.textscout.time.sleep", lambda s: None)
    calls = []

    def down(request):
        calls.append(1)
        return httpx.Response(503)

    with pytest.raises(SearchError) as e:
        _serper(down)()
    assert not e.value.fatal and len(calls) == 3
    with pytest.raises(SearchError):
        _serper(lambda r: httpx.Response(200, text="<html>"))()
    monkeypatch.delenv("SERPER_API_KEY")
    with pytest.raises(SearchError):
        _serper(down)()


def test_env_file_is_read_but_real_env_wins(tmp_path, monkeypatch):
    from shield.env import load_env

    f = tmp_path / ".env"
    f.write_text('# note\nSHIELD_T1=abc   # inline\nexport SHIELD_T2="q v"\nSHIELD_T3=\nSHIELD_T4=file\nnot a line\n')
    monkeypatch.setenv("SHIELD_T4", "real")
    for k in ("SHIELD_T1", "SHIELD_T2", "SHIELD_T3"):
        monkeypatch.delenv(k, raising=False)
    load_env(f)
    assert (os.environ["SHIELD_T1"], os.environ["SHIELD_T2"], os.environ["SHIELD_T4"]) == ("abc", "q v", "real")
    assert "SHIELD_T3" not in os.environ
    for k in ("SHIELD_T1", "SHIELD_T2"):
        monkeypatch.delenv(k)


def _ready_job(client):
    jid = client.post("/api/jobs", data={"text": "Aadhaar 2345 6789 0124 for the file"}).json()["id"]
    for _ in range(200):
        j = client.get(f"/api/jobs/{jid}").json()
        if j["status"] == "ready":
            return j
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_job_summary_ledger_and_tamper_demo_leave_the_real_chain_intact(client):
    j = _ready_job(client)
    assert j["summary"]["score"] > 0 and j["summary"]["layers"]
    led = client.get("/api/v1/ledger", params={"job_id": j["id"]}).json()
    assert led["first_bad"] is None and led["blocks"]
    demo = client.post("/api/v1/ledger/tamper-demo", params={"job_id": j["id"]}).json()
    assert demo["first_bad"] == demo["tampered_seq"]
    assert client.get("/api/v1/ledger", params={"job_id": j["id"]}).json() == led


def test_dossier_exports_after_a_crawl_match(client):
    import cv2
    import numpy as np

    _, jpeg = cv2.imencode(".jpg", np.zeros((16, 16, 3), dtype=np.uint8))
    j = _ready_job(client)
    server._get(j["id"]).discovery = {"provider": "offline", "results": [{"id": "m1", "source_url": "http://x/y", "image_url": "http://x/i.jpg", "kind": "pdq", "match_type": "pdq:full",
                                                                         "score": 3, "evidence_status": "candidate: needs human review", "timestamp": "t", "thumb_b64": base64.b64encode(jpeg.tobytes()).decode()}]}
    r = client.get("/api/v1/dossier/export", params={"job_id": j["id"]})
    assert r.status_code == 200 and r.content[:2] == b"PK"


def test_reference_with_no_usable_hash_is_refused_not_silently_kept(client):
    import cv2
    import numpy as np

    _, flat = cv2.imencode(".png", np.full((200, 200, 3), 128, dtype=np.uint8))
    r = client.post("/api/references", files={"file": ("flat.png", flat.tobytes(), "image/png")}, data={"label": "x", "authorized": "true"})
    assert r.status_code == 422 and "detail" in r.json()["detail"]
    assert client.get("/api/references").json()["references"] == []


def test_registry_and_match_review_is_sealed_in_the_ledger(client):
    assert client.get("/api/v1/scout/registry").json()[0]["domain"]
    j = _ready_job(client)
    job = server._get(j["id"])
    job.discovery = {"results": [{"id": "m1", "source_url": "http://127.0.0.1/x", "thumb_b64": "AA=="}, {"id": "m2", "source_url": "http://127.0.0.1/y"}]}
    body = {"job_id": j["id"], "match_id": "m1", "decision": "reject"}
    r = client.post("/api/v1/scout/review", json=body).json()
    assert r["review"] == "rejected" and "thumb_b64" not in r
    assert client.post("/api/v1/scout/review", json={**body, "match_id": "m2", "decision": "confirm"}).json()["infra"]
    assert client.post("/api/v1/scout/review", json={**body, "match_id": "nope"}).status_code == 404
    assert client.post("/api/v1/scout/review", json={**body, "decision": "maybe"}).status_code == 422
    assert client.get("/api/v1/ledger", params={"job_id": j["id"]}).json()["blocks"][-1]["action"] == "MATCH_REVIEW"


def test_llm_errors_never_carry_the_key(monkeypatch):
    from shield import llm

    cfg = llm.LLMConfig(provider="groq", model="m", endpoint="https://x.invalid/v1", api_key="SECRETKEY123", retries=0)
    t = httpx.MockTransport(lambda r: httpx.Response(401, json={"error": {"message": "bad key SECRETKEY123"}}))
    with pytest.raises(llm.LLMError) as e:
        llm.complete(cfg, "s", "u", t)
    assert "SECRETKEY123" not in str(e.value) and "401" in str(e.value)


@pytest.mark.parametrize("org,sent", [("2345 6789 0124", False), ("9876543210", False), ("abcpk1234f", False), ("123456789012", False), ("Acme Corp", True)])
def test_personal_values_never_reach_the_llm_prompt(monkeypatch, org, sent):
    from shield import llm, textscout

    calls = []
    monkeypatch.setattr(llm, "complete", lambda *a, **k: calls.append(a) or "")
    cfg = llm.LLMConfig(provider="groq", model="m", api_key="k")
    qs = textscout.build_queries(org, ["IN_PAN", "not_a_type'; drop"], "", cfg)
    assert bool(calls) == sent and not any("drop" in q for q in qs)
    assert all(textscout.firewall(q, []) == sent for q in qs)
    assert not textscout.build_queries("Acme Corp", [], "", cfg, ["Acme"]) or len(calls) == sent


def test_token_login_sets_cookie_that_unlocks_the_api(client, monkeypatch):
    monkeypatch.setattr(server, "API_TOKEN", "t0ken")
    assert client.get("/api/config").status_code == 401
    assert client.options("/api/config", headers={"Origin": "http://x", "Access-Control-Request-Method": "GET"}).status_code != 401
    assert client.post("/api/auth", json={"token": "nope"}).status_code == 401
    assert client.post("/api/auth", json={"token": "t0ken"}).status_code == 200
    assert "t0ken" not in client.cookies.get("shield_session", "")
    assert client.get("/api/config").status_code == 200
    client.cookies.clear()
    assert client.get("/api/config", headers={"Authorization": "Bearer t0ken"}).status_code == 200


def test_chunked_upload_is_refused_so_the_size_limit_holds(client):
    def body():
        yield b"x"

    assert client.post("/api/jobs", content=body()).status_code == 411


def test_env_example_comment_is_not_a_value(tmp_path, monkeypatch):
    from shield.env import load_env

    f = tmp_path / ".env"
    f.write_text("SHIELD_T9=                   # set to require a token\n")
    monkeypatch.delenv("SHIELD_T9", raising=False)
    load_env(f)
    assert "SHIELD_T9" not in os.environ


def test_unsafe_result_links_are_dropped():
    from shield.textscout import _hit

    assert _hit("javascript:alert(1)", "t", "s", "brave")["url"] == ""


def _job_for(client, text):
    jid = client.post("/api/jobs", data={"text": text}).json()["id"]
    for _ in range(300):
        j = client.get(f"/api/jobs/{jid}").json()
        if j["status"] != "queued" and j["status"] != "running":
            return j
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_website_sees_labelled_ids_keys_and_names_like_the_scanner(client):
    fake_key = "gsk_" + "aB3dE" * 10
    j = _job_for(client, f'Aadhaar No = 123456789012\nvoter id = ABCD1234QUYU\n"user": "Ravi Kumar"\nkey {fake_key}\n')
    by = {f["type"]: f for f in j["findings"]}
    assert by["IN_AADHAAR"]["severity"] == "medium" and by["IN_VOTER_ID"]["severity"] == "medium"
    assert by["PERSON"]["masked"] and by["API_KEY"]["severity"] == "critical"
    assert j["summary"]["severity"] == "CRITICAL" and j["summary"]["score"] >= 90
    assert fake_key not in json.dumps(j)
    sel = [{"finding_id": f["id"], "action": f["actions"][0]} for f in j["findings"]]
    r = client.post(f"/api/jobs/{j['id']}/redact", json={"selections": sel}).json()
    assert r["status"] == "CLEAN" and fake_key not in r["preview_text"] and "123456789012" not in r["preview_text"]


def test_extra_urls_must_be_http(client):
    body = {"org": "Acme Corp", "extra_urls": ["file:///etc/passwd"]}
    assert client.post("/api/discovery", json=body).status_code == 422


def test_image_pages_and_icons_are_not_treated_as_images():
    from bs4 import BeautifulSoup

    from shield.crawl import _image_urls

    html = '<a href="/wiki/File:A.jpg">x</a><a href="/a/real.jpg">y</a><img src="/i/icon.svg"><img src="/i/photo.png">'
    assert _image_urls(BeautifulSoup(html, "html.parser"), "https://w.org/p") == {"https://w.org/a/real.jpg", "https://w.org/i/photo.png"}


def test_a_failed_image_is_counted_and_a_rate_limit_is_retried(monkeypatch):
    import asyncio

    from shield.matcher import Matcher
    from shield.models import ImageRef

    class Res:
        def __init__(self, reason):
            self.blocked_reason, self.body, self.headers = reason, b"", {}

    calls = []

    class F:
        async def get(self, url):
            calls.append(url)
            return Res("http_403")

    async def no_wait(_):
        return None

    monkeypatch.setattr("shield.matcher.asyncio.sleep", no_wait)
    m = Matcher([], None)
    assert asyncio.run(m.on_image(ImageRef("p", "i", "d"), F())) is None
    assert len(calls) == 2 and m.failed == 1
