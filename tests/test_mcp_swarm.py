"""MCP tools + agent swarm. The LLM is replaced by a scripted provider at the HTTP layer (httpx.MockTransport),
so the ReAct loop, native tool-call parsing, and every MCP tool run for real."""
import ast
import asyncio
import json
import secrets
import string
import subprocess

import httpx
import pytest

from shield import llm, verify
from shield.mcp import server
from shield.mcp.tools import SESSIONS, list_findings, open_document, open_workspace, register_session
from shield.models import Entity
from shield.swarm import run_agentic

GROQ = llm.configure(llm.LLMConfig(retries=0), provider="groq", api_key="test-key")


def _reply(content="", calls=None):
    msg = {"content": content}
    if calls:
        msg["tool_calls"] = [{"id": f"c{i}", "type": "function", "function": {"name": n, "arguments": json.dumps(a)}} for i, (n, a) in enumerate(calls)]
    return httpx.Response(200, json={"choices": [{"message": msg}], "usage": {"total_tokens": 100}})


def scripted(decide=None, log=None):
    """Plays each agent: first turn calls its tool(s), next turn returns the JSON verdict."""

    def handler(req: httpx.Request):
        body = json.loads(req.content)
        system, msgs = body["messages"][0]["content"], body["messages"][1:]
        task = json.loads(msgs[0]["content"])
        tools = {t["function"]["name"] for t in body.get("tools", [])}
        done = msgs[-1]["role"] == "tool"
        findings = task.get("findings") or [{"id": i} for i in task.get("finding_ids", [])]
        ids = [f["id"] if isinstance(f, dict) else f for f in findings]
        if log is not None:
            log.append(system.split(".")[0][:40])
        if "You plan a privacy run" in system:
            if done:
                return _reply(json.dumps({"plan": "spawned", "spawned": ["SovereignPIIAgent", "VisualLikenessAgent"]}))
            if task["kind"] == "workspace":
                return _reply(calls=[("spawn_specialist_agent", {"role": "SecretsAuditor", "goal": "audit", "allowed_tools": ["list_code_findings"]})])
            return _reply(calls=[("spawn_specialist_agent", {"role": "SovereignPIIAgent", "goal": "prove ids", "allowed_tools": ["validate_checksum"]}),
                                 ("spawn_specialist_agent", {"role": "VisualLikenessAgent", "goal": "hash images", "allowed_tools": ["compute_perceptual_pdq"]})])
        if done or not tools:
            if "Synthesize the debate" in system:
                rows = [{"id": i, "type": r["type"]} for i, r in task["debate"].items()]
                want = {d["finding_id"]: d["action"] for d in decide(rows)}
                return _reply(json.dumps({"keep": [{"finding_id": i, "reason": "placeholder"} for i, a in want.items() if a == "keep"],
                                          "actions": [{"finding_id": i, "action": a} for i, a in want.items() if a != "keep"]}))
            if "optimize code" in system:
                return _reply(json.dumps({"proposals": [{"id": f["id"], "action": "move_to_env", "reason": "secret"} for f in findings]}))
            keep = set()
            if "You are PragmaticDev" in system and decide:
                keep = {d["finding_id"] for d in decide(findings) if d["action"] == "keep"}
            return _reply(json.dumps({"opinions": [{"id": i, "stance": "keep" if i in keep else "redact", "reason": "tool evidence"} for i in ids],
                                      "clean": True, "summary": "ok"}))
        first = sorted(tools)[0]
        args = {}
        if first == "validate_checksum":
            sid = next((i for i in ids if i), None)
            args = {"finding_id": sid or "none"}
        return _reply(calls=[(first, args)])

    return httpx.MockTransport(handler)


def test_mcp_validate_checksum_truth(tmp_path):
    s = register_session(tmp_path / "x.txt", {"text": ""}, {"ok": Entity("IN_AADHAAR", "2345 6789 0124", 0, 14, 0.9, "text"),
                                                            "bad": Entity("IN_AADHAAR", "2345 6789 0128", 0, 14, 0.9, "text")}, tmp_path)

    async def call(fid):
        r = await server.call_tool("validate_checksum", {"session_id": s.id, "finding_id": fid})
        return json.loads(r.content[0].text)

    assert asyncio.run(call("ok"))["valid"] is True
    assert asyncio.run(call("bad"))["valid"] is False and asyncio.run(call("bad"))["algorithm"] == "Verhoeff_D5"


def test_binding_verdict_drives_redaction_with_safety_floor(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_ROOT", str(tmp_path))
    doc = tmp_path / "hr.txt"
    doc.write_text("Aadhaar 2345 6789 0124\nPAN ABCPK1234F\nmail ravi.kumar@acme.in\n")
    sid = open_document(str(doc))["session_id"]

    ids = {f["type"]: f["id"] for f in list_findings(sid)["findings"]}
    real = scripted(lambda fs: [{"finding_id": f["id"], "action": "token", "reason": "x"} for f in fs])

    def handler(req):  # PragmaticDev and the adjudicator both want every finding kept, even PAN, which is never debated
        body = json.loads(req.content)
        system, last = body["messages"][0]["content"], body["messages"][-1]["role"]
        if "You are PragmaticDev" in system and last == "tool":
            return _reply(json.dumps({"opinions": [{"id": i, "stance": "keep", "reason": "x"} for i in ids.values()]}))
        if "Synthesize the debate" in system:
            return _reply(json.dumps({"keep": [{"finding_id": i, "reason": "x"} for i in ids.values()], "actions": []}))
        return real.handle_request(req)

    events = []
    res = asyncio.run(run_agentic(sid, GROQ, events.append, httpx.MockTransport(handler)))
    out = open(res["output"]).read()
    assert "ravi.kumar@acme.in" in out, "the binding 'keep' verdict must be honoured for non-floor findings"
    assert "ABCPK1234F" not in out and "2345 6789 0124" not in out, "floor types are always redacted"
    assert res["clean"] and res["tokens"] > 0
    by = {a["name"]: a for a in res["agents"]}
    assert all(a["steps"] > 0 for a in res["agents"])
    assert {"SovereignPIIAgent", "VisualLikenessAgent"} == {c["name"] for c in by["MetaPlanner"]["children"]}
    assert by["StatutoryAuditor"]["tools"] == ["validate_checksum"] and by["FormatGuard"]["tools"] == ["measure_layout"]
    assert {"PrivacyHawk", "SwarmAdjudicator"} <= set(by), "a challenge starts the debate"
    assert "AdversarialRedTeamAgent" not in by and res["attacks"], "the attack runs as a tool, without a model"
    assert any(e.get("agent") == "AdversarialRedTeamAgent" and e.get("event") == "final" and e["clean"] for e in events)


def test_nothing_contested_is_binding_without_hawk_or_adjudicator(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_ROOT", str(tmp_path))
    doc = tmp_path / "a.txt"
    doc.write_text("mail ravi.kumar@acme.in\n")
    sid = open_document(str(doc))["session_id"]
    res = asyncio.run(run_agentic(sid, GROQ, transport=scripted(lambda fs: [{"finding_id": f["id"], "action": "token", "reason": "x"} for f in fs])))
    assert not {"PrivacyHawk", "SwarmAdjudicator"} & {a["name"] for a in res["agents"]}
    assert res["fail_safe_defaults"] == 0 and res["clean"] and all(d["action"] != "keep" for d in res["decisions"])
    assert "ravi.kumar@acme.in" not in open(res["output"]).read()


def test_self_healing_replans_after_leak(fx, tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_ROOT", str(fx["pdf"].parent))
    sid = open_document(str(fx["pdf"]))["session_id"]
    real, calls = verify.attack, []

    def flaky(path, originals):  # first attack "recovers" a value; later ones are real
        calls.append(path)
        res = real(path, originals)
        if len(calls) == 1:
            res[0].passed, res[0].evidence = False, ["1 original value(s) recoverable from text"]
        return res

    monkeypatch.setattr(verify, "attack", flaky)
    res = asyncio.run(run_agentic(sid, GROQ, transport=scripted(lambda fs: [{"finding_id": f["id"], "action": "remove", "reason": "x"} for f in fs])))
    assert res["cycles"] == 2 and res["clean"], res
    assert "FormatGuard" not in {a["name"] for a in res["agents"]}, "PDFs always fill boxes: nothing for it to choose"
    assert res["decisions"] and all(d["action"] == "remove" for d in res["decisions"])
    assert any(a["name"] == "MetaPlanner" and "execute_destructive_redaction" in a["tools"] for a in res["agents"][1:])


def test_image_session_spawns_visual_specialist(fx, tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_ROOT", str(fx["png"].parent))
    sid = open_document(str(fx["png"]))["session_id"]
    res = asyncio.run(run_agentic(sid, GROQ, transport=scripted(lambda fs: [{"finding_id": f["id"], "action": "remove", "reason": "x"} for f in fs])))
    child = next(c for c in res["agents"][0]["children"] if c["name"] == "VisualLikenessAgent")
    assert child["tools"] == ["compute_perceptual_pdq"] and child["steps"] > 0
    assert res["clean"]


def test_refactorbot_workspace_fix_is_atomic_and_parses(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    key = "sk-proj-" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(48))
    (repo / "app/config.py").write_text(f'import json\nOPENAI_API_KEY = "{key}"\nprint(json.dumps({{}}))\n')
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    monkeypatch.setenv("SHIELD_MCP_ROOT", str(tmp_path))
    sid = open_workspace(str(repo))["session_id"]
    assert SESSIONS[sid].kind == "workspace"

    def decide(findings):
        return [{"finding_id": f["id"], "action": "move_to_env" if "move_to_env" in (f.get("fixes") or []) else "keep", "reason": "x"} for f in findings]

    res = asyncio.run(run_agentic(sid, GROQ, transport=scripted(decide)))
    src = (repo / "app/config.py").read_text()
    ast.parse(src)
    assert key not in src and 'os.environ["OPENAI_API_KEY"]' in src
    assert key in (repo / ".env").read_text() and list((repo / ".shield/backup").iterdir())
    assert res["clean"] and any(a["name"] == "RefactorBot" for a in res["agents"])


def test_llm_errors_fail_safe_never_skip_verification(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_ROOT", str(tmp_path))
    doc = tmp_path / "a.txt"
    doc.write_text("mail ravi.kumar@acme.in\n")
    sid = open_document(str(doc))["session_id"]
    down = httpx.MockTransport(lambda r: httpx.Response(503))
    res = asyncio.run(run_agentic(sid, GROQ, transport=down))
    # nothing could be challenged, so the redact-everything plan is binding, not a fallback
    assert res["fail_safe_defaults"] == 0 and res["clean"] and res["attacks"]  # every finding redacted, attack still ran
    assert all(d["action"] != "keep" for d in res["decisions"])
    assert "ravi.kumar@acme.in" not in open(res["output"]).read()


def test_adjudicator_failure_redacts_all_even_what_was_challenged(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_ROOT", str(tmp_path))
    doc = tmp_path / "a.txt"
    doc.write_text("mail ravi.kumar@acme.in\n")
    sid = open_document(str(doc))["session_id"]
    real = scripted(lambda fs: [{"finding_id": f["id"], "action": "keep", "reason": "x"} for f in fs])

    def handler(req):
        if "Synthesize the debate" in json.loads(req.content)["messages"][0]["content"]:
            return httpx.Response(503)
        return real.handle_request(req)

    res = asyncio.run(run_agentic(sid, GROQ, transport=httpx.MockTransport(handler)))
    assert res["fail_safe_defaults"] == 1 and res["clean"] and res["attacks"]
    assert "ravi.kumar@acme.in" not in open(res["output"]).read()


def test_malformed_opinion_still_redacts(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_ROOT", str(tmp_path))
    doc = tmp_path / "a.txt"
    doc.write_text("mail ravi.kumar@acme.in\n")
    sid = open_document(str(doc))["session_id"]
    real = scripted()

    def handler(req):
        body = json.loads(req.content)
        if "You are PragmaticDev" in body["messages"][0]["content"] and body["messages"][-1]["role"] == "tool":
            return _reply(json.dumps({"opinions": [{"stance": "keep"}]}))
        return real.handle_request(req)

    res = asyncio.run(run_agentic(sid, GROQ, transport=httpx.MockTransport(handler)))
    assert res["clean"] and "ravi.kumar@acme.in" not in open(res["output"]).read()


def test_mcp_resources_and_tool_list(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_ROOT", str(tmp_path))
    doc = tmp_path / "a.txt"
    doc.write_text("Aadhaar 2345 6789 0124\n")
    sid = open_document(str(doc))["session_id"]

    async def go():
        names = {t.name for t in await server.list_tools()}
        layers = await server.read_resource(f"shield://doc/{sid}/layers")
        return names, layers

    names, layers = asyncio.run(go())
    assert {"validate_checksum", "extract_ocr_region", "compute_perceptual_pdq", "compute_pca_projection", "execute_destructive_redaction",
            "refactor_code_secret", "adversarial_penetration_test", "run_agent_swarm"} <= names
    assert "2345 6789" not in str(layers)
    with pytest.raises(Exception):
        open_document("/etc/hosts")  # outside SHIELD_MCP_ROOT


def test_mcp_stdio_transport_end_to_end(tmp_path):
    """Real JSON-RPC over stdio: spawn `python -m shield.mcp`, list tools, open a doc, validate a checksum."""
    import os
    import sys

    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    doc = tmp_path / "a.txt"
    doc.write_text("Aadhaar 2345 6789 0124\n")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    params = StdioServerParameters(command=sys.executable, args=["-m", "shield.mcp"],
                                   env={**os.environ, "PYTHONPATH": root, "SHIELD_MCP_ROOT": str(tmp_path)})

    async def go():
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                names = {t.name for t in (await s.list_tools()).tools}
                opened = json.loads((await s.call_tool("open_document", {"path": str(doc)})).content[0].text)
                fid = opened["findings"][0]["id"]
                check = json.loads((await s.call_tool("validate_checksum", {"session_id": opened["session_id"], "finding_id": fid})).content[0].text)
                return names, opened, check

    names, opened, check = asyncio.run(go())
    assert "run_agent_swarm" in names and check["valid"] is True
    assert "2345 6789 0124" not in json.dumps(opened)


def test_keep_without_pragmatic_challenge_is_rejected(tmp_path, monkeypatch):
    """PragmaticDev challenges the e-mail, the adjudicator keeps the mobile instead: that keep is not grounded, so it is redacted."""
    monkeypatch.setenv("SHIELD_MCP_ROOT", str(tmp_path))
    doc = tmp_path / "m.txt"
    doc.write_text("Mobile +91 98765 43210\nmail ravi.kumar@acme.in\n")
    sid = open_document(str(doc))["session_id"]
    ids = {f["type"]: f["id"] for f in list_findings(sid)["findings"]}
    mobile, email = ids["MOBILE_IN"], ids["EMAIL_ADDRESS"]
    real = scripted(lambda fs: [{"finding_id": f["id"], "action": "keep" if f["id"] == email else "token", "reason": "x"} for f in fs])

    def handler(req):
        if "Synthesize the debate" in json.loads(req.content)["messages"][0]["content"]:
            return _reply(json.dumps({"keep": [{"finding_id": mobile, "reason": "trust me"}], "actions": []}))
        return real.handle_request(req)

    events = []
    res = asyncio.run(run_agentic(sid, GROQ, events.append, httpx.MockTransport(handler)))
    assert "SwarmAdjudicator" in {a["name"] for a in res["agents"]}, "the adjudicator must have run for this to prove anything"
    decision = {d["finding_id"]: d for d in res["decisions"]}
    assert decision[mobile]["action"] != "keep" and "keep rejected" in decision[mobile]["reason"]
    assert next(e for e in events if e.get("event") == "binding_plan")["rejected_keeps"] == 1
    out = open(res["output"]).read()
    assert "98765 43210" not in out and "ravi.kumar@acme.in" not in out
