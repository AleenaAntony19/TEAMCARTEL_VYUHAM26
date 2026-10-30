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
from shield.mcp.tools import SESSIONS, open_document, open_workspace, register_session
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

    def decide(findings):  # LLM wants to keep e-mail (allowed) and PAN (floor must override)
        return [{"finding_id": f["id"], "action": "keep" if f["type"] in {"EMAIL_ADDRESS", "IN_PAN"} else "token", "reason": "x"} for f in findings]

    log = []
    res = asyncio.run(run_agentic(sid, GROQ, transport=scripted(decide, log)))
    out = (tmp_path / "hr.txt").read_text() and open(res["output"]).read()
    assert "ravi.kumar@acme.in" in out, "the binding 'keep' verdict must be honoured for non-floor findings"
    assert "ABCPK1234F" not in out and "2345 6789 0124" not in out, "floor types are always redacted"
    assert res["clean"] and res["tokens"] > 0
    by = {a["name"]: a for a in res["agents"]}
    assert all(a["steps"] > 0 for a in res["agents"])
    assert {"SovereignPIIAgent", "VisualLikenessAgent"} == {c["name"] for c in by["MetaPlanner"]["children"]}
    assert by["StatutoryAuditor"]["tools"] == ["validate_checksum"] and by["FormatGuard"]["tools"] == ["measure_layout"]
    assert "adversarial_penetration_test" in by["AdversarialRedTeamAgent"]["tools"]


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
    assert res["fail_safe_defaults"] == 1 and res["clean"]  # every finding redacted, attack still ran
    assert "ravi.kumar@acme.in" not in open(res["output"]).read()


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
    """Adjudicator says keep, but PragmaticDev never challenged it: the keep is not grounded, so it is redacted."""
    monkeypatch.setenv("SHIELD_MCP_ROOT", str(tmp_path))
    doc = tmp_path / "m.txt"
    doc.write_text("Mobile +91 98765 43210\n")
    sid = open_document(str(doc))["session_id"]
    real_scripted = scripted(lambda fs: [{"finding_id": f["id"], "action": "token", "reason": "x"} for f in fs])

    def handler(req):  # adjudicator wants keep; PragmaticDev (from real_scripted) says redact
        body = json.loads(req.content)
        if "Synthesize the debate" in body["messages"][0]["content"] and body["messages"][-1]["role"] != "tool":
            ids = list(json.loads(body["messages"][1]["content"])["debate"])
            return _reply(json.dumps({"keep": [{"finding_id": i, "reason": "trust me"} for i in ids], "actions": []}))
        return real_scripted.handle_request(req)

    res = asyncio.run(run_agentic(sid, GROQ, transport=httpx.MockTransport(handler)))
    assert all(d["action"] != "keep" and "keep rejected" in d["reason"] for d in res["decisions"])
    assert "98765 43210" not in open(res["output"]).read()
