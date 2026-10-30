"""Smoke-test a built engine (CI release gate): python scripts/smoke_engine.py dist/shield-engine

Runs the frozen binary with a minimal environment: scan finds a planted key + Aadhaar + SAST issue,
the LLM helper starts, and the MCP stdio server lists its tools.
"""
import asyncio
import json
import os
import secrets
import string
import subprocess
import sys
import tempfile
from pathlib import Path

bundle = Path(sys.argv[1]).resolve()
exe = bundle / ("shield-engine.exe" if os.name == "nt" else "shield-engine")
assert exe.exists(), f"missing {exe}"
env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE") if k in os.environ}

with tempfile.TemporaryDirectory() as tmp:
    repo = Path(tmp)
    (repo / "app").mkdir()
    key = "sk-proj-" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(48))
    (repo / "app/config.py").write_text(f'import yaml\nKEY = "{key}"\nyaml.load(open("x"), Loader=yaml.Loader)\n')
    (repo / "users.json").write_text('{"aadhaar": "2345 6789 0124"}\n')
    out = subprocess.run([str(exe), "scan", str(repo), "--format", "json", "--no-ocr"], capture_output=True, text=True, env=env, timeout=600)
    assert out.returncode == 1, (out.returncode, out.stderr[-2000:])
    res = json.loads(out.stdout)
    rules = {f["rule"] for f in res["findings"]}
    assert {"OpenAI Token", "IN_AADHAAR", "B506"} <= rules, (rules, res["stats"])
    assert key not in out.stdout, "raw secret in output"
    print("scan ok:", sorted(rules), res["stats"]["engines"])

llm = subprocess.run([str(exe), "llm", "test"], capture_output=True, text=True, env=env, timeout=120)
assert json.loads(llm.stdout)["error"] == "no LLM provider configured", llm.stdout + llm.stderr
print("llm helper ok (and ssl imports)")


async def mcp() -> int:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    async with stdio_client(StdioServerParameters(command=str(exe), args=["mcp"], env=env)) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            return len((await s.list_tools()).tools)


n = asyncio.run(mcp())
assert n >= 14, n
print(f"mcp ok: {n} tools")
