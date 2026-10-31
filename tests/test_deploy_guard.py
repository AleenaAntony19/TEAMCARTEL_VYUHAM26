"""Deployment safety: main() must refuse an unprotected public bind. uvicorn.run is faked, so no server starts."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import shield.api  # noqa: F401  registers every route on the app
from shield.api import server

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def started(monkeypatch):
    calls = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: calls.append(kw))
    for name in ("SHIELD_HOST", "SHIELD_PORT", "PORT", "SHIELD_ALLOW_LOCAL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(server, "API_TOKEN", "")
    return calls


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.5", "example.com", ""])
@pytest.mark.parametrize("token", ["", "   ", "short-token"])
def test_public_bind_without_token_is_refused(started, monkeypatch, host, token):
    monkeypatch.setenv("SHIELD_HOST", host)
    monkeypatch.setattr(server, "API_TOKEN", token)
    with pytest.raises(SystemExit, match="SHIELD_API_TOKEN"):
        server.main()
    assert not started


def test_allow_local_on_public_bind_is_refused_even_with_token(started, monkeypatch):
    monkeypatch.setenv("SHIELD_HOST", "0.0.0.0")
    monkeypatch.setenv("SHIELD_ALLOW_LOCAL", "1")
    monkeypatch.setattr(server, "API_TOKEN", "t" * 32)
    with pytest.raises(SystemExit, match="SHIELD_ALLOW_LOCAL"):
        server.main()
    assert not started


def test_public_bind_with_token_starts(started, monkeypatch):
    monkeypatch.setenv("SHIELD_HOST", "0.0.0.0")
    monkeypatch.setattr(server, "API_TOKEN", "t" * 32)
    server.main()
    assert started == [{"host": "0.0.0.0", "port": 8000}]


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "localhost"])
def test_loopback_needs_no_token_and_may_allow_local(started, monkeypatch, host):
    monkeypatch.setenv("SHIELD_HOST", host)
    monkeypatch.setenv("SHIELD_ALLOW_LOCAL", "1")
    server.main()
    assert started[0]["host"] == host


def test_default_bind_stays_loopback(started):
    server.main()
    assert started == [{"host": "127.0.0.1", "port": 8000}]


@pytest.mark.parametrize("env,port", [
    ({"PORT": "10000"}, 10000),
    ({"PORT": "10000", "SHIELD_PORT": "9000"}, 9000),
    ({"PORT": "10000", "SHIELD_PORT": ""}, 10000),
])
def test_port_comes_from_the_environment(started, monkeypatch, env, port):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    server.main()
    assert started[0]["port"] == port


def test_health_is_open_but_the_api_stays_locked(monkeypatch):
    monkeypatch.setattr(server, "API_TOKEN", "t" * 32)
    client = TestClient(server.app)
    assert client.get("/api/health").status_code == 200
    for path in ("/api/config", "/api/health/x", "/api/v1/ledger", "/mcp/"):
        assert client.get(path).status_code == 401, path


def test_env_file_cannot_enter_the_image():
    ignored = (ROOT / ".dockerignore").read_text().split()
    assert {"**/.env", "**/.env.*", ".git", "**/node_modules", "**/dist", "**/*.vsix", "**/.shield", "demo/out", "**/__pycache__"} <= set(ignored)
    sources = [line.split()[1:-1] for line in (ROOT / "Dockerfile").read_text().splitlines() if line.startswith("COPY")]
    assert ["."] not in sources and ["./"] not in sources and not any(".env" in s for src in sources for s in src)


def test_face_detection_survives_threads_with_mixed_image_sizes():
    """Without the model lock this segfaults the interpreter, so it runs in a child process."""
    code = """
import random
from concurrent.futures import ThreadPoolExecutor
import numpy as np
from shield import face
def work(i):
    r = random.Random(i)
    return len(face.vectors(np.zeros((r.randint(80, 500), r.randint(80, 500), 3), dtype=np.uint8)))
with ThreadPoolExecutor(8) as pool:
    print(sum(1 for _ in pool.map(work, range(120))))
"""
    import subprocess
    import sys

    from shield.models import YUNET

    if not YUNET.exists():
        pytest.skip("face models not downloaded")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0 and out.stdout.strip() == "120", out.stderr[-300:]


def test_public_demo_closes_server_wide_switches(monkeypatch):
    monkeypatch.setenv("SHIELD_PUBLIC_DEMO", "1")
    monkeypatch.setattr(server, "LLM_CFG", server.llm.configure(server.llm.LLMConfig(), provider="groq", api_key="server-key"))
    c = TestClient(server.app)
    body = {"provider": "groq", "model": "", "endpoint": "https://evil.example/x", "api_key": "", "timeout": 20, "retries": 1}
    assert c.put("/api/llm", json=body).status_code == 403, "a visitor must not redirect the server key"
    assert server.LLM_CFG.api_key == "server-key" and "evil" not in server.LLM_CFG.endpoint
    assert c.delete("/api/session").status_code == 403, "a visitor must not wipe everyone"
    assert c.delete("/api/v1/scout/enroll").status_code == 403
    assert c.post("/api/llm/test").status_code == 409, "strangers must not spend the server key"
    assert c.get("/api/config").json()["public_demo"] is True


def test_public_demo_does_not_excuse_the_local_crawl_flag(monkeypatch):
    monkeypatch.setenv("SHIELD_PUBLIC_DEMO", "1")
    monkeypatch.setenv("SHIELD_ALLOW_LOCAL", "1")
    with pytest.raises(SystemExit, match="SHIELD_ALLOW_LOCAL"):
        server._refuse_unsafe_bind("0.0.0.0")


def test_public_demo_does_not_open_mcp(monkeypatch):
    monkeypatch.setenv("SHIELD_PUBLIC_DEMO", "1")
    with TestClient(server.app) as c:  # the context starts MCP's session manager
        assert c.post("/mcp/", json={}).status_code == 401, "no token set: MCP stays closed"
        assert c.get("/api/config").status_code == 200, "the website stays open"
        monkeypatch.setattr(server, "API_TOKEN", "demo")
        assert c.post("/mcp/", json={}, headers={"Authorization": "Bearer demo"}).status_code == 401, "a guessable token is not enough"
        monkeypatch.setattr(server, "API_TOKEN", "t" * 32)
        assert c.post("/mcp/", json={}).status_code == 401
        assert c.post("/mcp/", json={}, headers={"Authorization": "Bearer " + "t" * 32}).status_code != 401
