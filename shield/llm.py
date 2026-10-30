"""LLM providers for optional explanations. Deterministic analyzers never depend on this.

What is sent: finding type, rule, analyzer, severity and *masked* evidence only.
One exception: codescan/cognitive.py sends file text, only on an explicit per-scan request.
Keys come from env (GROQ_API_KEY / ANTHROPIC_API_KEY) or are set at runtime in memory; never logged or returned.
"""
from __future__ import annotations

import json
import re
import threading
import os
import sys
import time
from dataclasses import dataclass, field, replace

import httpx

PROVIDERS = {
    "groq": {
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "model": "openai/gpt-oss-20b",
        "key_env": "GROQ_API_KEY",
    },
    "anthropic": {
        "endpoint": "https://api.anthropic.com/v1/messages",
        "model": "claude-haiku-5-5",
        "key_env": "ANTHROPIC_API_KEY",
    },
}

SYSTEM = (
    "You explain privacy/security scanner findings to developers. You only see masked evidence. "
    "In at most 4 sentences: why it matters and how to remediate. Do not guess the hidden value. "
    "Do not claim the finding is confirmed beyond what the analyzer reported."
)


class LLMError(RuntimeError):
    pass


@dataclass
class LLMConfig:
    provider: str = "none"  # none | groq | anthropic
    model: str = ""
    endpoint: str = ""
    timeout: float = 20.0
    retries: int = 4
    api_key: str = field(default="", repr=False)

    def public(self) -> dict:
        return {
            "provider": self.provider,
            "model": self.model,
            "endpoint": self.endpoint,
            "timeout": self.timeout,
            "retries": self.retries,
            "key_set": bool(self.api_key),
        }


def from_env() -> LLMConfig:
    provider = os.getenv("SHIELD_LLM_PROVIDER", "none").strip().lower()
    if os.getenv("SHIELD_LOCAL_ONLY") == "1":
        provider = "none"
    return configure(
        LLMConfig(),
        provider=provider,
        model=os.getenv("SHIELD_LLM_MODEL", ""),
        endpoint=os.getenv("SHIELD_LLM_ENDPOINT", ""),
        timeout=float(os.getenv("SHIELD_LLM_TIMEOUT", "20")),
        retries=int(os.getenv("SHIELD_LLM_RETRIES", "2")),
    )


def configure(cfg: LLMConfig, **changes) -> LLMConfig:
    """Return a validated copy. An empty api_key/model/endpoint keeps the provider default or env key."""
    provider = (changes.get("provider") or cfg.provider or "none").lower()
    if provider not in {"none", *PROVIDERS}:
        raise ValueError(f"unknown provider '{provider}' (use none, groq or anthropic)")
    timeout = float(changes.get("timeout") or cfg.timeout)
    retries = int(changes["retries"]) if changes.get("retries") is not None else cfg.retries
    if not (1 <= timeout <= 120) or not (0 <= retries <= 5):
        raise ValueError("timeout must be 1-120 s and retries 0-5")
    if provider == "none":
        return LLMConfig(timeout=timeout, retries=retries)
    spec = PROVIDERS[provider]
    switched = provider != cfg.provider
    endpoint = changes.get("endpoint") or ("" if switched else cfg.endpoint) or spec["endpoint"]
    if not endpoint.startswith("https://"):
        raise ValueError("endpoint must be https://")
    key = changes.get("api_key") or ("" if switched else cfg.api_key) or os.getenv(spec["key_env"], "")
    return replace(
        cfg,
        provider=provider,
        model=changes.get("model") or ("" if switched else cfg.model) or spec["model"],
        endpoint=endpoint,
        timeout=timeout,
        retries=retries,
        api_key=key,
    )


def _request(cfg: LLMConfig, system: str, user: str, max_tokens: int, json_mode: bool) -> tuple[dict, dict]:
    if cfg.provider == "groq":
        body = {
            "model": cfg.model,
            "max_tokens": max_tokens,
            "temperature": 0.2,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        if cfg.model.startswith("openai/gpt-oss"):
            body["reasoning_effort"] = "low"  # reasoning tokens count against max_tokens; keep them short
        return ({"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json"}, body)
    return (
        {"x-api-key": cfg.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        {"model": cfg.model, "max_tokens": max_tokens, "system": system, "messages": [{"role": "user", "content": user}]},
    )


def _text(cfg: LLMConfig, data: dict) -> str:
    if cfg.provider == "groq":
        return data["choices"][0]["message"]["content"].strip()
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()


def parse_json(text: str) -> dict | None:
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        return None
    try:
        v = json.loads(m.group(0))
        return v if isinstance(v, dict) else None
    except ValueError:
        return None


_PACE = {"lock": threading.Lock(), "not_before": 0.0}
MAX_WAIT = float(os.getenv("SHIELD_LLM_MAX_WAIT", "20"))


def _seconds(v: str | None) -> float:
    """Parse rate-limit reset values like '7.66s', '1m2.5s', '450ms'."""
    if not v:
        return 0.0
    total = 0.0
    for num, unit in re.findall(r"([\d.]+)(ms|h|m|s)", v):
        total += float(num) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]
    return total


def _pace(resp: httpx.Response) -> None:
    """Shared token-bucket pacing from provider headers so parallel agents back off before hitting 429."""
    remaining = resp.headers.get("x-ratelimit-remaining-tokens") or resp.headers.get("anthropic-ratelimit-tokens-remaining")
    if remaining is not None and remaining.isdigit() and int(remaining) < 2500:
        reset = _seconds(resp.headers.get("x-ratelimit-reset-tokens")) or 5.0
        with _PACE["lock"]:
            _PACE["not_before"] = max(_PACE["not_before"], time.monotonic() + min(MAX_WAIT, reset))


def _post(cfg: LLMConfig, headers: dict, body: dict, transport: httpx.BaseTransport | None) -> dict:
    """POST with bounded retries; honours retry-after. Errors never include headers (they hold the key)."""
    if cfg.provider == "none":
        raise LLMError("no LLM provider configured")
    if not cfg.api_key:
        raise LLMError(f"no API key set for {cfg.provider}")
    last = "unknown error"
    with httpx.Client(timeout=cfg.timeout, transport=transport) as client:
        for attempt in range(cfg.retries + 1):
            wait = _PACE["not_before"] - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            try:
                resp = client.post(cfg.endpoint, headers=headers, json=body)
            except httpx.HTTPError as exc:
                last = type(exc).__name__
            else:
                _pace(resp)
                if resp.status_code == 200:
                    try:
                        return resp.json()
                    except ValueError:
                        raise LLMError("unexpected response shape") from None
                try:
                    err_json = resp.json()
                    err_msg = err_json.get("error", {}).get("message") if isinstance(err_json, dict) else ""
                    last = f"HTTP {resp.status_code} ({err_msg})" if err_msg else f"HTTP {resp.status_code}"
                except Exception:
                    last = f"HTTP {resp.status_code}"
                if resp.status_code not in {408, 429, 500, 502, 503, 504, 529}:
                    break
                if attempt < cfg.retries and resp.headers.get("retry-after"):
                    try:  # provider rate limit: wait what it asks, bounded so a request never hangs
                        time.sleep(min(MAX_WAIT, float(resp.headers["retry-after"])))
                        continue
                    except ValueError:
                        pass
            if attempt < cfg.retries:
                time.sleep(min(4.0, 0.5 * 2**attempt))
    # provider text can echo the request: the key must never reach an error, the UI or a log
    raise LLMError(f"{cfg.provider} request failed: {last}".replace(cfg.api_key, "***")[:300])


def complete(
    cfg: LLMConfig, system: str, user: str, transport: httpx.BaseTransport | None = None,
    max_tokens: int = 600, json_mode: bool = False,
) -> str:
    headers, body = _request(cfg, system, user, max_tokens, json_mode)
    try:
        return _text(cfg, _post(cfg, headers, body, transport))
    except (KeyError, IndexError, TypeError):
        raise LLMError("unexpected response shape") from None


def chat_tools(
    cfg: LLMConfig, system: str, history: list[dict], tools: list[dict],
    transport: httpx.BaseTransport | None = None, max_tokens: int = 1200,
) -> dict:
    """One native tool-calling turn.

    history items: {"role": "user", "content": str}
                   {"role": "assistant", "text": str, "tool_calls": [{"id", "name", "args"}]}
                   {"role": "tool", "id": str, "name": str, "content": str}
    tools: [{"name", "description", "input_schema"}]  (MCP Tool shape)
    returns {"text": str, "tool_calls": [{"id", "name", "args"}]}
    """
    if cfg.provider == "groq":
        msgs: list[dict] = [{"role": "system", "content": system}]
        for h in history:
            if h["role"] == "user":
                msgs.append({"role": "user", "content": h["content"]})
            elif h["role"] == "assistant":
                m = {"role": "assistant", "content": h.get("text") or ""}
                if h.get("tool_calls"):
                    m["tool_calls"] = [{"id": c["id"], "type": "function", "function": {"name": c["name"], "arguments": json.dumps(c["args"])}} for c in h["tool_calls"]]
                msgs.append(m)
            else:
                msgs.append({"role": "tool", "tool_call_id": h["id"], "content": h["content"]})
        body = {"model": cfg.model, "messages": msgs, "max_tokens": max_tokens, "temperature": 0.1,
                "tools": [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}} for t in tools],
                "tool_choice": "auto"}
        if cfg.model.startswith("openai/gpt-oss"):
            body["reasoning_effort"] = "low"
        data = _post(cfg, {"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json"}, body, transport)
        try:
            msg = data["choices"][0]["message"]
            calls = [{"id": c["id"], "name": c["function"]["name"], "args": json.loads(c["function"].get("arguments") or "{}")} for c in msg.get("tool_calls") or []]
        except (KeyError, IndexError, TypeError, ValueError):
            raise LLMError("unexpected tool-call response shape") from None
        u = data.get("usage") or {}
        return {"text": msg.get("content") or "", "tool_calls": calls, "tokens": int(u.get("total_tokens") or 0)}

    if cfg.provider == "anthropic":
        msgs = []
        for h in history:
            if h["role"] == "user":
                msgs.append({"role": "user", "content": h["content"]})
            elif h["role"] == "assistant":
                blocks = ([{"type": "text", "text": h["text"]}] if h.get("text") else []) + [
                    {"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["args"]} for c in h.get("tool_calls", [])]
                msgs.append({"role": "assistant", "content": blocks})
            else:
                block = {"type": "tool_result", "tool_use_id": h["id"], "content": h["content"]}
                if msgs and msgs[-1]["role"] == "user" and isinstance(msgs[-1]["content"], list):
                    msgs[-1]["content"].append(block)  # consecutive results share one user turn
                else:
                    msgs.append({"role": "user", "content": [block]})
        body = {"model": cfg.model, "max_tokens": max_tokens, "system": system, "messages": msgs,
                "tools": [{"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]} for t in tools]}
        data = _post(cfg, {"x-api-key": cfg.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}, body, transport)
        blocks = data.get("content", [])
        u = data.get("usage") or {}
        return {"tokens": int(u.get("input_tokens", 0)) + int(u.get("output_tokens", 0)),
                "text": "".join(b.get("text", "") for b in blocks if b.get("type") == "text"),
                "tool_calls": [{"id": b["id"], "name": b["name"], "args": b.get("input") or {}} for b in blocks if b.get("type") == "tool_use"]}

    raise LLMError("no LLM provider configured")


def test_connection(cfg: LLMConfig, transport: httpx.BaseTransport | None = None) -> dict:
    start = time.monotonic()
    try:
        complete(cfg, "Reply with the single word OK.", "ping", transport)
        return {"ok": True, "provider": cfg.provider, "model": cfg.model, "latency_ms": int((time.monotonic() - start) * 1000)}
    except LLMError as exc:
        models_info = ""
        if cfg.provider == "groq" and cfg.api_key:
            try:
                with httpx.Client(timeout=5, transport=transport) as client:
                    r = client.get("https://api.groq.com/openai/v1/models", headers={"Authorization": f"Bearer {cfg.api_key}"})
                    if r.status_code == 200:
                        avail = [m["id"] for m in r.json().get("data", []) if not m["id"].startswith("whisper")]
                        models_info = f" Available models for your key: {', '.join(avail)}"
            except Exception:
                pass
        return {"ok": False, "provider": cfg.provider, "model": cfg.model, "error": f"{exc}{models_info}"}


ALLOWED_FIELDS = ("type", "rule", "engine", "analyzer", "severity", "confidence", "layer", "masked", "message")


def explain(cfg: LLMConfig, finding: dict, transport: httpx.BaseTransport | None = None) -> dict:
    """Explain a finding from masked metadata only. The result is advice, not evidence."""
    safe = {k: finding[k] for k in ALLOWED_FIELDS if k in finding and finding[k] not in (None, "")}
    text = complete(cfg, SYSTEM, json.dumps(safe), transport)
    return {"explanation": text, "provider": cfg.provider, "model": cfg.model, "sent_fields": sorted(safe), "is_evidence": False}


def main(argv: list[str] | None = None) -> int:
    """`python -m shield.llm test|explain` for the VS Code extension. Finding JSON on stdin for explain."""
    argv = argv if argv is not None else sys.argv[1:]
    cfg = from_env()
    if not argv or argv[0] not in {"test", "explain"}:
        print("usage: python -m shield.llm test|explain", file=sys.stderr)
        return 2
    if argv[0] == "test":
        out = test_connection(cfg)
    else:
        try:
            out = explain(cfg, json.load(sys.stdin))
        except LLMError as exc:
            out = {"error": str(exc)}
    print(json.dumps(out))
    return 0 if "error" not in out and out.get("ok", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
