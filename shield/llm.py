"""LLM providers for optional explanations. Deterministic analyzers never depend on this.

What is sent: finding type, rule, analyzer, severity and *masked* evidence only.
Keys come from env (GROQ_API_KEY / ANTHROPIC_API_KEY) or are set at runtime in memory; never logged or returned.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field, replace

import httpx

PROVIDERS = {
    "groq": {
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "model": "llama-3.3-70b-versatile",
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
    retries: int = 2
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


def _request(cfg: LLMConfig, system: str, user: str) -> tuple[dict, dict]:
    if cfg.provider == "groq":
        return (
            {"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json"},
            {
                "model": cfg.model,
                "max_tokens": 300,
                "temperature": 0.2,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            },
        )
    return (
        {"x-api-key": cfg.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        {"model": cfg.model, "max_tokens": 300, "system": system, "messages": [{"role": "user", "content": user}]},
    )


def _text(cfg: LLMConfig, data: dict) -> str:
    if cfg.provider == "groq":
        return data["choices"][0]["message"]["content"].strip()
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()


def complete(cfg: LLMConfig, system: str, user: str, transport: httpx.BaseTransport | None = None) -> str:
    if cfg.provider == "none":
        raise LLMError("no LLM provider configured")
    if not cfg.api_key:
        raise LLMError(f"no API key set for {cfg.provider}")
    headers, body = _request(cfg, system, user)
    last = "unknown error"
    with httpx.Client(timeout=cfg.timeout, transport=transport) as client:
        for attempt in range(cfg.retries + 1):
            try:
                resp = client.post(cfg.endpoint, headers=headers, json=body)
            except httpx.HTTPError as exc:
                last = type(exc).__name__  # never include request details: headers hold the key
            else:
                if resp.status_code == 200:
                    try:
                        return _text(cfg, resp.json())
                    except (KeyError, IndexError, ValueError):
                        raise LLMError("unexpected response shape") from None
                last = f"HTTP {resp.status_code}"
                if resp.status_code not in {408, 429, 500, 502, 503, 504, 529}:
                    break
            if attempt < cfg.retries:
                time.sleep(min(4.0, 0.5 * 2**attempt))
    raise LLMError(f"{cfg.provider} request failed: {last}")


def test_connection(cfg: LLMConfig, transport: httpx.BaseTransport | None = None) -> dict:
    start = time.monotonic()
    try:
        complete(cfg, "Reply with the single word OK.", "ping", transport)
        return {"ok": True, "provider": cfg.provider, "model": cfg.model, "latency_ms": int((time.monotonic() - start) * 1000)}
    except LLMError as exc:
        return {"ok": False, "provider": cfg.provider, "model": cfg.model, "error": str(exc)}


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
