from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .detect import detect, variants
from .models import BASE

TEMPLATES = [
    'site:pastebin.com "{org}"',
    'site:rentry.co "{org}"',
    'site:github.com "{org}"',
    'site:gist.github.com "{org}"',
    'filetype:xlsx "{org}"',
    'filetype:pdf "{org}"',
]

TIER1_HOSTS = {"pastebin.com", "rentry.co", "gist.github.com"}


def build_queries(org: str, types: list[str], domain: str) -> list[str]:
    queries = [t.format(org=org) for t in TEMPLATES]
    key = os.getenv("ANTHROPIC_API_KEY")
    if key:
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=key)
            msg = client.messages.create(
                model=os.getenv("SHIELD_CLAUDE_MODEL", "claude-haiku-5-5"),
                max_tokens=300,
                messages=[
                    {
                        "role": "user",
                        "content": (
                            "Generate up to 4 short web search queries to find public leak pages. "
                            "Do not include personal values. Return one query per line.\n"
                            f"org={org}\ntypes={','.join(types)}\ndomain={domain}"
                        ),
                    }
                ],
            )
            extra = [line.strip() for line in msg.content[0].text.splitlines() if line.strip()]
            queries.extend(extra[:4])
        except Exception:
            pass
    return queries


def firewall(q: str, originals: list[str]) -> bool:
    for original in originals:
        if any(v in q for v in variants(original)):
            return False
    for e in detect(q):
        if e.type not in {"ORG", "LOCATION", "DATE_TIME"}:
            return False
    return True


def _tier(url: str) -> int:
    host = urlparse(url).netloc.lower().split(":")[0]
    if host in TIER1_HOSTS:
        return 1
    return 2


def search(q: str) -> list[dict]:
    key = os.getenv("BRAVE_API_KEY")
    if key:
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(
                    "https://api.search.brave.com/res/v1/web/search",
                    params={"q": q, "count": 10},
                    headers={"X-Subscription-Token": key, "Accept": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()
            out = []
            for item in data.get("web", {}).get("results", []):
                url = item.get("url", "")
                out.append(
                    {
                        "url": url,
                        "title": item.get("title", ""),
                        "snippet": item.get("description", ""),
                        "tier": _tier(url),
                        "offline": False,
                    }
                )
            return out
        except Exception:
            pass

    bank_path = BASE / "demo/leak_bank.json"
    if bank_path.exists():
        bank = json.loads(bank_path.read_text())
        return [
            {**hit, "tier": hit.get("tier", _tier(hit.get("url", ""))), "offline": True}
            for hit in bank.get("text_hits", [])
        ]
    return []

