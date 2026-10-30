from __future__ import annotations

import json
import os
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


def build_queries(org: str, types: list[str], domain: str, cfg=None) -> list[str]:
    """Template queries, plus up to 4 LLM suggestions when a provider is configured.
    The LLM sees org/domain/entity types only; every query still passes firewall() before use."""
    queries = [t.format(org=org) for t in TEMPLATES]
    from . import llm

    cfg = cfg or llm.from_env()
    if cfg.provider != "none" and cfg.api_key:
        try:
            text = llm.complete(
                cfg,
                "Suggest web search queries that find public leak pages. Never include personal values. One query per line.",
                f"org={org}\ntypes={','.join(types)}\ndomain={domain}",
            )
            queries.extend([line.strip() for line in text.splitlines() if line.strip()][:4])
        except llm.LLMError:
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


class SearchProvider:
    """Add a provider by subclassing and registering in PROVIDERS; the pipeline only calls search()."""

    name = "base"

    def available(self) -> bool:
        return True

    def search(self, q: str) -> list[dict]:
        raise NotImplementedError


def _hit(url: str, title: str, snippet: str, provider: str) -> dict:
    return {"url": url, "title": title, "snippet": snippet, "tier": _tier(url), "offline": provider == "offline", "provider": provider}


class BraveProvider(SearchProvider):
    name = "brave"

    def available(self) -> bool:
        return bool(os.getenv("BRAVE_API_KEY"))

    def search(self, q: str) -> list[dict]:
        with httpx.Client(timeout=10) as client:
            resp = client.get(
                "https://api.search.brave.com/res/v1/web/search",
                params={"q": q, "count": 10},
                headers={"X-Subscription-Token": os.environ["BRAVE_API_KEY"], "Accept": "application/json"},
            )
            resp.raise_for_status()
        return [_hit(i.get("url", ""), i.get("title", ""), i.get("description", ""), self.name) for i in resp.json().get("web", {}).get("results", [])]


class GoogleCSEProvider(SearchProvider):
    """Google Programmable Search (Custom Search JSON API): needs GOOGLE_CSE_KEY and GOOGLE_CSE_CX."""

    name = "google_cse"

    def available(self) -> bool:
        return bool(os.getenv("GOOGLE_CSE_KEY") and os.getenv("GOOGLE_CSE_CX"))

    def search(self, q: str) -> list[dict]:
        with httpx.Client(timeout=10) as client:
            resp = client.get(
                "https://www.googleapis.com/customsearch/v1",
                params={"key": os.environ["GOOGLE_CSE_KEY"], "cx": os.environ["GOOGLE_CSE_CX"], "q": q, "num": 10},
            )
            resp.raise_for_status()
        return [_hit(i.get("link", ""), i.get("title", ""), i.get("snippet", ""), self.name) for i in resp.json().get("items", [])]


class SerperProvider(SearchProvider):
    """Serper.dev Google results API: needs SERPER_API_KEY."""

    name = "serper"

    def available(self) -> bool:
        return bool(os.getenv("SERPER_API_KEY"))

    def search(self, q: str) -> list[dict]:
        with httpx.Client(timeout=10) as client:
            resp = client.post("https://google.serper.dev/search", json={"q": q, "num": 10},
                               headers={"X-API-KEY": os.environ["SERPER_API_KEY"], "Content-Type": "application/json"})
            resp.raise_for_status()
        return [_hit(i.get("link", ""), i.get("title", ""), i.get("snippet", ""), self.name) for i in resp.json().get("organic", [])]


class OfflineProvider(SearchProvider):
    """Fixture hits from demo/leak_bank.json; no network."""

    name = "offline"

    def search(self, q: str) -> list[dict]:
        bank_path = BASE / "demo/leak_bank.json"
        if not bank_path.exists():
            return []
        hits = json.loads(bank_path.read_text()).get("text_hits", [])
        return [_hit(h.get("url", ""), h.get("title", ""), h.get("snippet", ""), self.name) for h in hits]


PROVIDERS: dict[str, type[SearchProvider]] = {p.name: p for p in (BraveProvider, GoogleCSEProvider, SerperProvider, OfflineProvider)}


def get_provider(name: str | None = None) -> SearchProvider:
    """SHIELD_SEARCH_PROVIDER=auto|brave|google_cse|serper|offline. Local-only mode always uses offline."""
    if os.getenv("SHIELD_LOCAL_ONLY") == "1":
        return OfflineProvider()
    name = name or os.getenv("SHIELD_SEARCH_PROVIDER", "auto")
    if name == "auto":
        return next((p() for p in (BraveProvider, GoogleCSEProvider, SerperProvider) if p().available()), OfflineProvider())
    if name not in PROVIDERS:
        raise ValueError(f"unknown search provider '{name}'")
    return PROVIDERS[name]()


def search(q: str) -> list[dict]:
    provider = get_provider()
    try:
        return provider.search(q)
    except httpx.HTTPError:
        # provider down or quota hit: fall back to fixtures, flagged offline
        return OfflineProvider().search(q)
