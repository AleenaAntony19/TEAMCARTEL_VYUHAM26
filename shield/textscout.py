from __future__ import annotations

import json
import os
import re
import time
from urllib.parse import urlparse

import httpx

from .detect import detect, labelled_ids, variants
from .models import BASE

TEMPLATES = [
    'site:pastebin.com "{org}"',
    'site:rentry.co "{org}"',
    'site:github.com "{org}"',
    'site:gist.github.com "{org}"',
    'filetype:xlsx "{org}"',
    'filetype:pdf "{org}"',
    '"{org}"',
]

LONG_NUMBER = re.compile(r"\d(?:[\s-]?\d){8,}")
TYPE_TERMS = {"IN_AADHAAR": "aadhaar", "IN_PAN": "pan card", "CREDIT_CARD": "card number", "EMAIL_ADDRESS": "email list",
              "MOBILE_IN": "phone numbers", "IN_BANK_ACCOUNT": "bank account"}

TIER1_HOSTS = {"pastebin.com", "rentry.co", "gist.github.com"}


def build_queries(org: str, types: list[str], domain: str, sites: list[str] = ()) -> list[str]:
    """Search-engine queries from org, domain, known entity types and the predefined sites. Every query still passes firewall()."""
    queries = [f'site:{s} "{org}"' for s in sites] + [t.format(org=org) for t in TEMPLATES]
    queries += [f'"{org}" {TYPE_TERMS[t]} leak' for t in types if t in TYPE_TERMS]
    if domain:
        queries.append(f'"{domain}" leak OR dump')
    return queries


def firewall(q: str, originals: list[str]) -> bool:
    low = q.lower()
    for original in originals:
        if any(v.lower() in low for v in variants(original)):
            return False
    if LONG_NUMBER.search(q):  # an ID with a wrong checksum or a mistyped phone is still a personal value
        return False
    for e in detect(q) + detect(q.upper()) + labelled_ids(q):
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
    url = url if url.startswith(("https://", "http://")) else ""  # results are untrusted: nothing else may reach a link
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


class SearchError(RuntimeError):
    """A readable failure, safe to show: it never holds the key. `fatal` means the next query would fail the same way."""

    def __init__(self, message: str, fatal: bool = False):
        super().__init__(message)
        self.fatal = fatal


class SerperProvider(SearchProvider):
    """Serper.dev Google results API: needs SERPER_API_KEY."""

    name = "serper"

    def available(self) -> bool:
        return bool(os.getenv("SERPER_API_KEY"))

    def search(self, q: str, transport: httpx.BaseTransport | None = None) -> list[dict]:
        key = os.getenv("SERPER_API_KEY")
        if not key:
            raise SearchError("SERPER_API_KEY is not set", fatal=True)
        status = "no response"
        with httpx.Client(timeout=10, transport=transport) as client:
            for attempt in range(3):
                try:
                    resp = client.post("https://google.serper.dev/search", json={"q": q, "num": 10},
                                       headers={"X-API-KEY": key, "Content-Type": "application/json"})
                except httpx.HTTPError as exc:
                    status = type(exc).__name__
                else:
                    if resp.status_code == 200:
                        return self._parse(resp)
                    status = f"HTTP {resp.status_code}"
                    if resp.status_code in {400, 401, 402, 403}:  # bad key or no credits: retrying only wastes time
                        raise SearchError(f"serper rejected the request ({status}): check the key and remaining credits", fatal=True)
                    if resp.status_code != 429 and resp.status_code < 500:
                        break
                if attempt < 2:
                    time.sleep(0.5 * 2**attempt)
        raise SearchError(f"serper unavailable ({status})")

    def _parse(self, resp: httpx.Response) -> list[dict]:
        try:
            items = resp.json().get("organic", [])
        except (ValueError, AttributeError):
            raise SearchError("serper returned an unreadable reply") from None
        # results are untrusted: only http(s) links reach the UI and the crawler
        return [_hit(i["link"], str(i.get("title", "")), str(i.get("snippet", "")), self.name)
                for i in items if isinstance(i, dict) and str(i.get("link", "")).startswith(("https://", "http://"))]


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
    except (httpx.HTTPError, SearchError):
        # provider down or quota hit: fall back to fixtures, flagged offline
        return OfflineProvider().search(q)
