from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass, replace
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .models import ImageRef


RETRYABLE = {"http_403", "http_429"}
RETRY_WAIT = 5.0
IMAGE_RPS = 3.0  # images were unpaced: real sites answer a burst with 403, and the match is then silently lost


@dataclass
class Job:
    url: str
    kind: str = "page"
    depth: int = 0
    domain: str = ""
    page_url: str = ""
    seed_category: str = ""
    risk: float = 0.0
    tier: int = 2
    seq: int = 0
    retries: int = 0
    site: str = ""  # the site agent that owns this job


def classify(soup: BeautifulSoup, seed_category: str = "") -> str:
    if seed_category:
        return {
            "paste": "default",
            "image_host": "default",
            "mirror": "gallery",
        }.get(seed_category, seed_category)
    if soup.select_one("div.thread, a[rel=next]"):
        return "forum"
    if soup.select_one("div.card"):
        return "directory"
    if len(soup.select("img")) >= 20:
        return "gallery"
    return "default"


def _abs(base: str, href: str) -> str:
    return urljoin(base, href)


def _image_urls(soup: BeautifulSoup, base: str) -> set[str]:
    out: set[str] = set()
    for tag in soup.select("img"):
        for attr in ("src", "data-src", "srcset"):
            value = tag.get(attr)
            if not value:
                continue
            if attr == "srcset":
                value = value.split(",")[0].strip().split(" ")[0]
            out.add(_abs(base, value))
    for a in soup.select("a[href]"):
        href = _abs(base, a["href"])
        if re.search(r"\.(jpg|jpeg|png|webp|gif|bmp|pdf)(\?|$)", href, re.I) and "/wiki/File:" not in href:  # that is a page, not an image
            out.add(href)
    return {u for u in out if not re.search(r"\.svg(\?|$)", u, re.I)}  # vector icons cannot be hashed


class Scheduler:
    def __init__(self, rps_per_domain: float = 1.0, global_concurrency: int = 8, budget_pages: int = 500, max_depth: int = 10):
        self.rps = rps_per_domain
        self.image_gap = 1.0 / max(IMAGE_RPS, rps_per_domain)
        self.max_depth = max_depth
        self.sem = asyncio.Semaphore(global_concurrency)
        self.budget_pages = budget_pages
        self.sites: dict[str, asyncio.PriorityQueue] = {}
        self.site_stats: dict[str, dict] = {}
        self._agents: dict[str, asyncio.Task] = {}
        self._ctx: tuple | None = None
        self.pending = 0
        self.seq = 0
        self.blocked: set[str] = set()
        self.counters = {"pages": 0, "images": 0, "blocked": 0, "robots_denied": 0}
        self._last: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._done = asyncio.Event()

    def push(self, tier: int, risk: float, job: Job):
        if self.counters["pages"] >= self.budget_pages:
            return
        job.tier = tier
        job.risk = risk
        job.seq = self.seq
        self.seq += 1
        self.pending += 1
        job.site = job.site or job.domain or urlparse(job.url).netloc
        self.sites.setdefault(job.site, asyncio.PriorityQueue()).put_nowait((tier, -risk, job.seq, job))
        self._spawn(job.site)

    def _spawn(self, site: str) -> None:
        """One agent per site, so a slow or rate-limited site never holds up the others."""
        if self._ctx and (site not in self._agents or self._agents[site].done()):
            self._agents[site] = asyncio.create_task(self._site_agent(site))

    async def _pace(self, domain: str, gap: float | None = None):
        lock = self._locks.setdefault(domain, asyncio.Lock())
        async with lock:
            now = time.monotonic()
            last = self._last.get(domain, 0.0)
            wait = (1.0 / self.rps if gap is None else gap) - (now - last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last[domain] = time.monotonic()

    async def _process(self, job: Job, fetcher, on_image, on_event):
        domain = job.domain or (urlparse(job.url).netloc.split(":")[0])
        stats = self.site_stats.setdefault(job.site, {"pages": 0, "images": 0})
        if job.site in self.blocked:
            self.pending -= 1
            if self.pending <= 0:
                self._done.set()
            return

        if job.kind == "image":
            self.counters["images"] += 1
            stats["images"] += 1
            await self._pace(urlparse(job.url).netloc, self.image_gap)
            async with self.sem:
                    await on_image(ImageRef(job.page_url or job.url, job.url, domain))
            self.pending -= 1
            if self.pending <= 0:
                self._done.set()
            return

        await self._pace(domain)
        async with self.sem:
            res = await fetcher.get(job.url)

        if res.blocked_reason in RETRYABLE and job.retries < 1:  # often a rate limit, not a ban: back off once before giving up on the site
            await asyncio.sleep(RETRY_WAIT)
            self.push(job.tier, job.risk, replace(job, retries=job.retries + 1))
            self.pending -= 1
            if self.pending <= 0:  # at the page budget the push is refused, and nothing else would end the run
                self._done.set()
            return
        if res.blocked_reason:
            if res.blocked_reason == "robots":
                self.counters["robots_denied"] += 1
                await on_event({"kind": "robots_denied", "url": job.url})
            else:
                self.counters["blocked"] += 1
                self.blocked.add(job.site)  # the site, not the host: one refused section must not stop the rest of a host
                await on_event({"kind": "blocked", "url": job.url, "reason": res.blocked_reason})
            self.pending -= 1
            if self.pending <= 0:
                self._done.set()
            return

        if res.body[:5] == b"%PDF-":  # a page URL that is really a PDF: its embedded images go to the matcher
            self.push(job.tier, job.risk, replace(job, kind="image", page_url=job.url))
            self.pending -= 1
            if self.pending <= 0:
                self._done.set()
            return
        self.counters["pages"] += 1
        stats["pages"] += 1
        await on_event({"kind": "crawl_progress", **self.counters, "url": job.url, "site": job.site})

        soup = BeautifulSoup(res.body, "html.parser")
        kind = classify(soup, job.seed_category)

        next_urls: list[str] = []

        if kind == "gallery":
            refs = await _gallery_refs(job.url, fetcher, soup)
        elif kind == "forum":
            refs = _image_urls(soup, job.url)
            next_urls = _forum_next(soup, job.url)
        elif kind == "directory":
            refs = {_abs(job.url, img["src"]) for img in soup.select("div.card img[src]")}
        else:
            refs = _image_urls(soup, job.url)
            for a in soup.select("a[href]")[:20]:
                href = _abs(job.url, a["href"])
                if urlparse(href).netloc == urlparse(job.url).netloc:
                    next_urls.append(href)

        for ref in sorted(refs):
            self.push(job.tier, job.risk, Job(ref, "image", job.depth, domain, job.url, job.seed_category, site=job.site))

        if job.depth < self.max_depth:
            for nxt in next_urls:
                if urlparse(nxt).netloc == urlparse(job.url).netloc:
                    self.push(job.tier, job.risk, Job(nxt, "page", job.depth + 1, domain, job.url, job.seed_category, site=job.site))

        self.pending -= 1
        if self.pending <= 0:
            self._done.set()

    async def _site_agent(self, site: str):
        fetcher, on_image, on_event = self._ctx
        await on_event({"kind": "site_agent", "site": site, "status": "spawned"})
        q = self.sites[site]
        while not q.empty():
            job = q.get_nowait()[-1]
            try:
                await self._process(job, fetcher, on_image, on_event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await on_event({"kind": "crawl_error", "url": job.url, "error": str(exc)})
                self.pending -= 1
                if self.pending <= 0:
                    self._done.set()
        await on_event({"kind": "site_agent", "site": site, "status": "done", **self.site_stats.get(site, {})})

    async def run(self, fetcher, on_image, on_event, timeout: float = 120) -> dict:
        if self.pending == 0:
            return dict(self.counters)
        self._ctx = (fetcher, on_image, on_event)
        for site in list(self.sites):
            self._spawn(site)
        try:
            await asyncio.wait_for(self._done.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            self.counters["timed_out"] = True  # the report must say the crawl stopped early
        finally:
            agents = list(self._agents.values())
            for a in agents:
                a.cancel()
            await asyncio.gather(*agents, return_exceptions=True)
        return dict(self.counters)


def _forum_next(soup: BeautifulSoup, base: str) -> list[str]:
    out = []
    for a in soup.select("a[href]"):
        rel = " ".join(a.get("rel", [])).lower()
        text = (a.get_text() or "").strip().lower()
        if rel == "next" or text in {"next", "›", "»", "older", "aage"}:
            out.append(_abs(base, a["href"]))
    return out


async def _gallery_refs(url: str, fetcher, soup: BeautifulSoup) -> set[str]:
    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            # SHIELD_PLAYWRIGHT_CHANNEL=chrome uses an installed Chrome when the bundled build is missing
            browser = await p.chromium.launch(headless=True, channel=os.getenv("SHIELD_PLAYWRIGHT_CHANNEL") or None)
            page = await browser.new_page()
            await page.route("**/*", fetcher.guard_route)
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            last = 0
            for _ in range(15):
                srcs = await page.eval_on_selector_all(
                    "img", "els => els.map(e => e.currentSrc || e.dataset.src || e.src)"
                )
                if len(srcs) == last:
                    break
                last = len(srcs)
                await page.mouse.wheel(0, 2000)
                await page.wait_for_timeout(800)
            srcs = await page.eval_on_selector_all(
                "img", "els => els.map(e => e.currentSrc || e.dataset.src || e.src)"
            )
            await browser.close()
            return {_abs(url, s) for s in srcs if s}
    except Exception:
        return _image_urls(soup, url)

