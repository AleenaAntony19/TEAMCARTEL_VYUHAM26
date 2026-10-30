from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .models import ImageRef


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
        if re.search(r"\.(jpg|jpeg|png|webp|gif|bmp)(\?|$)", href, re.I):
            out.add(href)
    return out


class Scheduler:
    def __init__(self, rps_per_domain: float = 1.0, global_concurrency: int = 8, budget_pages: int = 500, max_depth: int = 10):
        self.rps = rps_per_domain
        self.max_depth = max_depth
        self.sem = asyncio.Semaphore(global_concurrency)
        self.budget_pages = budget_pages
        self.q: asyncio.PriorityQueue = asyncio.PriorityQueue()
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
        self.q.put_nowait((tier, -risk, job.seq, job))

    async def _pace(self, domain: str):
        lock = self._locks.setdefault(domain, asyncio.Lock())
        async with lock:
            now = time.monotonic()
            last = self._last.get(domain, 0.0)
            wait = (1.0 / self.rps) - (now - last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last[domain] = time.monotonic()

    async def _process(self, job: Job, fetcher, on_image, on_event):
        domain = job.domain or (urlparse(job.url).netloc.split(":")[0])
        if domain in self.blocked:
            self.pending -= 1
            if self.pending <= 0:
                self._done.set()
            return

        if job.kind == "image":
            self.counters["images"] += 1
            await on_image(ImageRef(job.page_url or job.url, job.url, domain))
            self.pending -= 1
            if self.pending <= 0:
                self._done.set()
            return

        await self._pace(domain)
        async with self.sem:
            res = await fetcher.get(job.url)

        if res.blocked_reason:
            if res.blocked_reason == "robots":
                self.counters["robots_denied"] += 1
                await on_event({"kind": "robots_denied", "url": job.url})
            else:
                self.counters["blocked"] += 1
                self.blocked.add(domain)
                await on_event({"kind": "blocked", "url": job.url, "reason": res.blocked_reason})
            self.pending -= 1
            if self.pending <= 0:
                self._done.set()
            return

        self.counters["pages"] += 1
        await on_event({"kind": "crawl_progress", **self.counters, "url": job.url})

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
            self.push(job.tier, job.risk, Job(ref, "image", job.depth, domain, job.url, job.seed_category))

        if job.depth < self.max_depth:
            for nxt in next_urls:
                if urlparse(nxt).netloc == urlparse(job.url).netloc:
                    self.push(job.tier, job.risk, Job(nxt, "page", job.depth + 1, domain, job.url, job.seed_category))

        self.pending -= 1
        if self.pending <= 0:
            self._done.set()

    async def _worker(self, fetcher, on_image, on_event):
        while True:
            try:
                _, _, _, job = await asyncio.wait_for(self.q.get(), timeout=5.0)
            except asyncio.TimeoutError:
                if self.pending <= 0:
                    return
                continue
            try:
                await self._process(job, fetcher, on_image, on_event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await on_event({"kind": "crawl_error", "url": job.url, "error": str(exc)})
                self.pending -= 1
                if self.pending <= 0:
                    self._done.set()

    async def run(self, fetcher, on_image, on_event) -> dict:
        if self.pending == 0:
            return dict(self.counters)
        workers = [asyncio.create_task(self._worker(fetcher, on_image, on_event)) for _ in range(8)]
        try:
            await asyncio.wait_for(self._done.wait(), timeout=120)
        except asyncio.TimeoutError:
            pass
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
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

