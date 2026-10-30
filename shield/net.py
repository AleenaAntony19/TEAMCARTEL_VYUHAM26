from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import httpx

from .models import FetchResult

UA = "ShieldScoutBot/1.0 (+contact: local-demo)"


def ip_allowed(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if addr.is_loopback and os.getenv("SHIELD_ALLOW_LOCAL") == "1":
        return True
    return addr.is_global


def is_public(host: str) -> bool:
    if not host:
        return False
    try:
        addrs = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    return all(ip_allowed(info[4][0]) for info in addrs)


def _peer_ip(resp: httpx.Response) -> str | None:
    stream = resp.extensions.get("network_stream")
    if stream is None:
        return None
    addr = stream.get_extra_info("server_addr")
    return addr[0] if addr else None


class Fetcher:
    def __init__(self, transport=None, timeout: float = 15.0, max_bytes: int = 5 * 1024 * 1024):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": UA},
        )
        self._robots: dict[str, RobotFileParser] = {}

    async def _robots_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        rp = self._robots.get(parsed.netloc)
        if rp is None:
            rp = RobotFileParser()
            rp.set_url(base + "/robots.txt")
            try:
                resp = await self._client.get(base + "/robots.txt")
                if resp.status_code == 200:
                    rp.parse(resp.text.splitlines())
                else:
                    rp.parse([])
            except Exception:
                rp.parse([])
            self._robots[parsed.netloc] = rp
        return rp.can_fetch(UA, url)

    async def get(self, url: str) -> FetchResult:
        current = url
        for _ in range(4):
            parsed = urlparse(current)
            if parsed.scheme not in {"http", "https"}:
                return FetchResult(0, {}, b"", current, "private_ip")
            if not is_public(parsed.hostname or ""):
                return FetchResult(0, {}, b"", current, "private_ip")
            if not await self._robots_allowed(current):
                return FetchResult(0, {}, b"", current, "robots")

            try:
                async with self._client.stream("GET", current) as resp:
                    # DNS can change between is_public() and connect (rebinding): check the IP we actually reached
                    peer = _peer_ip(resp)
                    if peer is not None and not ip_allowed(peer):
                        return FetchResult(0, {}, b"", current, "private_ip")
                    if resp.status_code in {301, 302, 303, 307, 308}:
                        loc = resp.headers.get("location")
                        if not loc:
                            return FetchResult(resp.status_code, dict(resp.headers), b"", current)
                        current = urljoin(current, loc)
                        continue

                    if resp.status_code == 403:
                        return FetchResult(403, dict(resp.headers), b"", current, "http_403")
                    if resp.status_code == 429:
                        return FetchResult(429, dict(resp.headers), b"", current, "http_429")

                    buf = bytearray()
                    async for chunk in resp.aiter_bytes():
                        buf += chunk
                        if len(buf) > self.max_bytes:
                            return FetchResult(resp.status_code, dict(resp.headers), b"", current, "too_large")
                    body = bytes(buf)

                    text_head = body[:4096].decode("utf-8", "ignore").lower()
                    if resp.status_code in {403, 503} and ("captcha" in text_head or "cf-chl" in text_head):
                        return FetchResult(resp.status_code, dict(resp.headers), b"", current, "captcha")

                    return FetchResult(
                        resp.status_code, dict(resp.headers), body, str(resp.url)
                    )
            except httpx.TimeoutException:
                return FetchResult(0, {}, b"", current, "timeout")
            except Exception as exc:
                return FetchResult(0, {}, b"", current, error=str(exc))

        return FetchResult(0, {}, b"", current, "too_many_redirects")

    async def guard_route(self, route):
        url = str(route.request.url)
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not is_public(parsed.hostname or ""):
            await route.abort()
        else:
            await route.continue_()

