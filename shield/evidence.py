from __future__ import annotations

import os
import hashlib
from pathlib import Path

import httpx

from .net import is_public


async def capture(url: str, out_dir: str | Path) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    png_path = out / "screenshot.png"
    har_path = out / "capture.har"

    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": 1366, "height": 900},
                record_har_path=str(har_path),
                record_har_content="omit",
            )
            page = await context.new_page()

            async def guard(route):
                host = str(route.request.url).split("/")[2].split(":")[0]
                if not is_public(host):
                    await route.abort()
                else:
                    await route.continue_()

            await page.route("**/*", guard)
            resp = await page.goto(url, wait_until="networkidle", timeout=20000)
            await page.add_style_tag(
                content="img,video,canvas{filter:blur(40px)!important} *{background-image:none!important}"
            )
            png = await page.screenshot(full_page=True)
            png_path.write_bytes(png)
            html = await page.content()
            await context.close()
            await browser.close()

        return {
            "png": str(png_path),
            "har": str(har_path),
            "html_sha256": hashlib.sha256(html.encode()).hexdigest(),
            "png_sha256": hashlib.sha256(png).hexdigest(),
            "har_sha256": hashlib.sha256(har_path.read_bytes()).hexdigest() if har_path.exists() else "",
            "status": resp.status if resp else 0,
            "headers": dict(resp.headers) if resp else {},
            "tls": url.split(":")[0],
            "server_addr": "unknown",
            "ts": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        }
    except Exception as exc:
        return {"error": str(exc), "png": None, "har": None, "headers": {}}


async def _rdap(url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return {}
            return resp.json()
    except Exception:
        return {}


async def infra(url: str, headers: dict) -> dict:
    from urllib.parse import urlparse
    import socket

    host = urlparse(url).hostname or ""
    ips = []
    try:
        for info in socket.getaddrinfo(host, None):
            ips.append(info[4][0])
    except Exception:
        pass

    cdn = "unknown"
    h = {k.lower(): v for k, v in headers.items()}
    if "cf-ray" in h:
        cdn = "Cloudflare"
    elif "x-amz-cf-id" in h:
        cdn = "CloudFront"
    elif "x-served-by" in h or "x-fastly-request-id" in h:
        cdn = "Fastly"
    elif any(k.startswith("x-akamai") for k in h):
        cdn = "Akamai"

    registrar = "unknown"
    abuse = []
    nameservers = []
    rdap = None if os.getenv("SHIELD_LOCAL_ONLY") == "1" else await _rdap(f"https://rdap.org/domain/{host}")
    if rdap:
        for ent in rdap.get("entities", []):
            vcard = ent.get("vcardArray", [None, []])
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] == "fn":
                        registrar = item[3] if registrar == "unknown" else registrar
                    if item and item[0] == "email":
                        abuse.append(item[3])
        nameservers = [ns.get("ldhName", "") for ns in rdap.get("nameservers", [])]

    return {
        "ips": ips,
        "cdn": cdn,
        "registrar": registrar,
        "abuse_emails": abuse,
        "nameservers": nameservers,
        "asn": "unknown",
        "network": "unknown",
    }


async def confirm(match, ledger, out_dir) -> dict:
    ev = await capture(match.page_url, out_dir)
    inf = await infra(match.page_url, ev.get("headers", {}))
    ledger.append("USER_CONFIRMED", {"match": match.id, "url": match.page_url})
    ledger.append("SCREENSHOT", {"match": match.id, "png_sha256": ev.get("png_sha256")})
    ledger.append("INFRA", {"match": match.id, "cdn": inf.get("cdn"), "ips": inf.get("ips")})
    match.status = "confirmed"
    return {"evidence": ev, "infra": inf}


def reject(match, ledger):
    match.status = "rejected"
    match.thumb_jpeg = b""
    ledger.append("USER_REJECTED", {"match": match.id, "url": match.page_url})

