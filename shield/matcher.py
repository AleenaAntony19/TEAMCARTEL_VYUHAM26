from __future__ import annotations

import asyncio
import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone

import cv2
import pymupdf
import numpy as np
from PIL import Image

from . import face, pdq
from .models import Match


def _blur_thumb(img_bgr: np.ndarray) -> bytes:
    rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
    img = Image.fromarray(rgb)
    img.thumbnail((128, 128))
    from PIL import ImageFilter
    import io

    blurred = img.filter(ImageFilter.GaussianBlur(radius=25))
    buf = io.BytesIO()
    blurred.save(buf, "JPEG", quality=85)
    return buf.getvalue()


cv2.setNumThreads(1)  # a small host has far fewer CPUs than cv2 sees: extra threads starve the website
_HASHER = ThreadPoolExecutor(1, thread_name_prefix="hash")  # fetches stay parallel, CPU work takes turns
MAX_PDF_PAGES, MAX_PDF_IMAGES, MAX_PDF_IMAGE_PIXELS = 50, 40, 40_000_000


def _pdf_images(data: bytes) -> list[bytes]:
    """Embedded images of an untrusted PDF, bounded. A damaged file yields none; it is not a crash."""
    try:
        with pymupdf.open(stream=data, filetype="pdf") as doc:
            xrefs = {i[0]: i for p in doc.pages(0, min(len(doc), MAX_PDF_PAGES)) for i in p.get_images(full=True)}
            return [doc.extract_image(x)["image"] for x, i in list(xrefs.items())[:MAX_PDF_IMAGES] if i[2] * i[3] <= MAX_PDF_IMAGE_PIXELS]
    except Exception:
        return []


class Matcher:
    def __init__(self, enrolled: list[face.FaceVec], bank: pdq.HashBank | None):
        self.enrolled = enrolled
        self.bank = bank
        self.matches: list[Match] = []
        self.failed = 0
        self._seen: dict[str, asyncio.Future] = {}  # image URL -> its verdict, shared by every page showing it
        self._shas: set[tuple[str, str]] = set()

    async def on_image(self, ref, fetcher) -> Match | None:
        known = self._seen.get(ref.image_url)
        if known is not None:  # same image on another page: no new fetch, but that page must still be reported
            first = await known
            if first is None or (first.sha256, ref.page_url) in self._shas:
                return None
            self._shas.add((first.sha256, ref.page_url))
            again = replace(first, page_url=ref.page_url, id=hashlib.sha256(f"{first.id}{ref.page_url}".encode()).hexdigest()[:16])
            self.matches.append(again)
            return again
        self._seen[ref.image_url] = done = asyncio.get_running_loop().create_future()
        try:
            found = await self._check(ref, fetcher)
        except BaseException:
            done.set_result(None)
            raise
        done.set_result(found)
        return found

    async def _check(self, ref, fetcher) -> Match | None:
        res = await fetcher.get(ref.image_url)
        if res.blocked_reason in {"http_403", "http_429"}:
            await asyncio.sleep(3)  # usually a rate limit: one patient retry
            res = await fetcher.get(ref.image_url)
        if res.blocked_reason or not res.body:
            self.failed += 1  # counted, so "no match" can never hide "could not check"
            return None
        return await asyncio.get_running_loop().run_in_executor(_HASHER, self._match, ref, res)

    def _match(self, ref, res) -> Match | None:
        if res.body[:5] != b"%PDF-":
            return self._match_one(ref.page_url, ref.image_url, res.body, res)
        hits = [self._match_one(ref.page_url, f"{ref.image_url}#image{i}", blob, res) for i, blob in enumerate(_pdf_images(res.body))]
        return next((m for m in hits if m), None)  # shortcut: a PDF reports its first match only; list them all if reviewers need that

    def _match_one(self, page_url: str, image_url: str, data: bytes, res) -> Match | None:
        arr = np.frombuffer(data, np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            del data, arr
            return None
        if min(img.shape[:2]) < 64:
            del data, arr, img
            return None

        vecs = face.vectors(img) if self.enrolled else []  # slow, and only an enrolment uses it
        boxes = [b for _, b in vecs]
        rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        regions = pdq.pdq_regions(rgb, boxes)

        nearest = self.bank.nearest(regions) if self.bank else None
        d = nearest[1] if nearest else None
        region = nearest[0].get("region", "full") if nearest else "full"

        sim = None
        if self.enrolled and vecs:
            sim = max(face.cosine(v, e) for v, _ in vecs for e in self.enrolled)

        v = pdq.verdict(d, sim, face.THRESHOLD)
        if v:
            sha = hashlib.sha256(data).hexdigest()
            if (sha, page_url) in self._shas:
                del data, arr, img, vecs, regions
                return None
            self._shas.add((sha, page_url))  # before any other thread reaches the check above
            kind = "face" if sim is not None and (d is None or sim >= face.THRESHOLD) else "pdq"
            m = Match(
                id=hashlib.sha256(f"{sha}{page_url}".encode()).hexdigest()[:16],
                page_url=page_url,
                image_url=image_url,
                kind=kind,
                pdq_distance=d,
                similarity=sim,
                band=pdq.band(d) if d is not None else None,
                verdict=v,
                region=region,
                sha256=sha,
                thumb_jpeg=_blur_thumb(img),
                discovered_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                etag=res.headers.get("etag"),
                last_modified=res.headers.get("last-modified"),
            )
            self.matches.append(m)
            del data, arr, img, vecs, regions
            return m

        del data, arr, img, vecs, regions
        return None

