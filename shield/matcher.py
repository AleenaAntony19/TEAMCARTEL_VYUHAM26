from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import cv2
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


class Matcher:
    def __init__(self, enrolled: list[face.FaceVec], bank: pdq.HashBank | None):
        self.enrolled = enrolled
        self.bank = bank
        self.matches: list[Match] = []
        self._urls: set[str] = set()
        self._shas: set[str] = set()

    async def on_image(self, ref, fetcher) -> Match | None:
        if ref.image_url in self._urls:
            return None

        res = await fetcher.get(ref.image_url)
        if res.blocked_reason or not res.body:
            return None

        data = res.body
        arr = np.frombuffer(data, np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            del data, arr
            return None
        if min(img.shape[:2]) < 64:
            del data, arr, img
            return None

        vecs = face.vectors(img)
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
            if sha in self._shas:
                del data, arr, img, vecs, regions
                return None
            kind = "face" if sim is not None and (d is None or sim >= face.THRESHOLD) else "pdq"
            m = Match(
                id=sha[:16],
                page_url=ref.page_url,
                image_url=ref.image_url,
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
            self._urls.add(ref.image_url)
            self._shas.add(sha)
            del data, arr, img, vecs, regions
            return m

        del data, arr, img, vecs, regions
        return None

