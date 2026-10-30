from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import cv2
import numpy as np

try:
    import pdqhash
except ImportError:
    pdqhash = None

_POPCOUNT = np.array([bin(i).count("1") for i in range(256)], dtype=np.uint8)


def _to_hex(bits) -> str:
    arr = np.asarray(bits, dtype=np.uint8)
    if arr.size == 256:
        arr = np.packbits(arr)
    return arr.tobytes().hex()


def _from_hex(h: str) -> np.ndarray:
    return np.frombuffer(bytes.fromhex(h), dtype=np.uint8)


def _compute(img_rgb: np.ndarray) -> tuple[str, int]:
    if pdqhash is None:
        import hashlib
        return hashlib.sha256(img_rgb.tobytes()).hexdigest(), 100
    h, q = pdqhash.compute(np.ascontiguousarray(img_rgb))
    return _to_hex(h), int(q)


def hamming(a_hex: str, b_hex: str) -> int:
    a = _from_hex(a_hex)
    b = _from_hex(b_hex)
    return int(_POPCOUNT[a ^ b].sum())


def band(d: int) -> Literal["strong", "marginal"] | None:
    if d <= 31:
        return "strong"
    if d <= 45:
        return "marginal"
    return None


@dataclass(frozen=True)
class RegionHash:
    hex: str
    quality: int
    region: str


def _center_crop(img: np.ndarray, frac: float) -> np.ndarray:
    h, w = img.shape[:2]
    nh, nw = int(h * frac), int(w * frac)
    y0, x0 = (h - nh) // 2, (w - nw) // 2
    return img[y0 : y0 + nh, x0 : x0 + nw]


def _region_crops(img: np.ndarray, face_boxes: list[tuple] = []):
    yield "full", img
    yield "c80", _center_crop(img, 0.8)
    yield "c60", _center_crop(img, 0.6)
    for i, box in enumerate(face_boxes):
        x, y, w, h = map(float, box[:4])
        mx, my = 0.2 * w, 0.2 * h
        x0 = max(0, int(x - mx))
        y0 = max(0, int(y - my))
        x1 = min(img.shape[1], int(x + w + mx))
        y1 = min(img.shape[0], int(y + h + my))
        crop = img[y0:y1, x0:x1]
        if crop.size:
            yield f"face{i}", cv2.resize(crop, (256, 256))


def _dihedral(img_rgb: np.ndarray) -> list[str]:
    out: list[str] = []
    for k in range(4):
        rot = np.rot90(img_rgb, k)
        for flip in (False, True):
            cand = np.fliplr(rot) if flip else rot
            h, q = _compute(np.ascontiguousarray(cand))
            if q >= 50:
                out.append(h)
    return list(dict.fromkeys(out))


def pdq_dihedral(img_rgb: np.ndarray) -> list[str]:
    return _dihedral(img_rgb)


def pdq_regions(img_rgb: np.ndarray, face_boxes: list[tuple] = []) -> list[RegionHash]:
    out: list[RegionHash] = []
    seen = set()
    for name, crop in _region_crops(img_rgb, face_boxes):
        if crop.size == 0:
            continue
        h, q = _compute(crop)
        if q < 50 or h in seen:
            continue
        seen.add(h)
        out.append(RegionHash(h, q, name))
    return out


class HashBank:
    def __init__(self):
        self._rows: list[np.ndarray] = []
        self._meta: list[dict] = []

    def add_reference(self, id: str, label: str, img_rgb: np.ndarray, face_boxes: list[tuple] = []):
        for region, crop in _region_crops(img_rgb, face_boxes):
            if crop.size == 0:
                continue
            hashes = _dihedral(crop)
            for h in hashes:
                row = _from_hex(h)
                if row.size != 32:
                    continue
                self._rows.append(row)
                self._meta.append({"id": id, "label": label, "region": region})

    def nearest(self, hashes: list[RegionHash]) -> tuple[dict, int] | None:
        if not self._rows or not hashes:
            return None
        matrix = np.stack(self._rows, axis=0)
        best = None
        for rh in hashes:
            q = _from_hex(rh.hex)
            if q.size != 32:
                continue
            d = _POPCOUNT[matrix ^ q].sum(axis=1)
            idx = int(d.argmin())
            dist = int(d[idx])
            if best is None or dist < best[1]:
                best = (self._meta[idx], dist)
        return best

    def save(self, path: str | Path):
        data = {
            "version": 2,
            "refs": [
                {"id": m["id"], "label": m["label"], "region": m["region"], "hash": r.tobytes().hex()}
                for r, m in zip(self._rows, self._meta)
            ],
        }
        Path(path).write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, path: str | Path) -> "HashBank":
        bank = cls()
        data = json.loads(Path(path).read_text())
        for ref in data.get("refs", []):
            row = _from_hex(ref["hash"])
            if row.size == 32:
                bank._rows.append(row)
                bank._meta.append(
                    {"id": ref["id"], "label": ref["label"], "region": ref["region"]}
                )
        return bank

    def __len__(self):
        return len(self._rows)


def verdict(
    pdq_d: int | None, face_sim: float | None, thr: float
) -> Literal["confirmed", "possible"] | None:
    b = band(pdq_d) if pdq_d is not None else None
    if b == "strong":
        return "confirmed"
    if b == "marginal" and face_sim is not None and face_sim >= thr:
        return "confirmed"
    if face_sim is not None and face_sim >= thr + 0.1:
        return "confirmed"
    if b == "marginal":
        return "possible"
    if face_sim is not None and face_sim >= thr:
        return "possible"
    return None

