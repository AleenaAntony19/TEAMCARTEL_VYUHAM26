"""PCA feature-space candidate retrieval for near-duplicate images, evaluated against baselines.

Features: 64x64 grayscale, histogram-equalised, flattened, zero-mean / unit-norm.
PCA is fit on a defined index set (references + known non-matches); queries are projected and
ranked by cosine similarity. The threshold is calibrated on the index negatives so that no
negative scores above it (zero false positives on calibration data).

Limits (measured by `python -m shield.pcamatch eval`): pixel features are not rotation/flip
invariant and the bundled dataset is tiny, so this is a candidate-retrieval aid, not an identity
or general similarity algorithm. PDQ remains the primary matcher; PCA hits need review.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np

from . import pdq
from .models import BASE

SIZE = 64


def features(img_bgr: np.ndarray) -> np.ndarray:
    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY) if img_bgr.ndim == 3 else img_bgr
    small = cv2.equalizeHist(cv2.resize(gray, (SIZE, SIZE), interpolation=cv2.INTER_AREA))
    v = small.astype(np.float32).ravel()
    v -= v.mean()
    n = np.linalg.norm(v)
    return v / n if n else v


@dataclass
class PCAIndex:
    mean: np.ndarray
    components: np.ndarray  # k x d
    keys: list[str]
    projected: np.ndarray  # n x k, unit rows
    threshold: float = 1.0

    @classmethod
    def fit(cls, items: dict[str, np.ndarray], k: int = 16) -> "PCAIndex":
        if len(items) < 3:
            raise ValueError("PCA needs at least 3 index images")
        keys = list(items)
        X = np.stack([items[key] for key in keys])
        mean = X.mean(axis=0)
        _, _, vt = np.linalg.svd(X - mean, full_matrices=False)
        comps = vt[: min(k, len(keys) - 1)]
        idx = cls(mean, comps, keys, np.zeros((0, comps.shape[0]), np.float32))
        idx.projected = np.stack([idx.project(items[key]) for key in keys])
        return idx

    def project(self, f: np.ndarray) -> np.ndarray:
        z = self.components @ (f - self.mean)
        n = np.linalg.norm(z)
        return z / n if n else z

    def query(self, f: np.ndarray) -> list[tuple[str, float]]:
        sims = self.projected @ self.project(f)
        order = np.argsort(-sims)
        return [(self.keys[i], float(sims[i])) for i in order]

    def calibrate(self, reference: str, negatives: list[str], margin: float = 0.02) -> float:
        """Threshold = highest similarity any known negative reaches against the reference, plus a margin."""
        ref = self.projected[self.keys.index(reference)]
        neg = [float(self.projected[self.keys.index(n)] @ ref) for n in negatives]
        self.threshold = min(1.0, max(neg) + margin) if neg else 0.9
        return self.threshold


def _load(path: Path) -> np.ndarray:
    img = cv2.imread(str(path))
    if img is None:
        raise ValueError(f"cannot read {path}")
    return img


def evaluate(img_dir: Path, reference: str = "orig.jpg", k: int = 16) -> dict:
    """Recall on planted transforms at zero false positives on decoys, for PCA vs raw-pixel cosine vs PDQ."""
    paths = sorted(p for p in img_dir.iterdir() if p.suffix.lower() in {".jpg", ".jpeg", ".png"})
    decoys = [p.name for p in paths if p.name.startswith("decoy_")]
    positives = [p.name for p in paths if p.name != reference and not p.name.startswith("decoy_")]
    imgs = {p.name: _load(p) for p in paths}
    feats = {n: features(i) for n, i in imgs.items()}

    # half the decoys fit/calibrate; the other half are held out to measure false positives
    fit_neg, test_neg = decoys[::2], decoys[1::2]
    index = PCAIndex.fit({n: feats[n] for n in [reference, *fit_neg]}, k=k)
    thr = index.calibrate(reference, fit_neg)
    ref_p = index.projected[index.keys.index(reference)]

    def pca_sim(n):
        return float(index.project(feats[n]) @ ref_p)

    def raw_sim(n):
        return float(feats[n] @ feats[reference])

    raw_thr = min(1.0, max(raw_sim(n) for n in fit_neg) + 0.02)

    ref_rgb = cv2.cvtColor(imgs[reference], cv2.COLOR_BGR2RGB)
    bank = pdq.HashBank()
    bank.add_reference("ref", "reference", ref_rgb, [])

    def pdq_hit(n):
        rh = pdq.pdq_regions(cv2.cvtColor(imgs[n], cv2.COLOR_BGR2RGB))
        near = bank.nearest(rh) if rh else None
        return bool(near and near[1] <= 31)

    def rate(fn, names, thr_):
        return sum(fn(n) >= thr_ for n in names) / max(1, len(names))

    per = {n: {"pca": round(pca_sim(n), 3), "raw": round(raw_sim(n), 3), "pdq": pdq_hit(n)} for n in positives}
    return {
        "dataset": {"reference": reference, "positives": len(positives), "fit_negatives": len(fit_neg), "heldout_negatives": len(test_neg)},
        "pca": {"k": int(index.components.shape[0]), "threshold": round(thr, 3), "recall": rate(pca_sim, positives, thr), "heldout_fpr": rate(pca_sim, test_neg, thr)},
        "raw_pixel_baseline": {"threshold": round(raw_thr, 3), "recall": rate(raw_sim, positives, raw_thr), "heldout_fpr": rate(raw_sim, test_neg, raw_thr)},
        "pdq_baseline": {"threshold": "hamming<=31", "recall": sum(pdq_hit(n) for n in positives) / max(1, len(positives)), "heldout_fpr": sum(pdq_hit(n) for n in test_neg) / max(1, len(test_neg))},
        "per_positive": per,
    }


if __name__ == "__main__":
    if sys.argv[1:2] != ["eval"]:
        print("usage: python -m shield.pcamatch eval [img_dir]", file=sys.stderr)
        raise SystemExit(2)
    d = Path(sys.argv[2]) if len(sys.argv) > 2 else BASE / "demo/mockweb/img"
    print(json.dumps(evaluate(d), indent=2))
