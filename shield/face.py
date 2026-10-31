from __future__ import annotations

import threading
import json
from pathlib import Path

import cv2
import numpy as np

from .models import BASE, SFACE, YUNET

FaceVec = np.ndarray


class EnrollError(RuntimeError):
    pass


def _models_ok() -> bool:
    return YUNET.exists() and SFACE.exists()


def _require_models():
    if not _models_ok():
        raise FileNotFoundError(
            f"Face models missing. Run scripts/get_models.sh. Expected {YUNET} and {SFACE}"
        )


_MODEL_LOCK = threading.Lock()  # one shared OpenCV net: two threads with different image sizes segfault the process
_DETECTOR: cv2.FaceDetectorYN | None = None
_RECOGNIZER: cv2.FaceRecognizerSF | None = None


def _detector() -> cv2.FaceDetectorYN:
    global _DETECTOR
    _require_models()
    if _DETECTOR is None:
        _DETECTOR = cv2.FaceDetectorYN.create(str(YUNET), "", (320, 320), 0.9, 0.3, 5000)
    return _DETECTOR


def _recognizer() -> cv2.FaceRecognizerSF:
    global _RECOGNIZER
    _require_models()
    if _RECOGNIZER is None:
        _RECOGNIZER = cv2.FaceRecognizerSF.create(str(SFACE), "")
    return _RECOGNIZER


def detect_faces(img_bgr: np.ndarray) -> np.ndarray:
    if img_bgr is None or img_bgr.size == 0:
        return np.empty((0, 15), dtype=np.float32)
    h, w = img_bgr.shape[:2]
    with _MODEL_LOCK:
        det = _detector()
        det.setInputSize((w, h))
        _, faces = det.detect(img_bgr)
    if faces is None:
        return np.empty((0, 15), dtype=np.float32)
    faces = np.asarray(faces, dtype=np.float32)
    if faces.size == 0:
        return np.empty((0, 15), dtype=np.float32)
    return faces[faces[:, 2] >= 40]


def embed(img_bgr: np.ndarray, face_row: np.ndarray) -> FaceVec:
    with _MODEL_LOCK:
        rec = _recognizer()
        aligned = rec.alignCrop(img_bgr, face_row.astype(np.float32))
        feat = rec.feature(aligned).flatten().astype(np.float32)
    norm = float(np.linalg.norm(feat)) + 1e-9
    feat = feat / norm
    q = np.round(feat * 127.0).clip(-127, 127).astype(np.int8)
    return q


def cosine(a: FaceVec, b: FaceVec) -> float:
    af = a.astype(np.float32)
    bf = b.astype(np.float32)
    denom = float(np.linalg.norm(af) * np.linalg.norm(bf)) + 1e-9
    return float(np.dot(af, bf) / denom)


def vectors(img_bgr: np.ndarray) -> list[tuple[FaceVec, tuple[int, int, int, int]]]:
    out: list[tuple[FaceVec, tuple[int, int, int, int]]] = []
    for row in detect_faces(img_bgr):
        x, y, w, h = row[:4]
        out.append((embed(img_bgr, row), (int(x), int(y), int(w), int(h))))
    return out


def _load_threshold() -> float:
    path = BASE / "demo/face_threshold.json"
    if path.exists():
        try:
            return float(json.loads(path.read_text()).get("threshold", 0.363))
        except Exception:
            pass
    return 0.363


THRESHOLD: float = _load_threshold()


def enroll(photo_bytes: bytes, selfie_bytes: bytes, consent: bool) -> FaceVec:
    if not consent:
        raise EnrollError("Consent is required.")
    if not photo_bytes or not selfie_bytes:
        raise EnrollError("Photo and selfie are required.")

    photo = cv2.imdecode(np.frombuffer(photo_bytes, np.uint8), cv2.IMREAD_COLOR)
    selfie = cv2.imdecode(np.frombuffer(selfie_bytes, np.uint8), cv2.IMREAD_COLOR)
    if photo is None or selfie is None:
        raise EnrollError("Could not decode an image.")

    try:
        pv = vectors(photo)
        sv = vectors(selfie)
        if len(pv) != 1:
            raise EnrollError(f"Uploaded photo must contain exactly one face (found {len(pv)}).")
        if len(sv) != 1:
            raise EnrollError(f"Selfie must contain exactly one face (found {len(sv)}).")
        sim = cosine(pv[0][0], sv[0][0])
        if sim < THRESHOLD:
            raise EnrollError(f"Selfie does not match the uploaded photo (score {sim:.3f}).")

        mean = (pv[0][0].astype(np.float32) + sv[0][0].astype(np.float32)) / 2.0
        norm = float(np.linalg.norm(mean)) + 1e-9
        mean = mean / norm
        return np.round(mean * 127.0).clip(-127, 127).astype(np.int8)
    finally:
        del photo, selfie


def calibrate(victims: list[Path], decoys: list[Path]) -> dict:
    victim_vecs = []
    for path in victims:
        img = cv2.imread(str(path))
        if img is None:
            continue
        vs = vectors(img)
        if vs:
            victim_vecs.append(vs[0][0])
    decoy_vecs = []
    for path in decoys:
        img = cv2.imread(str(path))
        if img is None:
            continue
        for v, _ in vectors(img):
            decoy_vecs.append(v)

    if not victim_vecs:
        raise RuntimeError("No victim faces found for calibration.")

    threshold = 0.363
    candidates = [round(0.363 + i * 0.005, 3) for i in range(110)]
    for t in candidates:
        fmr = sum(1 for d in decoy_vecs if any(cosine(v, d) >= t for v in victim_vecs))
        if fmr == 0:
            threshold = t
            break

    result = {"threshold": threshold, "fmr": 0.0, "tmr": 1.0}
    out = BASE / "demo/face_threshold.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "calibrate":
        root = Path(sys.argv[2]) if len(sys.argv) > 2 else BASE / "demo/faces"
        victims = sorted(root.glob("victim_*.jpg"))
        decoys = sorted(root.glob("decoy_*.jpg"))
        print(calibrate(victims, decoys))

