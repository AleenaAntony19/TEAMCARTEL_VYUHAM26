from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .detect import detect


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _has_vector(details) -> bool:
    if isinstance(details, list):
        if len(details) >= 64 and all(isinstance(x, (int, float)) for x in details):
            return True
        return any(_has_vector(x) for x in details)
    if isinstance(details, dict):
        return any(_has_vector(v) for v in details.values())
    return False


def _has_pii(details) -> bool:
    text = json.dumps(details, default=str)
    for e in detect(text):
        if e.type in {"IN_AADHAAR", "IN_PAN", "MOBILE_IN", "EMAIL_ADDRESS"}:
            return True
    return False


class Ledger:
    def __init__(self):
        self.blocks: list[dict] = []

    def append(self, actor: str, action: str, details: dict | None = None) -> dict:
        details = details or {}
        if _has_vector(details):
            raise ValueError("Ledger refuses vector-sized numeric arrays")
        if _has_pii(details):
            raise ValueError("Ledger refuses raw PII in details")

        seq = len(self.blocks)
        prev = self.blocks[-1]["current_hash"] if self.blocks else "0" * 64
        payload = {
            "seq": seq,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "actor": actor,
            "action": action,
            "details": details,
            "prev_hash": prev,
        }
        serial = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        current = sha256_bytes(serial.encode("utf-8"))
        block = {**payload, "current_hash": current}
        self.blocks.append(block)
        return block

    def verify(self, blocks: list[dict] | None = None) -> int | None:
        blocks = self.blocks if blocks is None else blocks
        prev = "0" * 64
        for i, block in enumerate(blocks):
            if block.get("prev_hash") != prev:
                return i
            payload = {
                "seq": block["seq"],
                "timestamp": block["timestamp"],
                "actor": block["actor"],
                "action": block["action"],
                "details": block["details"],
                "prev_hash": block["prev_hash"],
            }
            serial = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            if sha256_bytes(serial.encode("utf-8")) != block["current_hash"]:
                return i
            prev = block["current_hash"]
        return None

    def to_json(self) -> str:
        return json.dumps(self.blocks, indent=2)

