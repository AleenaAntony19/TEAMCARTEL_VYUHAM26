from __future__ import annotations

import base64
import json
import textwrap
import zipfile
from pathlib import Path

import pymupdf

VERIFY_SCRIPT = r'''#!/usr/bin/env python3
import hashlib, json, sys

def sha(b):
    return hashlib.sha256(b).hexdigest()

blocks = json.load(open(sys.argv[1]))
prev = "0"*64
for i, b in enumerate(blocks):
    if b.get("prev_hash") != prev:
        print("BAD prev at", i); sys.exit(1)
    payload = {k:b[k] for k in ("seq","timestamp","actor","action","details","prev_hash")}
    s = json.dumps(payload, sort_keys=True, separators=(",",":")).encode()
    if sha(s) != b["current_hash"]:
        print("BAD hash at", i); sys.exit(1)
    prev = b["current_hash"]
print("LEDGER OK", len(blocks), "blocks")
'''


def _pdf(path: Path, report: dict):
    doc = pymupdf.open()
    sections = [
        ("SHIELD·SCOUT DOSSIER", "Summary"),
        ("Document Redaction", "Types and counts, attack results, input/output hashes."),
        ("Leak Matches", "Confirmed URLs, match scores, blurred thumbnails, infrastructure."),
        ("NCRP Draft", "cybercrime.gov.in — women/NCII category. Incident description and URLs."),
        ("CERT-In Notice", "incident@cert-in.org.in — offshore hosting."),
        ("IT Rules 2021 Rule 3(2)(b)", "24-hour takedown notice to Grievance Officer / host abuse / CDN abuse / registrar."),
        ("StopNCII.org", "Hash the image and submit to StopNCII.org."),
        ("Section 63 BSA", "Part A draft and hash table. Part B: to be completed by expert. Not legal advice."),
    ]
    for title, body in sections:
        page = doc.new_page(width=595, height=842)
        page.insert_textbox(pymupdf.Rect(50, 50, 545, 120), title, fontsize=16, fontname="helv")
        page.insert_textbox(
            pymupdf.Rect(50, 130, 545, 780),
            body + "\n\n" + textwrap.fill(json.dumps(report, indent=2, default=str)[:3500], 90),
            fontsize=8,
            fontname="helv",
        )

    for m in report.get("scout", {}).get("matches", []):
        thumb = m.get("thumb_b64")
        if not thumb:
            continue
        page = doc.new_page(width=595, height=842)
        page.insert_textbox(pymupdf.Rect(50, 50, 545, 120), f"Match {m['id']}", fontsize=14)
        page.insert_textbox(
            pymupdf.Rect(50, 130, 545, 220),
            f"Page: {m['page_url']}\nImage: {m['image_url']}\nKind: {m['kind']} "
            f"distance={m['pdq_distance']} similarity={m['similarity']}",
            fontsize=8,
        )
        img_bytes = base64.b64decode(thumb)
        page.insert_image(pymupdf.Rect(50, 240, 306, 496), stream=img_bytes)

    path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(path, garbage=4, deflate=True)
    doc.close()


def build_dossier(report: dict, ledger, out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    pdf_path = out / "dossier.pdf"
    _pdf(pdf_path, report)

    zip_path = out / "shield_dossier.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(pdf_path, "dossier.pdf")
        z.writestr("ledger.json", ledger.to_json())
        z.writestr("verify_ledger.py", VERIFY_SCRIPT)
        z.writestr(
            "README.txt",
            "SHIELD·SCOUT dossier. Part B of the Section 63 BSA certificate must be completed by an expert. "
            "This is not legal advice. Verify the ledger with: python verify_ledger.py ledger.json\n",
        )
        for m in report.get("scout", {}).get("matches", []):
            for key in ("png", "har"):
                p = m.get("evidence", {}).get(key)
                if p and Path(p).exists():
                    z.write(p, f"evidence/{m['id']}_{Path(p).name}")
    return zip_path

