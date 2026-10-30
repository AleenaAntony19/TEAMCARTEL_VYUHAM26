from __future__ import annotations

import asyncio
import io
import json
import os
import tempfile
from pathlib import Path

import streamlit as st

from shield import face, pdq
from shield.dossier import build_dossier
from shield.evidence import confirm, reject
from shield.ledger import Ledger, sha256_file
from shield.pipeline import run_document, run_scout, wipe
from shield.registry import load_registry

BASE = Path(__file__).resolve().parent
WORK = Path(tempfile.mkdtemp(prefix="shield_"))

st.set_page_config(page_title="SHIELD·SCOUT", page_icon="🛡️", layout="wide")
st.title("🛡️ SHIELD·SCOUT")
st.caption("On-device redaction + consented likeness scout. Nothing leaves this machine.")

if "ledger" not in st.session_state:
    st.session_state.ledger = Ledger()
if "matches" not in st.session_state:
    st.session_state.matches = []
if "doc_report" not in st.session_state:
    st.session_state.doc_report = None
if "scout_report" not in st.session_state:
    st.session_state.scout_report = None
if "enrolled" not in st.session_state:
    st.session_state.enrolled = None

tabs = st.tabs(
    [
        "Copy-Paste Test",
        "Agent Swarm",
        "Red Team",
        "Likeness Enrol",
        "Leak Scout",
        "Review",
        "Ledger",
        "Downloads",
    ]
)

# ── 1. Copy-Paste Test ──────────────────────────────────────────────────────
with tabs[0]:
    st.subheader("The black rectangle is NOT redaction — try pdftotext on these two files")
    naive = BASE / "demo/out/naive.pdf"
    clean_path = st.session_state.doc_report["output"] if st.session_state.doc_report else None

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Naive PDF** — black box drawn on top")
        if naive.exists():
            try:
                import subprocess
                naive_text = subprocess.run(
                    ["pdftotext", "-layout", str(naive), "-"],
                    capture_output=True, text=True
                ).stdout
            except Exception:
                naive_text = "(pdftotext unavailable)"
            st.code(naive_text or "(empty)", language="text")
        else:
            st.info("Run `python demo/make_fixtures.py demo/out` first.")
    with col2:
        st.markdown("**SHIELD sanitized output** — object-level redacted")
        if clean_path and Path(clean_path).exists():
            try:
                import subprocess
                clean_text = subprocess.run(
                    ["pdftotext", "-layout", str(clean_path), "-"],
                    capture_output=True, text=True
                ).stdout
            except Exception:
                clean_text = "(pdftotext unavailable)"
            st.code(clean_text or "(empty)", language="text")
        else:
            st.info("Run Shield on a document first (Agent Swarm tab).")

# ── 2. Agent Swarm ──────────────────────────────────────────────────────────
with tabs[1]:
    st.subheader("Document Shield — Dynamic Agent Swarm")
    up = st.file_uploader(
        "Upload PDF / DOCX / XLSX / image",
        type=["pdf", "docx", "xlsx", "jpg", "jpeg", "png"]
    )
    if up and st.button("🚀 Run Shield", type="primary"):
        src = WORK / up.name
        src.write_bytes(up.getvalue())
        events = []
        with st.spinner("Profiling, spawning agents, redacting, red-teaming…"):
            for ev in run_document(src, WORK, st.session_state.ledger):
                events.append(ev)
        st.session_state.doc_report = events[-1]["report"]
        report = st.session_state.doc_report
        sev_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "⚪"}.get(report["severity"], "⚪")
        st.success(f"Status: **{report['status']}**  {sev_color} Severity: **{report['severity']}**")
        st.markdown("---")
        for ev in events:
            if ev["kind"] == "agent":
                st.status(f"🤖 Agent: {ev['agent']}", state="complete")
            elif ev["kind"] == "detect":
                st.write(f"**Detected:** {ev['counts']}  — severity **{ev['severity']}** (score {ev['score']})")
            elif ev["kind"] == "deliberation":
                with st.expander("🗣️ Live Multi-Persona Deliberation & Dialectic Swarm", expanded=True):
                    for log in ev["logs"]:
                        verdict_color = "🟢" if log["verdict"] == "CONFIRMED" else "🟡"
                        st.markdown(f"**Entity Target:** `{log['val']}` ({log['type']}) {verdict_color} Verdict: **{log['verdict']}** (Confidence: {log['score']:.2f})")
                        for t in log["turns"]:
                            st.caption(f"{t['avatar']} **{t['persona']}** [{t['action']}]: {t['argument']}")
                        st.markdown("---")
            elif ev["kind"] == "redact":
                st.write(f"✅ Sanitized: `{ev['output']}`")
            elif ev["kind"] == "attack":
                icon = "✅" if ev["passed"] else "❌"
                st.write(f"{icon} Attack `{ev['name']}`: {'PASS' if ev['passed'] else 'FAIL'} {ev.get('evidence', '')}")
            elif ev["kind"] == "retry":
                st.warning("🔁 Retry with aggressive mode triggered")

# ── 3. Red Team ──────────────────────────────────────────────────────────────
with tabs[2]:
    st.subheader("⚔️ Red Team — Adversarial Self-Verification")
    report = st.session_state.doc_report
    if report:
        rows = [{"Attack": a["name"], "Result": "PASS ✅" if a["passed"] else "FAIL ❌", "Evidence": str(a.get("evidence", ""))} for a in report["attacks"]]
        st.table(rows)
        if report["status"] == "CLEAN":
            st.success("✅ CLEAN — no original value recovered by text, binary, or metadata attack.")
        else:
            st.error("❌ FAILED — the output still leaks. Download and inspect manually.")
        st.json({"input_sha256": report["input_sha256"], "output_sha256": report["output_sha256"]})
    else:
        st.info("Run Shield first (Agent Swarm tab).")

# ── 4. Likeness Enrol ────────────────────────────────────────────────────────
with tabs[3]:
    st.subheader("👤 Consented Likeness Enrolment")
    st.warning(
        "Enrol **only your own face**. A face vector is personal biometric data under DPDP Act 2023. "
        "It is held in RAM only and wiped at session end. "
        "Anti-spoofing (printed photo attacks) is not implemented in this demo."
    )
    if os.getenv("SHIELD_TEST_SELFIE") == "1":
        st.error("⚠️ TEST MODE: selfie is replaced by the uploaded photo. Not for production use.")

    photo = st.file_uploader("Your photo (ID / portrait)", type=["jpg", "jpeg", "png"], key="enrol_photo")
    selfie = st.camera_input("Live selfie (take a photo now)")
    consent = st.checkbox("I consent to on-device face-vector enrolment to find my own leaked images.")

    if st.button("Create 128-byte face vector", disabled=not (photo and consent)):
        try:
            photo_bytes = photo.getvalue()
            if os.getenv("SHIELD_TEST_SELFIE") == "1":
                selfie_bytes = photo_bytes
            elif selfie:
                selfie_bytes = selfie.getvalue()
            else:
                st.error("Please take a selfie.")
                selfie_bytes = b""
            if selfie_bytes:
                vec = face.enroll(photo_bytes, selfie_bytes, consent)
                st.session_state.enrolled = vec
                st.success("✅ Vector ready (128 bytes). Photo discarded from memory. Vector is never displayed or logged.")
        except face.EnrollError as exc:
            st.error(str(exc))
        except FileNotFoundError as exc:
            st.error(f"Face models missing: {exc}. Run `bash scripts/get_models.sh`.")

    if st.session_state.enrolled is not None:
        st.success("Face vector enrolled ✅")
        if st.button("Wipe vector"):
            st.session_state.enrolled = None
            st.rerun()

# ── 5. Leak Scout ────────────────────────────────────────────────────────────
with tabs[4]:
    st.subheader("🌐 Critical-Site Likeness Scout")
    st.caption("Demo crawls the local mock leak web only (port 8765). Real registry entries ship disabled.")

    reg_path = BASE / "registry/seeds.yaml"
    try:
        reg = load_registry(reg_path)
        st.table([{"domain": r["domain"], "type": r["category"], "tier": r["tier"]} for r in reg])
    except Exception as exc:
        st.error(str(exc))
        reg = []

    org = st.text_input("Organisation for text queries", "Acme Corp")
    domain = st.text_input("Domain for text queries", "acme.in")
    types = st.multiselect("Entity types to search", ["IN_AADHAAR", "IN_PAN", "IN_UPI", "MOBILE_IN"], default=["IN_AADHAAR", "IN_PAN"])

    if st.button("🔍 Run Leak Scout", type="primary"):
        bank = None
        bank_path = BASE / "demo/leak_bank.json"
        if bank_path.exists():
            try:
                bank = pdq.HashBank.load(bank_path)
            except Exception:
                pass

        enrolled = [st.session_state.enrolled] if st.session_state.enrolled is not None else []

        events = []
        with st.spinner("Crawling mock web at 1 req/s/domain…"):
            async def _go():
                async for ev in run_scout(
                    enrolled, bank, reg_path, org, types, domain, st.session_state.ledger
                ):
                    events.append(ev)
            asyncio.run(_go())

        st.session_state.matches = [ev["match"] for ev in events if ev["kind"] == "match"]
        done_evs = [ev for ev in events if ev["kind"] == "done"]
        st.session_state.scout_report = done_evs[-1]["report"] if done_evs else {"scout": {"matches": [], "text_hits": [], "counters": {}}}

        scout = st.session_state.scout_report.get("scout", {})
        counters = scout.get("counters", {})
        st.success(f"Done — matches: {len(st.session_state.matches)} | pages: {counters.get('pages',0)} | images: {counters.get('images',0)} | blocked: {counters.get('blocked',0)}")

        for ev in events:
            if ev["kind"] == "query":
                icon = "✅" if ev["allowed"] else "🚫"
                st.write(f"{icon} Query: `{ev['query']}`")
            elif ev["kind"] == "search_hit":
                st.write(f"📄 Text hit (tier {ev['hit']['tier']}{'  offline' if ev['hit'].get('offline') else ''}): {ev['hit']['url']}")
            elif ev["kind"] == "blocked":
                st.warning(f"🚫 Blocked {ev['url']}: {ev['reason']}")
            elif ev["kind"] == "match":
                st.write(f"🎯 Match: **{ev['match'].verdict}** — {ev['match'].image_url}")

# ── 6. Review ────────────────────────────────────────────────────────────────
with tabs[5]:
    st.subheader("🔍 Review Blurred Hits")
    matches = st.session_state.matches
    if not matches:
        st.info("No matches yet. Run Leak Scout.")
    else:
        # sort: confirmed first
        matches.sort(key=lambda m: (0 if m.verdict == "confirmed" else 1, m.discovered_at))
        for m in matches:
            with st.container():
                c1, c2 = st.columns([1, 3])
                with c1:
                    if m.thumb_jpeg:
                        st.image(m.thumb_jpeg, width=128, caption="blurred")
                with c2:
                    st.markdown(f"**{m.page_url}**")
                    st.write(m.image_url)
                    st.write(f"`{m.kind}` — PDQ distance={m.pdq_distance} similarity={m.similarity} — verdict: **{m.verdict}**")
                    st.write(f"Status: `{m.status}`")
                    if m.status == "pending":
                        a, b = st.columns(2)
                        if a.button("✅ Confirm", key=f"c_{m.id}"):
                            async def _confirm(match=m):
                                return await confirm(match, st.session_state.ledger, WORK / "evidence" / match.id)
                            res = asyncio.run(_confirm())
                            st.success(f"Confirmed. CDN: {res['infra'].get('cdn')} | IPs: {res['infra'].get('ips')}")
                            st.rerun()
                        if b.button("❌ Reject", key=f"r_{m.id}"):
                            reject(m, st.session_state.ledger)
                            st.success("Rejected. Thumbnail cleared.")
                            st.rerun()
                st.divider()

# ── 7. Ledger ────────────────────────────────────────────────────────────────
with tabs[6]:
    st.subheader("🔗 SHA-256 Hash-Chain Ledger")
    bad_idx = st.session_state.ledger.verify()
    if bad_idx is None:
        st.success(f"✅ LEDGER INTEGRITY VERIFIED — {len(st.session_state.ledger.blocks)} blocks")
    else:
        st.error(f"❌ Tampering detected at Block #{bad_idx}")

    c1, c2 = st.columns(2)
    with c1:
        if st.button("🔴 Simulate Tamper Attack"):
            import copy
            blocks = copy.deepcopy(st.session_state.ledger.blocks)
            if len(blocks) > 2:
                blocks[2]["details"]["simulated_tamper"] = True
                idx = st.session_state.ledger.verify(blocks)
                st.error(f"Tampering detected at Block #{idx} ✅ (detection works)")
            else:
                st.info("Need at least 3 blocks first.")
    with c2:
        if st.button("🗑️ Reset Ledger"):
            st.session_state.ledger = Ledger()
            st.rerun()

    if st.session_state.ledger.blocks:
        st.json(st.session_state.ledger.blocks[-5:])

# ── 8. Downloads ─────────────────────────────────────────────────────────────
with tabs[7]:
    st.subheader("📦 Downloads")
    report = st.session_state.doc_report
    if report and Path(report["output"]).exists():
        st.download_button(
            "⬇️ Download sanitized file",
            data=Path(report["output"]).read_bytes(),
            file_name=Path(report["output"]).name,
            mime="application/octet-stream",
        )
    else:
        st.info("Run Shield first to generate a sanitized file.")

    if st.button("📋 Build dossier ZIP"):
        scout_rep = st.session_state.scout_report or {"matches": []}
        dossier = build_dossier(
            {"doc": st.session_state.doc_report, "scout": scout_rep},
            st.session_state.ledger,
            WORK / "dossier",
        )
        st.download_button(
            "⬇️ Download dossier ZIP",
            data=dossier.read_bytes(),
            file_name=dossier.name,
            mime="application/zip",
        )

    st.divider()
    if st.button("🔒 End session & wipe all vectors/thumbnails"):
        wipe(st.session_state, st.session_state.ledger)
        st.success("✅ Face vectors and thumbnails wiped.")

