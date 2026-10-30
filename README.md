# Shield·Scout

Find sensitive data in text, images and documents. Redact it for real (the underlying text and pixels are removed, not just covered), verify the result with independent checks, and look for places where the content may already have leaked.

> Vyuham'26 challenge AF-13: Privacy Leakage Detection, Secure Redaction & Leak Discovery.

Three connected surfaces share one Python engine (`shield/`):

| Surface | What it does | Run |
|---|---|---|
| **Web app** (`web/`, React + Vite) | Paste text or upload PDF/DOCX/XLSX/PNG/JPG/TXT → findings with severity, confidence, masked evidence and location → choose token/mask/remove per finding → preview → apply → verification → download (only if every check passed). Also discovery, reference images, an activity view and an **AI provider** tab (Groq / Claude). | `python -m shield.api` → <http://127.0.0.1:8000> |
| **Backend API** (`shield/api/`, FastAPI) | `/api/v1` contract: `shield/analyze`, `shield/redact`, `scout/search`, `scout/crawl`, `scout/enroll`, `swarm/deliberate` (SSE), `dossier/export`. Async jobs move through a checked graph (`intake → deliberate → object_redact → red_team_attack → consensus_ledger`) with a per-job SHA-256 ledger. OpenAPI at `/docs`; see [connections.md](connections.md) and [docs/API.md](docs/API.md). | same |
| **VS Code extension** (`vscode/`) | Scans the workspace (secrets, Indian PII, bandit SAST, risky config, images with OCR, PDFs/Office files) with bounded parallel analyzers, progress, cancellation and timeouts; diagnostics + findings tree; quick fixes with a diff preview and an explicit confirmation step; an **AI Provider** panel (Groq / Claude). | see [vscode/README.md](vscode/README.md) |

The original Streamlit demo (`app.py`) still runs (`streamlit run app.py`) for the likeness-scout/ledger demo.

## Quick start

```bash
source /Users/aaronr/py311/bin/activate          # or any Python 3.11 env
pip install -r requirements.txt
brew install tesseract poppler                    # OCR + pdftotext (used by verification)
bash scripts/get_models.sh                        # YuNet/SFace ONNX models (face *region* detection)
cp .env.example .env                              # optional: fill in only what you use

(cd web && npm ci && npm run build)               # web UI, served by the API from web/dist
PYTHONPATH=$PWD python -m shield.api              # http://127.0.0.1:8000  (API docs: /docs)
```

Development UI with hot reload: `cd web && npm run dev` (http://localhost:5173, proxies `/api` to port 8000).

Run every check: `bash scripts/validate.sh`.

## How it works

1. **Validate upload**: allowed type plus magic-byte check, size cap, PDF page cap, image pixel cap, zip-bomb and path-traversal checks for Office files ([shield/uploads.py](shield/uploads.py)). The client filename is never used as a path.
2. **Extract layers**: PDF visible text, annotations, embedded files, metadata/XMP; Office XML of every part (comments, tracked changes, hidden sheets) and `docProps`; image OCR and EXIF ([shield/profile.py](shield/profile.py) `layer_texts`).
3. **Detect**: deterministic patterns with validation (Verhoeff for Aadhaar, Luhn for cards, PAN/GSTIN/IFSC/UPI formats, context-gated bank accounts) ([shield/detect.py](shield/detect.py)).
4. **Deliberate**: a 2-round persona ring (🦅 PrivacyHawk claims, 💻 PragmaticDev challenges placeholders and invoice numbers, ⚖️ StatutoryAuditor runs Verhoeff/Luhn, 🧠 SwarmAdjudicator rules with "checksum beats context"). It is deterministic, has no loop and no LLM, every turn carries masked evidence, and it streams over SSE ([agents.md](agents.md)).
5. **Redact** the selected findings: text gets token/mask/remove; PDFs get PyMuPDF redaction with `PDF_REDACT_IMAGE_PIXELS`, plus annotation, embedded-file and metadata removal; DOCX/XLSX are rewritten at XML level; images get an opaque fill over the OCR word boxes and EXIF is dropped. The output is always a new file; the original is kept.
6. **Verify** with independent attacks ([shield/verify.py](shield/verify.py)): text extraction (`pdftotext` / XML / OCR), a binary grep over *decompressed* streams, and a metadata audit. A check that cannot run (e.g. OCR missing) is reported as **FAIL**, never as clean. On failure, one aggressive retry runs (rasterize / raw-byte replace), then the result is reported as-is. Download is only enabled for CLEAN.

### Image matching: PDQ, PCA, faces

- **PDQ** ([shield/pdq.py](shield/pdq.py)): 8 dihedral hashes × regions (full, centre 80%/60%), Hamming distance ≤31 = strong match. Used for discovery crawl matching and repo near-duplicates. A fingerprint is **not** redaction; the UI says so.
- **PCA** ([shield/pcamatch.py](shield/pcamatch.py)): 64×64 equalised grayscale features, PCA fit on a defined index set (reference + half the decoys), cosine in PCA space, threshold calibrated on index negatives. Measured with `python -m shield.pcamatch eval` on the bundled mock set (1 reference, 10 transformed positives, 20 fit decoys, 20 held-out decoys):

  | Method | Threshold | Recall | Held-out false-positive rate |
  |---|---|---|---|
  | PCA (k=16) | cos ≥ 0.499 | 0.8 | 0.0 |
  | Raw-pixel cosine baseline | cos ≥ 0.557 | 0.6 | 0.0 |
  | PDQ | Hamming ≤ 31 | 0.7 | 0.0 |

  Limits: a tiny synthetic dataset; pixel features are not rotation-invariant (rot90 scores 0.28); PCA is a candidate-retrieval aid that needs review, not an identity or general similarity algorithm. It is offered as an evaluation module, not wired into automatic verdicts.
- **Faces**: analysis only *detects face regions* (YuNet) so photos can be removed with an opaque fill. Likeness matching is opt-in: `POST /api/v1/scout/enroll` needs consent plus a selfie that matches the photo (SFace cosine ≥ 0.363). It keeps one 128-byte int8 vector in memory, which is then used only by `scout/crawl` with `use_faces: true`. Crawled bytes stay in RAM and only a 128 px, radius-25 blurred thumbnail is kept for review.

### Discovery

Queries are built from organisation/domain and entity *types* only (plus up to 4 LLM suggestions if a provider is set). Every query goes through the privacy firewall ([shield/textscout.py](shield/textscout.py) `firewall`), which blocks any detected personal value and, when linked to an analysis, that document's values. Search providers are pluggable: `brave`, `google_cse` (Google Programmable Search JSON API), `serper`, or `offline` (bundled fixtures, clearly labelled). Optional crawl: registry seeds only ([registry/seeds.yaml](registry/seeds.yaml)), robots.txt honoured, rate/page/depth limits, an SSRF guard that re-checks the *connected* IP (DNS-rebinding defence), and no redirects to private networks or non-http(s) schemes. Results show URL, title, masked excerpt, timestamp, match type, score and status (`candidate: needs human review` vs `confirmed: PDQ strong match`).

## AI providers (optional)

Deterministic analysis never needs an LLM. A provider only adds plain-language explanations and extra discovery queries. Configure it in the web **AI provider** tab, the VS Code **AI Provider** panel, or env vars:

| Variable | Meaning |
|---|---|
| `SHIELD_LLM_PROVIDER` | `none` (default), `groq` (development), `anthropic` (production) |
| `SHIELD_LLM_MODEL` | default `llama-3.3-70b-versatile` (Groq) / `claude-haiku-5-5` (Anthropic) |
| `GROQ_API_KEY` / `ANTHROPIC_API_KEY` | keys; never logged, printed or returned by the API |
| `SHIELD_LLM_ENDPOINT`, `SHIELD_LLM_TIMEOUT`, `SHIELD_LLM_RETRIES` | https endpoint override; 1–120 s; 0–5 retries |

What is sent: finding type, rule, severity, confidence, layer and **masked** evidence. Never document text or raw values. Output is labelled "advice, not evidence".

> ⚠️ Any API key that was ever pasted into a chat, ticket or commit is compromised: revoke and rotate it at the provider before using this tool. No key is stored in this repo; `.githooks/pre-commit` blocks commits that contain one.

## Privacy & safety

See [SECURITY.md](SECURITY.md) for the threat model, the dev-only deployment assumptions and the exact list of data that can leave the machine. In short: local-only mode (`SHIELD_LOCAL_ONLY=1`) disables every remote LLM/search call; uploads live in per-job `0700` temp dirs deleted on job delete, session clear or TTL; logs record job id, stage and status only.

## Tests

`bash scripts/validate.sh` runs:
- pytest: detection, review, redaction for every format, verification (fail-closed), API flows, upload limits, SSRF, LLM providers, codescan, PCA;
- web: typecheck, unit tests and build;
- extension: typecheck, unit tests and build;
- the mock-web scout run.
