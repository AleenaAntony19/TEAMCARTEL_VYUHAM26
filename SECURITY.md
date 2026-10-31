# Security & privacy notes

## Deployment model (read before exposing the API)
- **Development / single-user tool.** There are no user accounts. The API binds to `127.0.0.1` by default. All jobs, reference hashes and the runtime LLM key are shared by whoever can reach the port.
- To put it on a network: set `SHIELD_API_TOKEN` (bearer auth on every `/api` call; the web UI asks for the token once and keeps a strict HttpOnly cookie), terminate TLS in a reverse proxy, restrict `SHIELD_CORS_ORIGINS`, and run one instance per user or add real authn/authz first. It is **not production-ready** as a multi-tenant service.

## What can leave the machine
| When | What | Where |
|---|---|---|
| LLM provider configured and "Explain" used | finding type, rule, engine, severity, confidence, layer, masked evidence | Groq or Anthropic endpoint (https only) |
| AI deep scan (opt-in, asked every scan: `--cognitive`, or the **AI Deep Scan** command and its dialog) | **raw text** of images (OCR), documents and text notes (`.txt .md .csv .tsv .log`), never source code, with values the detectors already know blanked first. Max 30 files, 48,000 characters each | Groq or Anthropic endpoint. `SHIELD_LOCAL_ONLY=1` turns it off |
| Discovery with an AI provider set | subject name plus masked search titles and snippets (one batched call per round, 2 rounds at most). Skipped if the subject fails the firewall | Groq or Anthropic endpoint |
| Confirming an image match | the page hostname | rdap.org |
| Agent swarm run (opt-in) | masked findings, masked tool observations (OCR text is masked), agent prompts | Groq or Anthropic endpoint |
| LLM provider configured and discovery run | org, domain, entity type names | same |
| Search provider configured | firewall-approved query strings (org/domain + generic terms) | Brave or Google Programmable Search |
| Discovery crawl requested | HTTP GETs to registry seed domains | those sites |
| Dependency audit | not implemented | n/a |

`SHIELD_LOCAL_ONLY=1` disables every LLM and search call (the offline fixture provider is used). Nothing else makes network requests.

## Controls in code
- **Uploads** ([shield/uploads.py](shield/uploads.py)): extension allowlist + magic bytes; size, PDF page, image pixel (decompression-bomb) and text length caps; Office zip member count, total size, compression ratio and path-traversal checks; encrypted PDFs rejected. Stored as `input<suffix>` in a per-job `mkdtemp` (0700) directory, never under the client filename.
- **Retention**: job dirs are deleted on job delete, session clear, or after the TTL (`SHIELD_JOB_TTL_SECONDS`, swept on each request). Reference images are reduced to PDQ hashes and the pixels are discarded at once.
- **Verification fails closed**: a check that cannot run is a FAIL; download is refused unless all checks pass.
- **Logs**: job id, stage, status and duration only; exception *type* names only (messages may contain document text).
- **SSRF** ([shield/net.py](shield/net.py)): http/https only; every hop's host must resolve to global IPs; the *connected* peer IP is re-checked (DNS rebinding); ≤3 redirects; 5 MB body cap; robots.txt honoured; 403/429/CAPTCHA stop the domain. `SHIELD_ALLOW_LOCAL=1` (tests/demo only) allows loopback.
- **Discovery firewall**: no query may contain a detected personal value or a value from the linked analysis.
- **Secrets**: LLM keys come from env or are set at runtime into process memory (web) / VS Code Secret Storage (extension). They are never echoed by the API, never logged, and are cleared by "Clear session data". `.githooks/pre-commit` (enable with `git config core.hooksPath .githooks`) blocks commits with secrets or Indian PII.
- **Biometrics**: the web/API flow does face *region detection* only, to support opaque removal of photos. Face recognition vectors exist only in the opt-in Streamlit likeness demo (consent + selfie match, memory only).

## Agent swarm guarantees
- Tools address findings by id; raw values stay in the engine process.
- AI deep scan is the one path that sends raw file text. Its model answers are untrusted: an item counts only if it quotes the text, it cannot rate itself critical, it can only add findings, and `.shield/cache/cognitive.json` keeps masked findings only (git-ignored by its own `.gitignore`).
- The redaction tool enforces a floor that no LLM verdict can lower.
- A "keep" must be grounded in a PragmaticDev challenge.
- The workspace swarm writes code only through `refactor_code_secret`, which checks Python with `ast` and backs up the original first. The VS Code command asks for confirmation.
- MCP file access is limited to `SHIELD_MCP_ROOT`.

## Known limits
- Small/free LLM tiers rate-limit hard (Groq free tier is about 8k tokens per minute). Runs slow down instead of failing (header-based pacing plus retry-after), and any finding without a decision is redacted.
- OCR quality bounds image redaction: text tesseract cannot read is neither detected nor redacted. Verification OCRs the output again, but it uses the same engine family.
- Face redaction in PDFs removes the whole placed image that contains a face. DOCX/XLSX embedded photos are reported but not auto-redacted.
- The bundled demo face is a drawing that YuNet does not detect, so the demo PDF photo is not flagged as a face.
- Job state is in memory; restarting the API forgets jobs. Their leftover folders in `SHIELD_WORK_DIR` are deleted by the sweeper once older than the TTL.
- PCA matching is evaluated on a tiny synthetic set (see README); treat its hits as candidates only.
- Python threads cannot be force-killed: a cancelled job stops at the next stage boundary, and a timed-out codescan engine is abandoned (the CLI exits without waiting).
