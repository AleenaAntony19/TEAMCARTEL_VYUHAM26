# Connections

How the surfaces talk to the shared engine. Everything below is implemented and covered by tests in `tests/`.

```
React (web/)  ── fetch /api/* ──────────────┐
Dashboards    ── /api/v1/* (REST + SSE) ────┤──▶ shield/api (FastAPI: server.py + v1.py)
VS Code (vscode/) ── spawn python -m shield.codescan / shield.llm (JSON on stdout)
                                              └──▶ shield/* engine (detect, review, redact, verify, scout, ledger)
```

## REST / SSE contract (`/api/v1`, OpenAPI at `/docs`)
| Call | Flow |
|---|---|
| `POST /shield/analyze` (file or text) → `{job_id}` | job graph `intake → deliberate`; poll `GET /shield/jobs/{job_id}` |
| `GET /swarm/deliberate?job_id=` (SSE) | `start`, then per entity the persona `turn` events (round 1: PrivacyHawk CLAIM, PragmaticDev CHALLENGE, StatutoryAuditor CHECK; round 2: SwarmAdjudicator VERDICT), a `verdict`, and finally `end`. Values are masked |
| `POST /shield/redact {job_id, selections, dry_run}` | `object_redact → red_team_attack (→ one aggressive retry) → consensus_ledger`; returns checks, status, `ledger_head`, `ledger_valid` |
| `POST /scout/search` / `POST /scout/crawl` | firewalled queries → provider (`brave`, `google_cse`, `serper`, `offline`); crawl = registry seeds, SSRF guard, robots, 1 rps/domain, PDQ (+ opt-in faces) |
| `POST /scout/enroll` (photo, live selfie, consent) | int8 SFace vector kept in memory only; `DELETE` removes it |
| `GET /dossier/export?job_id=` | ZIP: dossier.pdf, ledger.json, verify_ledger.py, README.txt |

The unversioned `/api/*` routes used by the bundled React app are documented in [docs/API.md](docs/API.md).

## MCP (Model Context Protocol)
- **stdio**: `python -m shield.mcp`. Use `SHIELD_MCP_ROOT` to limit which files a client may open. The VS Code command "Shield: Run AI Agent Swarm on Workspace (MCP)" uses this transport via `@modelcontextprotocol/sdk`.
- **Streamable HTTP**: `POST /mcp/` on the API (stateless JSON responses). It needs `SHIELD_API_TOKEN` when that is set.
- **Tools**: `open_document`, `list_findings`, `validate_checksum`, `extract_ocr_region`, `compute_perceptual_pdq`, `compute_pca_projection`, `measure_layout`, `execute_destructive_redaction`, `adversarial_penetration_test`, `open_workspace`, `list_code_findings`, `refactor_code_secret`, `rescan_workspace`, `run_agent_swarm`. In-process agents also get `spawn_specialist_agent`.
- **Resources**: `shield://doc/{id}/metadata`, `shield://doc/{id}/layers` (masked), `shield://ledger/{job_id}/chain`.
- **Swarm over HTTP**: `POST /api/v1/swarm/run {job_id}` starts the run; `GET /api/v1/swarm/events?job_id=` streams it as SSE (spawns, tool calls with masked observations, binding plan, end with token totals). Every tool call is chained into the job's SHA-256 ledger.

## VS Code ⇄ engine
- Scan: `python -m shield.codescan scan <root> --format json --workers N --timeout S [--no-ocr] [--exclude G] [--files F…]`. Exit 0 means clean, 1 means critical/high findings; any other code is an error.
- Fix: `… fix <root> --id <finding> --kind <kind> [--file F] --dry-run` returns the plan (edits and op summaries, never the secret). Without `--dry-run` it applies the plan after the user confirms in VS Code.
- Explain: `python -m shield.llm explain` with the finding on stdin; provider and key come from env set by the extension (key from Secret Storage).
