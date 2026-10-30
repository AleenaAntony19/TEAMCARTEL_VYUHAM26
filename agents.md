# Agents, personas and the job graph

Two layers, both real:
1. **Deterministic layer** (always on, no LLM): specialists in `profile.py` and the persona ring in `review.py`. It is the grounding the LLM swarm builds on.
2. **LLM agent swarm** (`shield/swarm.py`, opt-in, needs Groq or Claude): ReAct agents that act **only through MCP tools** (`shield/mcp/tools.py`). Their adjudicated plan is **binding**: it is executed as the redaction or code fix.

## LLM agent swarm (`POST /api/v1/swarm/run`, MCP tool `run_agent_swarm`, VS Code "Run AI Agent Swarm")
| Step | Agent | MCP tools it may call |
|---|---|---|
| plan | **MetaPlanner** spawns only the specialists needed, in one turn | `spawn_specialist_agent` |
| specialists | SovereignPIIAgent · DocumentForensicAgent · VisualLikenessAgent (documents); SecretsAuditor · PiiFixtureAuditor (code) | `validate_checksum`, `extract_ocr_region`, `compute_perceptual_pdq`, `compute_pca_projection`, `list_code_findings` |
| round 1 (parallel) | 🦅 PrivacyHawk claims · 💻 PragmaticDev challenges · ⚖️ StatutoryAuditor proves (spawned only if a checksum applies) | `list_findings`, `validate_checksum` |
| round 2 | **FormatGuard** (documents) picks layout-preserving actions · **RefactorBot** (code) picks fixes that keep code running | `measure_layout` |
| verdict | 🧠 **SwarmAdjudicator**: binding plan; redact by default, keep only what PragmaticDev challenged | — |
| execute | the plan goes straight to the tool | `execute_destructive_redaction` / `refactor_code_secret` (AST-checked, backed up) |
| red team | **AdversarialRedTeamAgent**; the MetaPlanner replans with `aggressive` up to 3 cycles | `adversarial_penetration_test` (4 attacks) / `rescan_workspace` |

Enforced in code, not delegated:
- **Safety floor**: verified Aadhaar and cards, PAN, passport, bank, UPI, GSTIN, coordinates and faces are always redacted.
- **Grounded keeps**: a "keep" without a PragmaticDev challenge is rejected.
- **"Clean"** is the attack tool's real result.
- Agents see masked values only. Tools take `finding_id`s, and raw values never leave the process.

**Bounds:** `max_steps` is 2–4 per agent; spawn depth is 1, with at most 4 children; at most 3 redact/attack cycles. Tool errors go back to the model instead of crashing the run. Rate-limit headers drive pacing.

**Token use**, measured live on `demo/out/kyc.pdf` (12 findings) with Groq `openai/gpt-oss-20b`: 11,224 tokens, 12 LLM calls, 49 s, CLEAN. Before compaction it was 20,096 tokens. The breakdown per agent is in `result.agents[].tokens` and the web panel.

## Deterministic layer

## Dynamic specialists (ontology profiler)
`shield/profile.py` reads the format, layers and domain keywords, then `AgentFactory.spawn` creates only the specialists that apply. Examples: `PdfStreamInspector` for PDFs, `SheetCacheInspector` for XLSX, `IndiaKycSpecialist` when Indian identifiers appear, `VisualLikenessAgent` when the file has images.

## Persona deliberation ring (`shield/review.py`, `SHIELD_PERSONAS`)
| Round | Persona | Action | Rule |
|---|---|---|---|
| 1 | 🦅 PrivacyHawk | CLAIM | records the detector match; precautionary keep |
| 1 | 💻 PragmaticDev | CHALLENGE | RFC 2606 / mock e-mail domains; invoice/order context near a non-Verhoeff 12-digit number |
| 1 | ⚖️ StatutoryAuditor | CHECK | Verhoeff (D5) for Aadhaar, Luhn mod-10 for cards; cites DPDP Act 2023 |
| 2 | 🧠 SwarmAdjudicator | VERDICT | **Rule of Mathematical Superiority**: a checksum result beats context; otherwise an upheld challenge dismisses; otherwise keep. Emits `layer:start-end` |

`MAX_ROUNDS = 2`; there is no loop, so it cannot deadlock or run forever. Stream it with `GET /api/v1/swarm/deliberate?job_id=` (SSE). An LLM is never part of a verdict: "Explain with AI" is shown separately as advice.

## Job graph (`shield/api/server.py` `GRAPH`)
`new → intake → deliberate → object_redact → red_team_attack → consensus_ledger`. `red_team_attack → object_redact` is the single aggressive retry, and `consensus_ledger → object_redact` allows a new selection. Any other transition returns 409. Each transition appends a SHA-256 ledger block holding types, counts and hashes only; the ledger refuses raw PII and vector-sized arrays.

## Workspace analyzers (`shield/codescan`)
| Analyzer | What it checks |
|---|---|
| `secrets` | detect-secrets plus token rules for Anthropic, OpenAI, Groq, Google, AWS, GitHub, Razorpay, Slack and private keys; critical keys say "CRITICAL: Rotate this key now"; `--history` scans git log |
| `pii` | the detectors in `detect.py` |
| `sast` | bandit, AST-based: shell injection, unsafe YAML, TLS bypass, pickle and so on |
| `config` | tracked `.env`/key files, `DEBUG`, missing `.gitignore` entries |
| `media` | EXIF, OCR with bounding boxes, face presence, PDQ near-duplicates and bank matches |
| `document` | PDF/DOCX/XLSX layers plus OCR of embedded images |

They run in parallel (`--workers`) under one overall `--timeout`.
