# Agents, personas and the job graph

"Agents" in Shield·Scout are named, bounded analysis steps. They are deterministic rule sets, not free-running LLMs. The UI and the SSE stream only show turns that really ran.

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
