# Shield·Scout API

The versioned dashboard contract (`/api/v1/...`) is in [../connections.md](../connections.md). The routes below are the ones the bundled React app uses.

Base: `http://127.0.0.1:8000`. Live OpenAPI schema: `/docs` (Swagger) and `/openapi.json`. All bodies are JSON unless noted. If `SHIELD_API_TOKEN` is set, every `/api/*` call needs `Authorization: Bearer <token>`.

| Method & path | Purpose | Notes |
|---|---|---|
| `GET /api/health` | tool availability (tesseract, pdftotext, face models) | |
| `GET /api/config` | limits, search provider, LLM state (no key), **data that can leave the machine** | |
| `POST /api/jobs` | start analysis. multipart: `file` **or** form field `text` | 202 `{id}`; 422 on invalid upload; 429 when too many jobs |
| `GET /api/jobs/{id}` | status, stages (`name,status,detail,ms`), findings, redaction, discovery | findings carry masked evidence only |
| `POST /api/jobs/{id}/cancel` | cooperative cancel (checked between stages / crawl ticks) | |
| `DELETE /api/jobs/{id}` | delete job and its files | |
| `DELETE /api/session` | delete all jobs, reference hashes, runtime LLM key | |
| `POST /api/jobs/{id}/redact` | `{selections:[{finding_id, action: token\|mask\|remove}], dry_run}` | dry run → preview text or plan; apply → `{status: CLEAN\|FAILED, checks[], sha256, preview_text}` |
| `GET /api/jobs/{id}/download` | sanitized file | 409 unless status CLEAN |
| `GET /api/jobs/{id}/preview.png` | first page / image of the sanitized output | PDF and image inputs |
| `POST /api/jobs/{id}/fingerprint` | PDQ region hashes of an image input | matching only, not redaction |
| `POST /api/references` | multipart `file`, `label`, `authorized=true` | stores PDQ hashes only |
| `GET /api/references` | labels + hash row count | |
| `POST /api/discovery` | `{org, domain?, entity_types[], crawl, job_id?}` | 202 `{id}`; poll `GET /api/jobs/{id}` → `discovery.{queries,results,crawl}` |
| `GET /api/llm` / `PUT /api/llm` | read / set `{provider, model, endpoint, api_key, timeout, retries}` | key is write-only (`key_set` boolean) |
| `POST /api/llm/test` | round-trip test | |
| `POST /api/llm/explain` | `{job_id, finding_id}` → `{explanation, sent_fields, is_evidence:false}` | |

Job lifecycle: `queued → running → ready | failed | cancelled`. Jobs and files expire after `SHIELD_JOB_TTL_SECONDS` (default 3600). At most `SHIELD_MAX_JOBS` run at once.

Finding shape (analysis):
```json
{"id":"…","type":"IN_AADHAAR","severity":"critical","confidence":0.99,"layer":"visible",
 "location":{"layer":"visible","start":34,"end":48},"masked":"•••• •••• 0124",
 "evidence":"Aadhaar •••• •••• 0124 PAN ••••••234F","analyzer":"pattern:IN_AADHAAR",
 "checks":[{"reviewer":"validator","rule":"verhoeff","passed":true,"evidence":"Verhoeff checksum passed"}],
 "recommendation":"…","actions":["token","mask","remove"]}
```
