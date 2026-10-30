# Shield·Scout Frontend Framework

High-performance, on-device intelligence console for PII redaction and critical-site likeness scouting. Built with **Vue 3**, **Vite**, **D3.js (force-directed graph)**, and styled with the **Rupert Neve Designs** industrial console aesthetic.

---

## 1. Quick Start

### Prerequisites
- Node.js 18+ (tested on Node v20 LTS)
- npm 9+

### Installation
```bash
cd CARTEL_VYUHAM26/frontend
npm install
```

### Run in Mock Mode (Default)
Runs standalone with full offline simulations (multi-agent dialectic deliberation, 3 red-team attacks, mock crawl with 1 blocked site, 1 PDQ match, 1 face reuse match):
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

### Run in Live Mode (FastAPI Backend)
1. Start the backend adapter:
   ```bash
   cd CARTEL_VYUHAM26
   python3 api_server.py
   ```
   (Binds strictly to `http://127.0.0.1:8000`)

2. In `CARTEL_VYUHAM26/frontend/.env`, set:
   ```env
   VITE_MOCK=0
   VITE_API_BASE_URL=http://127.0.0.1:8000
   ```

3. Launch frontend:
   ```bash
   npm run dev
   ```

---

## 2. Visual System & Rules
- **Sharp 90° Corners Everywhere**: `border-radius: 0 !important` globally across all components.
- **Rupert Neve Designs Palette**:
  - Fascia: `#DADCDA` (Light) / `#202326` (Dark)
  - Console: `#17191B` (Pitch dark log strip)
  - Ink: `#1B1D20` / `#E6E7E4`
  - Neve Blue: `#4A6178` (selection & progress)
  - Scrape Red: `#C8312B` (flowing crawl edges, kill, blocked)
- **Web Scraping is ALWAYS Red**:
  All crawl / fetch edges in the knowledge graph are `--red` (#C8312B), 1.6px, dashed and flowing. Motion ceases under `prefers-reduced-motion`.
- **Entity Types**:
  10 classes matching reference ontology: `MediaOutlet`, `Entity`, `GovernmentAgency`, `Company`, `Person`, `Organization`, `InvestorInstitution`, `PolicyMaker`, `DeveloperCommunity`, `TechExecutive`.

---

## 3. Core Intelligence Modules

1. **D3.js Force-Directed Relationship Graph**:
   - Thousands-of-entities knowledge graph layout with zoom/pan and floating node details.
   - **⚡ Comm Deliberation Mode**: Highlights multi-agent persona communication pulses and debate links.
   - Flowing red scrape links indicating active leak discovery crawls.

2. **Step 1: Document Shield**:
   - Deep multi-layer stream inspection (visible text, AcroForms, XML metadata).
   - Side-by-side **Copy-Paste Test** demonstrating naive redaction byte leaks vs object-level destruction.

3. **Step 2: Dynamic Swarm & Dual-Platform Simulation Configuration**:
   - Population scaling (6, 12, 24 nodes) with individual agent cards, fuel budget, and instant kill buttons.
   - **Dual-Platform Simulation Configuration**: Microblog vs Darknet recommendation algorithms, virality spread, moderation filters, response rates, and 24h interactive activity timeline.
   - **Initial Activation Orchestration**: Narrative direction, trending hashtags (`#AADHAAR_LEAK`, `#DARKWEB_DUMP`), and seed discussion events timeline.
   - **Critical Sensitive Exposure Window**: Prominent security modal with instant redaction lock and CERT-In notice trigger.

4. **Step 3: Red Team Adversarial Verification**:
   - Automated adversarial attacks (raw stream dump, binary grep, raster OCR bypass) with real-time PASS/FAIL badges and cryptographic proof hashes.

5. **Step 4: Consented Likeness Scout**:
   - Dual-gate privacy enrollment (reference portrait + live anti-stalking selfie verification).
   - Query firewall (ALLOWED vs BLOCKED) and crawl engine across verified seeds.
   - Strict notice: *"Leads for human review, not proof."*

6. **Step 5: Review, Prediction Report & Interactive Agent**:
   - **Forensic Review & Ledger**: Server-side blurred thumbnails (radius 25), infrastructure attribution, and Section 63 BSA SHA-256 hash-chain ledger with live tamper attack simulation.
   - **Prediction Report Generation**: Collapsible structured sections (executive threat overview, attribution matrix, Section 63 BSA compliance, statutory takedown directives).
   - **Interactive Report Agent**: Dual-mode conversation engine allowing investigators to query either the unified Report Agent or specific Swarm Personas (`IndiaKycSpecialist`, `RedTeamAttacker`, `VisualLikenessAgent`).

---

## 4. Data & Event Contract

The frontend receives Server-Sent Events (SSE) via `GET /api/cases/{id}/events`. Handled in `src/api/events.js`:

| Event Kind | Payload | Action |
|---|---|---|
| `profile` | `{ file_format, domain_tags, layers }` | Profiles document structure and spawns root graph node |
| `agent` | `{ agent, status }` | Spawns format/domain inspection agent in Step 2 swarm |
| `deliberation`| `{ logs: [{ entity_val, turns: [...] }] }` | Streams dialectic consensus deliberation between personas |
| `detect` | `{ counts, severity, score }` | Maps detected PII entities to graph nodes with linkability score |
| `redact` | `{ output, sha256 }` | Records sanitized file path and hash digest |
| `attack` | `{ name, passed, evidence }` | Evaluates adversarial red-team tests (text, binary, metadata) |
| `retry` | `{ reason }` | Flags aggressive rasterization retry |
| `agents` | `{ agents: [...] }` | Spawns scout crawlers and matchers |
| `query` | `{ query, allowed }` | Runs query firewall (allowed vs blocked) |
| `search_hit` | `{ hit: { url, title, tier } }` | Displays text leak hits |
| `crawl_progress` | `{ domain, pages, images }` | Updates crawl metrics and draws red flowing scrape edges |
| `blocked` | `{ url, reason }` | Records honeypot / 403 / captcha blockage |
| `match` | `{ match: { id, kind, verdict, ... } }` | Adds suspect blurred match card for human review |
| `done` | `{ report }` | Concludes cycle and verifies ledger integrity |

---

## 5. How to Add a New Step

1. **Create the Step Component**:
   Create `src/components/steps/Step6NewWorkflow.vue`. Ensure sharp borders (`border-radius: 0`) and use tokens from `src/theme/tokens.css`.
2. **Register in Step Names**:
   In `src/store/session.js`, append your new step title to the `stepNames` array.
3. **Mount in CaseView**:
   In `src/views/CaseView.vue`:
   - Import `Step6NewWorkflow.vue`
   - Add condition `<Step6NewWorkflow v-else-if="session.currentStep === 6" />`
4. **Wire Event Handlers**:
   If your step reacts to backend events, add a case block to `handleEvent()` in `src/api/events.js`.
