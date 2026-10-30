<template>
  <div class="step-view">
    <div class="sub-nav-bar mono">
      <button class="sub-nav-btn" :class="{ active: activeSubTab === 'review' }" @click="activeSubTab = 'review'">
        <span>01 // FORENSIC REVIEW & LEDGER</span>
      </button>
      <button class="sub-nav-btn" :class="{ active: activeSubTab === 'report' }" @click="activeSubTab = 'report'">
        <span>02 // CASE REPORT</span>
      </button>
    </div>

    <div v-if="activeSubTab === 'review'" class="tab-content-group">
      <div class="step-card">
        <div class="card-header">
          <div class="step-meta">
            <span class="step-badge mono">05</span>
            <span class="step-title">HUMAN REVIEW: IMAGE MATCHES</span>
          </div>
          <div class="step-status-tag mono" :class="session.matches.length ? 'completed' : 'pending'">{{ session.matches.length }} MATCH CANDIDATES</div>
        </div>

        <div class="card-content">
          <p class="step-desc">Thumbnails are blurred on the server (Gaussian radius 25). Every decision is sealed in the ledger.</p>

          <div v-if="session.matches.length" class="matches-list">
            <div v-for="m in session.matches" :key="m.id" class="match-card" :class="'status-' + (m.review || 'pending')">
              <div class="thumbnail-wrapper">
                <img v-if="m.thumb_b64" :src="'data:image/jpeg;base64,' + m.thumb_b64" alt="Blurred match thumbnail" class="thumb-img" />
                <div v-else class="thumb-cleared mono">CLEARED</div>
                <span class="thumb-badge mono">RADIUS 25 BLURRED</span>
              </div>

              <div class="match-details">
                <div class="match-top-row">
                  <span class="match-kind-tag mono" :class="'kind-' + m.kind">{{ (m.kind || 'image').toUpperCase() }} MATCH</span>
                  <span class="match-status-tag mono" :class="m.review || 'pending'">STATUS: {{ (m.review || 'pending').toUpperCase() }}</span>
                  <span class="match-time mono">{{ m.timestamp }}</span>
                </div>

                <div class="match-verdict mono font-bold">{{ m.evidence_status }}</div>
                <div class="mono">{{ m.match_type }}<template v-if="m.pdq_distance != null"> · PDQ distance {{ m.pdq_distance }} of 256 (0 = same)</template><template v-if="m.similarity != null"> · face similarity {{ m.similarity.toFixed(2) }}</template></div>

                <div class="url-block">
                  <div class="url-line">
                    <span class="url-label mono">PAGE:</span>
                    <a :href="m.source_url" target="_blank" rel="noopener noreferrer" class="url-text mono">{{ m.source_url }}</a>
                  </div>
                  <div class="url-line">
                    <span class="url-label mono">IMAGE:</span>
                    <span class="url-text mono dim-text">{{ m.image_url }}</span>
                  </div>
                </div>

                <div v-if="m.infra" class="infra-box">
                  <div class="infra-header mono">HOSTING TRACE</div>
                  <div class="infra-grid mono">
                    <div v-if="m.infra.cdn !== 'unknown'"><strong>CDN:</strong> {{ m.infra.cdn }}</div>
                    <div><strong>IP:</strong> {{ (m.infra.ips || []).join(', ') || 'none resolved' }}</div>
                  </div>
                </div>

                <div v-if="!m.review" class="match-actions">
                  <button class="confirm-btn mono" @click="review(m, 'confirm')">✅ CONFIRM MATCH & TRACE HOST</button>
                  <button class="reject-btn mono" @click="review(m, 'reject')">❌ REJECT (CLEAR THUMBNAIL)</button>
                </div>
              </div>
            </div>
          </div>
          <div v-else class="empty-matches mono">// No image matches. Run a crawl in Step 4.</div>
          <p v-if="error" class="err-line mono">{{ error }}</p>
        </div>
      </div>

      <div class="step-card">
        <div class="card-header">
          <div class="step-meta">
            <span class="step-badge mono">LEDGER</span>
            <span class="step-title">SHA-256 HASH-CHAIN FORENSIC LEDGER</span>
          </div>
          <div class="step-status-tag mono" :class="!session.ledgers.length ? 'pending' : allVerified ? 'completed' : 'failed'">
            {{ !session.ledgers.length ? 'NO LEDGER YET' : allVerified ? 'CHAIN INTEGRITY: VERIFIED ✅' : 'CHAIN BROKEN ❌' }}
          </div>
        </div>

        <div class="card-content">
          <p class="step-desc">Every state change and human decision is chained with SHA-256. The tamper test edits a copy and shows that verification catches it; the real ledger is not changed.</p>

          <div v-for="l in session.ledgers" :key="l.id">
            <div class="ledger-controls">
              <span class="mono font-bold">{{ l.label }}: {{ l.blocks.length }} blocks</span>
              <button class="tamper-btn mono" @click="tamper(l.id)">🔴 RUN TAMPER TEST</button>
            </div>
            <p v-if="session.tamperResult?.id === l.id" class="err-line mono">
              Edited copy of block #{{ session.tamperResult.tampered_seq }}: verification failed at block #{{ session.tamperResult.first_bad }}. Real ledger unchanged.
            </p>
            <div class="blocks-list">
              <div v-for="b in l.blocks" :key="b.seq" class="ledger-block">
                <div class="block-top mono">
                  <span class="block-seq">BLOCK #{{ b.seq }}</span>
                  <span class="block-action">[{{ b.action }}]</span>
                  <span class="block-actor">{{ b.actor }}</span>
                  <span class="block-time">{{ b.timestamp }}</span>
                </div>
                <div class="block-hashes mono">
                  <div class="hash-row"><span class="hl">PREV:</span><span class="hv">{{ b.prev_hash }}</span></div>
                  <div class="hash-row"><span class="hl">CURR:</span><span class="hv font-bold">{{ b.current_hash }}</span></div>
                </div>
                <div class="block-details mono">{{ JSON.stringify(b.details) }}</div>
              </div>
            </div>
          </div>
          <p v-if="!session.ledgers.length" class="empty-matches mono">// The ledger starts with the first job.</p>
        </div>
      </div>

      <div class="step-card">
        <div class="card-header">
          <div class="step-meta">
            <span class="step-badge mono">EXPORT</span>
            <span class="step-title">ARTIFACT DOWNLOADS & DOSSIER</span>
          </div>
        </div>

        <div class="card-content">
          <div class="downloads-grid">
            <div class="download-card">
              <div class="dc-icon">📄</div>
              <div class="dc-info">
                <span class="dc-title mono">SANITIZED DOCUMENT</span>
                <span class="dc-desc">Available only when every red team check passed.</span>
              </div>
              <a v-if="canDownload" class="dc-btn mono" :href="api.downloadUrl(session.jobId)" download>⬇️ DOWNLOAD SANITIZED</a>
              <span v-else class="dc-btn mono disabled">{{ session.redaction ? 'WITHHELD: CHECKS FAILED' : 'REDACT FIRST' }}</span>
            </div>

            <div class="download-card">
              <div class="dc-icon">📦</div>
              <div class="dc-info">
                <span class="dc-title mono">DOSSIER ZIP</span>
                <span class="dc-desc">Dossier PDF with NCRP, CERT-In, IT Rules and Section 63 BSA drafts, ledger.json and a standalone verifier. Drafts need human review.</span>
              </div>
              <a v-for="l in session.ledgers" :key="l.id" class="dc-btn mono primary" :href="api.dossierUrl(l.id)" download>⬇️ DOSSIER: {{ l.label.toUpperCase() }}</a>
              <span v-if="!session.ledgers.length" class="dc-btn mono disabled">NO CASE YET</span>
            </div>
          </div>

          <div class="wipe-callout">
            <div class="callout-text">
              <strong>END OF CASE SESSION:</strong>
              Deletes every job, upload, sanitized output, reference hash and enrolment on this server, and forgets any API key set here.
            </div>
            <button class="wipe-action-btn mono" @click="handleWipeAll">🔒 END SESSION & WIPE</button>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="tab-content-group">
      <div class="step-card">
        <div class="card-header">
          <div class="step-meta">
            <span class="step-badge mono">REPORT</span>
            <span class="step-title">CASE REPORT</span>
          </div>
        </div>

        <div class="card-content">
          <p class="step-desc">Built only from what this case produced. Nothing here is a legal conclusion.</p>
          <div class="sections-container">
            <div v-for="(sec, sIdx) in report" :key="sec.title" class="report-section-card">
              <div class="section-title-row" @click="collapsed[sIdx] = !collapsed[sIdx]">
                <span class="sec-index mono">0{{ sIdx + 1 }}</span>
                <span class="sec-headline mono">{{ sec.title }}</span>
                <span class="sec-arrow mono">{{ collapsed[sIdx] ? '▶' : '▼' }}</span>
              </div>
              <div v-show="!collapsed[sIdx]" class="section-body-markdown">
                <pre class="report-pre">{{ sec.content }}</pre>
              </div>
            </div>
          </div>
          <p v-if="!report.length" class="empty-matches mono">// Nothing to report yet.</p>
          <div v-else class="report-export-row">
            <button class="report-act-btn mono" @click="copyReport">📋 {{ copied ? 'COPIED' : 'COPY FULL REPORT' }}</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { session } from '../../store/session'
import { refreshLedgers, reviewMatch, tamperDemo, wipeAll } from '../../api/case'
import { buildReport } from '../../api/map'
import { api } from '../../api/index'

const router = useRouter()
const activeSubTab = ref('review')
const collapsed = reactive({})
const copied = ref(false)
const error = ref('')

const report = computed(() => buildReport(session))
const allVerified = computed(() => session.ledgers.length > 0 && session.ledgers.every((l) => l.first_bad === null))
const canDownload = computed(() => session.redaction?.status === 'CLEAN')

const review = (m, decision) => reviewMatch(m, decision).catch((e) => { error.value = e.message })
const tamper = (id) => tamperDemo(id).catch((e) => { error.value = e.message })

const copyReport = async () => {
  await navigator.clipboard.writeText(report.value.map((s) => `## ${s.title}\n${s.content}`).join('\n\n'))
  copied.value = true
}

const handleWipeAll = async () => {
  if (!confirm('Delete every job, upload, output, reference hash and enrolment in this session?')) return
  try {
    await wipeAll()
    router.push('/')
  } catch (e) {
    error.value = `Wipe failed: ${e.message}`
  }
}

onMounted(() => refreshLedgers().catch(() => {}))
</script>

<style scoped>
.step-view {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.sub-nav-bar {
  display: flex;
  background: var(--panel);
  border: 1px solid var(--line);
  overflow-x: auto;
}

.sub-nav-btn {
  background: transparent;
  border: none;
  border-right: 1px solid var(--line);
  padding: 10px 16px;
  font-size: 11px;
  font-weight: 800;
  color: var(--ink);
  opacity: 0.65;
  cursor: pointer;
  white-space: nowrap;
  transition: all 0.15s ease;
}

.sub-nav-btn:hover {
  opacity: 1;
  background: rgba(0, 0, 0, 0.04);
}

.sub-nav-btn.active {
  opacity: 1;
  background: var(--fascia);
  border-bottom: 2px solid var(--blue);
  color: var(--ink);
}

.tab-content-group {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.step-card {
  background: var(--panel);
  border: 1px solid var(--line);
}

.card-header {
  height: 42px;
  background: var(--fascia);
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
}

.step-meta {
  display: flex;
  align-items: center;
  gap: 10px;
}

.step-badge {
  background: var(--ink);
  color: var(--panel);
  font-size: 11px;
  font-weight: 800;
  padding: 2px 6px;
}

.step-title {
  font-size: 12.5px;
  font-weight: 800;
  letter-spacing: 0.5px;
  color: var(--ink);
}

.step-status-tag {
  font-size: 10px;
  font-weight: 800;
  padding: 3px 8px;
}

.step-status-tag.completed {
  background: #2E9E6B20;
  color: #2E9E6B;
  border: 1px solid #2E9E6B;
}

.step-status-tag.failed {
  background: #C8312B20;
  color: var(--red);
  border: 1px solid var(--red);
}

.step-status-tag.pending {
  background: var(--fascia);
  border: 1px solid var(--line);
  color: var(--ink);
}

.card-content {
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.api-note {
  font-size: 9.5px;
  color: #7E848A;
}

.step-desc {
  font-size: 12.5px;
  line-height: 1.4;
  color: var(--ink);
}

/* Match Cards */
.matches-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.match-card {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 12px;
  display: flex;
  gap: 16px;
}

.thumbnail-wrapper {
  width: 128px;
  height: 128px;
  background: #17191B;
  border: 1px solid var(--line);
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.thumb-img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.thumb-cleared {
  color: #7E848A;
  font-size: 10px;
}

.thumb-badge {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  background: rgba(0, 0, 0, 0.7);
  color: #FFF;
  font-size: 8px;
  text-align: center;
  padding: 2px 0;
}

.match-details {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.match-top-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 10px;
}

.match-kind-tag {
  background: var(--blue);
  color: #FFF;
  font-weight: 800;
  padding: 2px 6px;
}

.match-kind-tag.kind-face {
  background: #E0245E;
}

.match-status-tag {
  border: 1px solid var(--line);
  padding: 2px 6px;
  font-weight: 700;
}

.match-status-tag.confirmed {
  border-color: #2E9E6B;
  color: #2E9E6B;
}

.match-status-tag.rejected {
  border-color: var(--red);
  color: var(--red);
}

.match-time {
  margin-left: auto;
  color: #7E848A;
}

.match-verdict {
  font-size: 13px;
  color: var(--ink);
}

.url-block {
  display: flex;
  flex-direction: column;
  gap: 3px;
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 8px;
}

.url-line {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 11px;
}

.url-label {
  font-size: 9.5px;
  font-weight: 700;
  color: #7E848A;
  min-width: 45px;
}

.url-text {
  color: var(--blue);
  word-break: break-all;
  text-decoration: none;
}

.url-text:hover {
  text-decoration: underline;
}

.dim-text {
  color: var(--ink);
  opacity: 0.8;
}

.hash-line {
  font-size: 10px;
  display: flex;
  align-items: center;
  gap: 6px;
  color: #7E848A;
}

.hash-string {
  color: var(--ink);
}

.infra-box {
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 8px 10px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.infra-header {
  font-size: 9.5px;
  font-weight: 800;
  color: #2E9E6B;
}

.infra-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 4px 12px;
  font-size: 10.5px;
  color: var(--ink);
}

.match-actions {
  display: flex;
  gap: 10px;
  margin-top: 4px;
}

.confirm-btn {
  background: var(--ink);
  color: var(--panel);
  border: 1px solid var(--ink);
  font-size: 10.5px;
  font-weight: 700;
  padding: 6px 14px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.confirm-btn:hover {
  background: #2E9E6B;
  border-color: #2E9E6B;
  color: #FFF;
}

.reject-btn {
  background: transparent;
  color: var(--red);
  border: 1px solid var(--red);
  font-size: 10.5px;
  font-weight: 700;
  padding: 6px 14px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.reject-btn:hover {
  background: var(--red);
  color: #FFF;
}

.empty-matches {
  font-size: 11px;
  color: #7E848A;
  font-style: italic;
  padding: 20px 0;
}

/* Ledger */
.ledger-controls {
  display: flex;
  gap: 10px;
}

.tamper-btn {
  background: transparent;
  color: var(--red);
  border: 1px solid var(--red);
  font-size: 10.5px;
  font-weight: 700;
  padding: 6px 14px;
  cursor: pointer;
}

.tamper-btn:hover {
  background: var(--red);
  color: #FFF;
}

.reset-btn {
  background: var(--fascia);
  border: 1px solid var(--line);
  color: var(--ink);
  font-size: 10.5px;
  font-weight: 700;
  padding: 6px 14px;
  cursor: pointer;
}

.reset-btn:hover {
  border-color: var(--ink);
}

.blocks-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.ledger-block {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.ledger-block.tampered-block {
  border-color: var(--red);
  background: #C8312B14;
}

.block-top {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 11px;
}

.block-seq {
  font-weight: 800;
  color: var(--blue);
}

.block-action {
  font-weight: 700;
  color: var(--ink);
}

.block-actor {
  color: #7E848A;
}

.block-time {
  margin-left: auto;
  font-size: 10px;
  color: #7E848A;
}

.tamper-pill {
  background: var(--red);
  color: #FFF;
  font-size: 9px;
  font-weight: 800;
  padding: 2px 6px;
}

.block-hashes {
  display: flex;
  flex-direction: column;
  gap: 2px;
  font-size: 9.5px;
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 6px 8px;
}

.hash-row {
  display: flex;
  gap: 8px;
}

.hl {
  color: #7E848A;
  min-width: 40px;
}

.hv {
  color: var(--ink);
  word-break: break-all;
}

.block-details {
  font-size: 10px;
  color: #6C727A;
  word-break: break-all;
}

/* Downloads */
.downloads-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.download-card {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 14px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.dc-icon {
  font-size: 24px;
}

.dc-title {
  font-size: 12px;
  font-weight: 800;
  color: var(--ink);
}

.dc-desc {
  font-size: 11.5px;
  color: #6C727A;
  line-height: 1.35;
  margin-top: 2px;
}

.dc-btn {
  background: var(--panel);
  border: 1px solid var(--line);
  color: var(--ink);
  font-size: 11px;
  font-weight: 700;
  padding: 7px;
  cursor: pointer;
  margin-top: auto;
  transition: all 0.15s ease;
}

.dc-btn:hover {
  border-color: var(--ink);
}

.dc-btn.primary {
  background: var(--ink);
  color: var(--panel);
  border-color: var(--ink);
}

.dc-btn.primary:hover {
  background: var(--blue);
  border-color: var(--blue);
  color: #FFF;
}

.wipe-callout {
  border: 1px solid var(--red);
  background: #C8312B0F;
  padding: 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.callout-text {
  font-size: 12px;
  color: var(--ink);
  line-height: 1.4;
}

.wipe-action-btn {
  background: var(--red);
  color: #FFF;
  border: 1px solid var(--red);
  font-size: 11px;
  font-weight: 800;
  padding: 8px 16px;
  white-space: nowrap;
  cursor: pointer;
}

.wipe-action-btn:hover {
  background: #A02620;
}

/* Report Styles */
.report-header-banner {
  background: var(--fascia);
  border: 1px solid var(--line);
  border-top: 3px solid var(--blue);
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.rh-meta {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 9.5px;
}

.rh-tag {
  background: var(--ink);
  color: var(--panel);
  font-weight: 800;
  padding: 2px 6px;
}

.rh-sub {
  color: #7E848A;
  font-weight: 700;
}

.rh-title {
  font-size: 18px;
  font-weight: 900;
  color: var(--ink);
}

.rh-summary {
  font-size: 12px;
  line-height: 1.45;
  color: var(--ink);
}

.report-quick-stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
  margin-top: 4px;
}

.rq-box {
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 8px 10px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.rq-label {
  font-size: 8px;
  font-weight: 700;
  color: #7E848A;
}

.rq-val {
  font-size: 11.5px;
  font-weight: 800;
  color: var(--ink);
}

.text-red { color: var(--red); }
.text-green { color: #2E9E6B; }

.sections-container {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.report-section-card {
  background: var(--fascia);
  border: 1px solid var(--line);
}

.section-title-row {
  height: 40px;
  padding: 0 14px;
  display: flex;
  align-items: center;
  gap: 12px;
  cursor: pointer;
  user-select: none;
  background: var(--fascia);
  border-bottom: 1px solid var(--line);
}

.section-title-row:hover {
  background: rgba(0, 0, 0, 0.03);
}

.sec-index {
  font-size: 11px;
  font-weight: 800;
  color: var(--blue);
}

.sec-headline {
  font-size: 12px;
  font-weight: 800;
  color: var(--ink);
}

.sec-arrow {
  margin-left: auto;
  font-size: 10px;
  color: #7E848A;
}

.section-body-markdown {
  padding: 14px;
  background: var(--panel);
}

.report-pre {
  font-family: var(--font-ui);
  white-space: pre-wrap;
  font-size: 12px;
  line-height: 1.5;
  color: var(--ink);
}

.report-export-row {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  margin-top: 6px;
}

.report-act-btn {
  background: var(--panel);
  border: 1px solid var(--line);
  color: var(--ink);
  font-size: 11px;
  font-weight: 800;
  padding: 8px 16px;
  cursor: pointer;
}

.report-act-btn.primary {
  background: var(--ink);
  color: var(--panel);
  border-color: var(--ink);
}

.report-act-btn.primary:hover {
  background: var(--blue);
  border-color: var(--blue);
  color: #FFF;
}

/* Chat Styles */
.agent-target-selector {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 10px;
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 8px 12px;
  overflow-x: auto;
}

.target-label {
  font-weight: 800;
  color: #7E848A;
}

.target-pill {
  background: var(--panel);
  border: 1px solid var(--line);
  color: var(--ink);
  padding: 4px 10px;
  font-size: 10.5px;
  font-weight: 700;
  cursor: pointer;
  white-space: nowrap;
}

.target-pill.active {
  background: var(--blue);
  color: #FFF;
  border-color: var(--blue);
}

.chat-viewport {
  height: 340px;
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 14px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  overflow-y: auto;
}

.chat-bubble-row {
  display: flex;
  gap: 10px;
  max-width: 85%;
}

.chat-bubble-row.user {
  margin-left: auto;
  flex-direction: row-reverse;
}

.chat-avatar {
  font-size: 18px;
}

.chat-bubble {
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 8px 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.chat-bubble-row.user .chat-bubble {
  background: var(--ink);
  color: var(--panel);
  border-color: var(--ink);
}

.bubble-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  font-size: 9px;
  color: #7E848A;
}

.chat-bubble-row.user .bubble-header {
  color: #B5B8B6;
}

.bubble-sender {
  font-weight: 800;
  color: var(--blue);
}

.chat-bubble-row.user .bubble-sender {
  color: #FFFFFF;
}

.bubble-text {
  font-size: 12px;
  line-height: 1.4;
}

.quick-prompts-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 9.5px;
  overflow-x: auto;
}

.qp-label {
  font-weight: 800;
  color: #7E848A;
  white-space: nowrap;
}

.qp-chip {
  background: var(--fascia);
  border: 1px solid var(--line);
  color: var(--ink);
  padding: 4px 8px;
  font-size: 9.5px;
  font-weight: 700;
  cursor: pointer;
  white-space: nowrap;
}

.qp-chip:hover {
  border-color: var(--blue);
  color: var(--blue);
}

.chat-input-bar {
  display: flex;
  gap: 8px;
}

.chat-input {
  flex: 1;
  background: var(--fascia);
  border: 1px solid var(--line);
  color: var(--ink);
  padding: 8px 12px;
  font-size: 11.5px;
  outline: none;
}

.chat-input:focus {
  border-color: var(--blue);
}

.send-btn {
  background: var(--ink);
  color: var(--panel);
  border: 1px solid var(--ink);
  font-size: 11px;
  font-weight: 800;
  padding: 0 18px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.send-btn:hover {
  background: var(--blue);
  border-color: var(--blue);
  color: #FFF;
}
</style>
