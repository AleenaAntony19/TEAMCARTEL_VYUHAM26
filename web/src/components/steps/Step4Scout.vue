<template>
  <div class="step-view">
    <div class="step-card">
      <div class="card-header">
        <div class="step-meta">
          <span class="step-badge mono">04</span>
          <span class="step-title">LEAK SCOUT: SEARCH & QUERY FIREWALL</span>
        </div>
        <button class="run-scout-btn mono" :disabled="session.scoutRunning || form.org.trim().length < 2" @click="start">
          {{ session.scoutRunning ? 'SCOUT ACTIVE…' : '🔍 EXECUTE LEAK SCOUT' }}
        </button>
      </div>

      <div class="card-content">
        <div class="honest-limits-line mono">⚠️ NOTICE: Leads for human review, not proof.</div>
        <p class="step-desc">
          <strong>Text</strong> search covers the open web through the search provider. <strong>Images</strong> are checked only on your predefined sites, pages you add, and AI leads: hashing every image online needs far more compute than one server has. The PDQ matcher uses compact hashes, so it can scale out with more compute; that scale is not tested here.
        </p>

        <div class="form-row">
          <label class="mono grow">ORGANISATION
            <input class="field mono" v-model="form.org" maxlength="100" placeholder="Acme Corp" />
          </label>
          <label class="mono grow">DOMAIN (OPTIONAL)
            <input class="field mono" v-model="form.domain" maxlength="253" placeholder="acme.in" />
          </label>
        </div>
        <div class="check-row mono">
          <label v-for="t in entityTypes" :key="t"><input type="checkbox" :value="t" v-model="form.types" /> {{ t }}</label>
        </div>
        <div class="check-row mono">
          <label><input type="checkbox" v-model="form.crawl" /> ALSO CRAWL REGISTRY SITES (needs a reference image or enrolment below)</label>
          <span class="rule-hint">AI leads (first 10) are also checked by the image matcher when crawl is on.</span>
        </div>
        <label v-if="form.crawl" class="mono url-box">EXTRA PAGES TO SCAN FOR YOUR IMAGE (ONE URL PER LINE, MAX 20; ROBOTS.TXT APPLIES, LINKS ARE NOT FOLLOWED)
          <textarea class="field mono" rows="4" v-model="form.urls" placeholder="https://example.com/page"></textarea>
        </label>
        <p v-if="session.scoutError" class="err-line mono">{{ session.scoutError }}</p>
        <p v-if="crawlGap" class="err-line mono">{{ crawlGap }}</p>

        <div class="counters-row">
          <div class="counter-box">
            <span class="c-num mono">{{ session.counters.pages }}</span>
            <span class="c-label mono">PAGES CRAWLED</span>
          </div>
          <div class="counter-box">
            <span class="c-num mono">{{ session.counters.images }}</span>
            <span class="c-label mono">IMAGES EXTRACTED</span>
          </div>
          <div class="counter-box">
            <span class="c-num mono match-count">{{ session.counters.matches }}</span>
            <span class="c-label mono">SUSPECT MATCHES</span>
          </div>
          <div class="counter-box">
            <span class="c-num mono blocked-count">{{ session.counters.blocked }}</span>
            <span class="c-label mono">BLOCKED TARGETS</span>
          </div>
        </div>

        <p v-if="agentTotal" class="step-desc mono">SITE AGENTS: {{ agentTotal }} spawned, {{ agentsRunning }} running (one per site, in parallel, no AI tokens)</p>

        <div class="firewall-monitor">
          <div class="monitor-header mono">
            <span>ZERO-PII QUERY FIREWALL INSPECTOR</span>
            <span class="rule-hint">Blocks any query containing a personal value</span>
          </div>
          <div class="queries-list">
            <div v-for="(q, idx) in session.queries" :key="idx" class="query-item" :class="q.allowed ? 'allowed-item' : 'blocked-item'">
              <span class="q-badge mono" :class="q.allowed ? 'badge-allow' : 'badge-block'">{{ q.allowed ? 'ALLOWED ✅' : 'BLOCKED 🚫' }}</span>
              <span class="q-text mono">{{ q.query }}</span>
            </div>
            <p v-if="!session.queries.length" class="empty-state mono">Queries appear here when the scout runs.</p>
          </div>
        </div>

        <div class="registry-section">
          <div class="section-title mono">MONITORED LEAK REGISTRY TARGETS</div>
          <table class="registry-table">
            <thead>
              <tr>
                <th class="mono">DOMAIN</th>
                <th class="mono">CATEGORY</th>
                <th class="mono">TIER</th>
                <th class="mono">ENTRY URLS</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(r, i) in session.registry" :key="i">
                <td class="mono font-bold">{{ r.domain }}</td>
                <td class="mono">{{ r.category }}</td>
                <td class="mono">Tier {{ r.tier }}</td>
                <td class="mono">{{ (r.entry_urls || []).length }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div v-if="aiLine" class="honest-limits-line mono">{{ aiLine }}</div>

        <div v-if="session.textHits.length" class="text-hits-box">
          <div class="section-title mono">{{ session.discovery.provider === 'offline' ? 'DEMO FIXTURES, NOT REAL RESULTS (NO SEARCH PROVIDER SET)' : `SEARCH RESULTS VIA ${session.discovery.provider.toUpperCase()} (CANDIDATES)` }}</div>
          <div class="text-hits-list">
            <div v-for="(hit, idx) in session.textHits" :key="idx" class="text-hit-card">
              <div class="th-top">
                <span class="th-title mono">{{ hit.title || '(untitled)' }}</span>
                <span class="th-tier mono">Tier {{ hit.tier }}</span>
              </div>
              <a :href="hit.source_url" target="_blank" rel="noopener noreferrer" class="th-url mono">{{ hit.source_url }}</a>
              <p class="th-snippet">{{ hit.excerpt }}</p>
              <p v-if="hit.ai_why" class="th-snippet mono">AI OPINION, NOT PROOF: {{ hit.ai_why }}</p>
            </div>
          </div>
        </div>
        <p v-else-if="allBlocked" class="err-line mono">Every query was blocked by the firewall, so nothing was searched. Search organisations, not people.</p>
        <p v-else-if="session.discovery && !session.scoutError" class="empty-state mono">The search returned no results.</p>

        <div class="next-action-row">
          <button class="action-btn mono" @click="emit('next-step')">PROCEED TO STEP 5: REVIEW & LEDGER →</button>
        </div>
      </div>
    </div>

    <div class="step-card">
      <div class="card-header">
        <div class="step-meta">
          <span class="step-badge mono">PDQ</span>
          <span class="step-title">REFERENCE IMAGES</span>
        </div>
        <div class="step-status-tag mono" :class="session.references ? 'completed' : 'pending'">{{ session.references }} ADDED</div>
      </div>
      <div class="card-content">
        <p class="step-desc">Images you are authorised to match. Only PDQ hashes are kept; the image is discarded.</p>
        <div class="input-block">
          <input type="file" accept="image/png, image/jpeg" class="file-input mono" @change="(e) => (refFile = e.target.files?.[0])" />
        </div>
        <div class="consent-block">
          <label class="consent-label"><input type="checkbox" v-model="refAuthorised" /> <span>I am authorised to use this image for matching.</span></label>
        </div>
        <div class="enrol-action">
          <button class="enrol-btn mono" :disabled="!refFile || !refAuthorised" @click="addReference">ADD REFERENCE</button>
        </div>
        <p v-if="refError" class="err-line mono">{{ refError }}</p>
      </div>
    </div>

    <div class="step-card">
      <div class="card-header">
        <div class="step-meta">
          <span class="step-badge mono">FACE</span>
          <span class="step-title">CONSENTED LIKENESS ENROLMENT GATE</span>
        </div>
        <div class="step-status-tag mono" :class="session.enrolled ? 'completed' : 'pending'">{{ session.enrolled ? 'ENROLLED' : 'OPTIONAL' }}</div>
      </div>

      <div class="card-content">
        <div class="privacy-notice">
          <span class="notice-icon">🔒</span>
          <div class="notice-text">
            <strong>PRIVACY & BIOMETRIC PROTECTION:</strong>
            Enrol only your own likeness. A face vector is sensitive personal data. It is held in memory only and the images are discarded.
          </div>
        </div>

        <div class="enrol-container">
          <div class="enrol-inputs">
            <div class="input-block">
              <label class="block-label mono">1. REFERENCE PORTRAIT / ID PHOTO</label>
              <input type="file" accept="image/png, image/jpeg" class="file-input mono" @change="(e) => (photo = e.target.files?.[0])" />
            </div>

            <div class="input-block">
              <label class="block-label mono">2. CAMERA SELFIE (MUST MATCH THE PHOTO)</label>
              <div class="selfie-mock-box">
                <video v-show="cameraOn" ref="video" class="selfie-video" autoplay playsinline muted></video>
                <div v-if="!cameraOn" class="selfie-placeholder mono">
                  <span class="cam-icon">📷</span>
                  <span>{{ selfie ? 'Selfie captured' : 'Camera off' }}</span>
                </div>
                <button type="button" class="capture-btn mono" @click="cameraOn ? capture() : openCamera()">
                  {{ cameraOn ? 'CAPTURE' : selfie ? 'RETAKE SELFIE' : 'OPEN CAMERA' }}
                </button>
              </div>
            </div>

            <div class="consent-block">
              <label class="consent-label">
                <input type="checkbox" v-model="consentChecked" />
                <span>I affirm I am the individual in these images and consent to on-device likeness matching strictly for leak discovery.</span>
              </label>
            </div>

            <div class="enrol-action">
              <button class="enrol-btn mono" :disabled="!canEnrol" @click="performEnrol">GENERATE 128-BYTE VECTOR & ENROL</button>
            </div>
            <p v-if="enrolError" class="err-line mono">{{ enrolError }}</p>
          </div>

          <div class="enrol-result-box">
            <div class="box-header mono">ENROLMENT</div>
            <div v-if="session.enrolled" class="victim-tag-display">
              <span class="victim-icon">👤</span>
              <span class="victim-tag-note">Vector held in memory. Images discarded. Crawls will also compare faces.</span>
              <button class="enrol-btn mono" @click="unenrol">REMOVE ENROLMENT</button>
            </div>
            <div v-else class="victim-tag-empty mono">// No face vector in memory.</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { session } from '../../store/session'
import { runScout } from '../../api/case'
import { api } from '../../api/index'

const emit = defineEmits(['next-step'])
const entityTypes = ['IN_AADHAAR', 'IN_PAN', 'CREDIT_CARD', 'EMAIL_ADDRESS', 'MOBILE_IN', 'IN_BANK_ACCOUNT']
const form = reactive({ org: '', domain: '', types: ['IN_AADHAAR', 'IN_PAN'], crawl: false, urls: '' })

const refFile = ref(null)
const refAuthorised = ref(false)
const refError = ref('')
const photo = ref(null)
const selfie = ref(null)
const consentChecked = ref(false)
const enrolError = ref('')
const video = ref(null)
const cameraOn = ref(false)
let camera = null

const canEnrol = computed(() => photo.value && selfie.value && consentChecked.value)

const crawlGap = computed(() => {
  const c = session.discovery?.crawl
  if (!c) return ''
  const gaps = []
  if (c.images_failed) gaps.push(`${c.images_failed} image(s) could not be fetched`)
  if (c.blocked) gaps.push(`${c.blocked} page(s) were blocked`)
  if (c.robots_denied) gaps.push(`${c.robots_denied} page(s) disallowed by robots.txt`)
  if (c.timed_out || c.stopped === 'timeout') gaps.push('the crawl hit its time limit')
  return gaps.length ? `Not fully checked: ${gaps.join(', ')}. No match means none found in what was read, not that the image is absent.` : ''
})
const agentTotal = computed(() => Object.keys(session.siteAgents).length)
const agentsRunning = computed(() => Object.values(session.siteAgents).filter((st) => st === 'spawned').length)
const allBlocked = computed(() => session.queries.length > 0 && session.queries.every((q) => !q.allowed))
const aiLine = computed(() => {
  const ai = session.discovery?.ai
  if (!ai) return ''
  return ai.used ? `AI read ${ai.read} results in ${ai.calls} call(s), ${ai.tokens} tokens, ${ai.leads} lead(s)` : 'AI triage off: connect a provider in Step 2'
})
const start = () => runScout({ org: form.org.trim(), domain: form.domain.trim().toLowerCase(), entity_types: form.types, crawl: form.crawl, extra_urls: form.crawl ? form.urls.split('\n').map((u) => u.trim()).filter(Boolean) : [] })

const addReference = async () => {
  refError.value = ''
  try {
    await api.addReference(refFile.value, refFile.value.name.slice(0, 60))
    session.references = (await api.references()).references.length
    refFile.value = null
    refAuthorised.value = false
  } catch (e) {
    refError.value = e.message
  }
}

const stopCamera = () => {
  camera?.getTracks().forEach((t) => t.stop())
  camera = null
  cameraOn.value = false
}

const openCamera = async () => {
  enrolError.value = ''
  try {
    camera = await navigator.mediaDevices.getUserMedia({ video: true })
    cameraOn.value = true
    video.value.srcObject = camera
  } catch (e) {
    enrolError.value = `Camera unavailable: ${e.message}`
  }
}

const capture = () => {
  const canvas = document.createElement('canvas')
  canvas.width = video.value.videoWidth
  canvas.height = video.value.videoHeight
  canvas.getContext('2d').drawImage(video.value, 0, 0)
  canvas.toBlob((blob) => { selfie.value = blob; stopCamera() }, 'image/jpeg', 0.92)
}

const performEnrol = async () => {
  enrolError.value = ''
  try {
    await api.enroll(photo.value, selfie.value)
    session.enrolled = true
    photo.value = selfie.value = null
  } catch (e) {
    enrolError.value = e.message
  }
}

const unenrol = async () => {
  await api.unenroll()
  session.enrolled = false
}

onMounted(async () => {
  session.enrolled = (await api.config()).enrolled > 0 // the server may hold one from before a refresh
  if (!session.registry.length) session.registry = await api.registry()
  session.references = (await api.references()).references.length
})
onUnmounted(stopCamera)
</script>

<style scoped>
.step-view {
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
  font-size: 11px;
  font-weight: 800;
  color: var(--blue);
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 2px 6px;
}

.step-title {
  font-size: 12.5px;
  font-weight: 700;
  letter-spacing: 0.5px;
  color: var(--ink);
}

.step-status-tag {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 8px;
  border: 1px solid var(--line);
}

.step-status-tag.completed {
  background: #2E9E6B;
  color: #FFF;
  border-color: #2E9E6B;
}

.step-status-tag.pending {
  background: var(--fascia);
  color: #7E848A;
}

.card-content {
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.api-note {
  font-size: 11px;
  color: var(--blue);
  background: var(--fascia);
  padding: 3px 8px;
  border: 1px solid var(--line);
  align-self: flex-start;
}

.privacy-notice {
  background: rgba(74, 97, 120, 0.12);
  border: 1px solid var(--blue);
  padding: 10px 14px;
  display: flex;
  gap: 10px;
  align-items: flex-start;
}

.notice-icon {
  font-size: 18px;
}

.notice-text {
  font-size: 12px;
  color: var(--ink);
  line-height: 1.4;
}

.enrol-container {
  display: grid;
  grid-template-columns: 3fr 2fr;
  gap: 16px;
}

.enrol-inputs {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.input-block {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.block-label {
  font-size: 10px;
  font-weight: 700;
  color: #7E848A;
  letter-spacing: 0.5px;
}

.file-input {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 6px;
  font-size: 11px;
  color: var(--ink);
}

.input-hint {
  font-size: 10px;
  color: #2E9E6B;
}

.selfie-mock-box {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 10px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.selfie-placeholder {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 11.5px;
  color: var(--ink);
}

.capture-btn {
  background: var(--panel);
  border: 1px solid var(--line);
  color: var(--ink);
  font-size: 10px;
  font-weight: 700;
  padding: 5px 10px;
  cursor: pointer;
}

.capture-btn:hover {
  border-color: var(--ink);
}

.consent-block {
  padding: 6px 0;
}

.consent-label {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: 11.5px;
  color: var(--ink);
  line-height: 1.35;
  cursor: pointer;
}

.consent-label input {
  margin-top: 3px;
}

.enrol-btn {
  background: var(--ink);
  color: var(--panel);
  border: 1px solid var(--ink);
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.5px;
  padding: 8px 16px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.enrol-btn:hover:not(:disabled) {
  background: var(--blue);
  border-color: var(--blue);
  color: #FFF;
}

.enrol-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.enrol-result-box {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 14px;
  display: flex;
  flex-direction: column;
}

.box-header {
  font-size: 10px;
  font-weight: 800;
  color: #7E848A;
  margin-bottom: 8px;
}

.victim-tag-display {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.victim-icon {
  font-size: 28px;
}

.victim-hash {
  font-size: 18px;
  font-weight: 800;
  color: #E0245E;
}

.victim-tag-note {
  font-size: 11px;
  color: var(--ink);
}

.specs-grid {
  font-size: 10px;
  color: #7E848A;
  display: flex;
  flex-direction: column;
  gap: 2px;
  margin-top: 6px;
  border-top: 1px solid var(--line);
  padding-top: 6px;
}

.victim-tag-empty {
  font-size: 11px;
  color: #7E848A;
  font-style: italic;
  padding: 20px 0;
}

.run-scout-btn {
  background: var(--red);
  color: #FFF;
  border: 1px solid var(--red);
  font-size: 11px;
  font-weight: 700;
  padding: 4px 12px;
  cursor: pointer;
}

.run-scout-btn:hover:not(:disabled) {
  background: #A02620;
}

.honest-limits-line {
  background: var(--fascia);
  border-left: 3px solid var(--red);
  padding: 8px 12px;
  font-size: 11.5px;
  font-weight: 700;
  color: var(--ink);
}

.counters-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
}

.counter-box {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 10px;
  text-align: center;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.c-num {
  font-size: 22px;
  font-weight: 800;
  color: var(--ink);
}

.c-label {
  font-size: 9.5px;
  font-weight: 700;
  color: #7E848A;
}

.match-count { color: var(--red); }
.blocked-count { color: #E9724C; }

/* Firewall */
.firewall-monitor {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.monitor-header {
  display: flex;
  justify-content: space-between;
  font-size: 10.5px;
  font-weight: 700;
  color: var(--ink);
}

.rule-hint {
  color: #7E848A;
  font-weight: normal;
}

.queries-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.query-item {
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 8px 10px;
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 11px;
}

.q-badge {
  font-size: 9.5px;
  font-weight: 700;
  padding: 2px 6px;
}

.badge-allow {
  background: rgba(46, 158, 107, 0.15);
  color: #2E9E6B;
  border: 1px solid #2E9E6B;
}

.badge-block {
  background: rgba(200, 49, 43, 0.15);
  color: var(--red);
  border: 1px solid var(--red);
}

.q-text {
  font-weight: 700;
  color: var(--ink);
  flex: 1;
}

.q-reason {
  font-size: 10px;
  color: #7E848A;
}

/* Registry Table */
.registry-section {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.section-title {
  font-size: 10.5px;
  font-weight: 800;
  color: var(--ink);
  letter-spacing: 0.5px;
}

.registry-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 11.5px;
  background: var(--fascia);
  border: 1px solid var(--line);
}

.registry-table th {
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  padding: 7px 10px;
  font-size: 10px;
  text-align: left;
  color: #7E848A;
}

.registry-table td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--line);
}

.status-pill {
  font-size: 9.5px;
  font-weight: 700;
  padding: 2px 6px;
}

.status-pill.active {
  background: rgba(74, 97, 120, 0.15);
  color: var(--blue);
  border: 1px solid var(--blue);
}

/* Text Hits */
.text-hits-box {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.text-hits-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.text-hit-card {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.th-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.th-title {
  font-size: 12px;
  font-weight: 700;
  color: var(--ink);
}

.th-tier {
  font-size: 9.5px;
  font-weight: 700;
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 2px 6px;
  color: var(--blue);
}

.th-url {
  font-size: 11px;
  color: var(--blue);
  text-decoration: none;
  word-break: break-all;
}

.th-url:hover {
  text-decoration: underline;
}

.th-snippet {
  font-size: 11.5px;
  color: #6C727A;
}

.next-action-row {
  display: flex;
  justify-content: flex-end;
  margin-top: 6px;
}

.action-btn {
  background: var(--ink);
  color: var(--panel);
  border: 1px solid var(--ink);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.5px;
  padding: 8px 18px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.action-btn:hover {
  background: var(--blue);
  border-color: var(--blue);
  color: #FFF;
}
</style>
