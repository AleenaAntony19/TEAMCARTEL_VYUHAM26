<template>
  <div class="home-view">
    <header class="home-header">
      <div class="brand">
        <span class="brand-icon">🛡️</span>
        <span class="brand-text mono">SHIELD·SCOUT</span>
      </div>
      <span class="mode-badge mono">{{ modeLabel }}</span>
    </header>

    <main class="home-main">
      <div class="intake-card">
        <div class="intake-header">
          <span class="intake-title mono">NEW INVESTIGATION / REDACTION CASE</span>
          <span class="intake-subtitle">PII detection and redaction on this machine, plus a consented leak scout.</span>
        </div>

        <div class="intake-body">
          <div
            class="dropzone"
            :class="{ 'is-dragover': isDragOver, 'has-file': selectedFile }"
            @dragover.prevent="isDragOver = true"
            @dragleave.prevent="isDragOver = false"
            @drop.prevent="onFileDrop"
            @click="fileInputRef?.click()"
          >
            <input type="file" ref="fileInputRef" class="hidden-input" accept=".pdf,.docx,.xlsx,.png,.jpg,.jpeg,.txt,.csv,.json" @change="onFileSelected" />
            <div class="dropzone-content">
              <span class="drop-icon">📁</span>
              <p class="drop-primary mono">{{ selectedFile ? selectedFile.name : 'DRAG & DROP CASE DOCUMENT HERE' }}</p>
              <p class="drop-secondary">
                {{ selectedFile ? `${(selectedFile.size / 1024).toFixed(1)} KB ready for inspection` : 'Supports PDF, DOCX, XLSX, PNG/JPEG images, TXT, CSV and JSON' }}
              </p>
            </div>
          </div>

          <label class="mono url-box">OR PASTE TEXT
            <textarea class="field mono" rows="4" v-model="pastedText"></textarea>
          </label>
          <p v-if="selectedFile && hasText" class="drop-secondary">Both given: the file is used and the pasted text is ignored.</p>

          <div class="consent-box">
            <label class="consent-checkbox-label">
              <input type="checkbox" v-model="consentAffirmed" />
              <span class="consent-text">
                I affirm legal authorization under applicable data protection statutes (including DPDP Act 2023) to process this case file.
              </span>
            </label>
          </div>

          <div class="consent-box mode-box">
            <span class="mono mode-title">HOW SHOULD THIS RUN?</span>
            <label class="consent-checkbox-label">
              <input type="radio" value="rules" v-model="ai.mode" />
              <span class="consent-text"><strong>Rules only:</strong> fixed detectors, no key needed. Nothing goes to an AI. The same file always gives the same result.</span>
            </label>
            <label class="consent-checkbox-label" :class="{ muted: config.value?.local_only }">
              <input type="radio" value="ai" v-model="ai.mode" :disabled="config.value?.local_only" />
              <span class="consent-text"><strong>Rules + AI:</strong> adds the agent swarm and search triage with your own key. Results can vary, and AI can be wrong. Rules still run.</span>
            </label>
            <div v-if="ai.mode === 'ai'" class="form-row">
              <label class="mono">PROVIDER
                <select class="field mono" v-model="ai.provider">
                  <option value="anthropic">Anthropic Claude</option>
                  <option value="groq">Groq</option>
                </select>
              </label>
              <label class="mono grow">YOUR API KEY (kept in this tab only)
                <input class="field mono" type="password" autocomplete="off" v-model.trim="ai.key" :placeholder="serverKey ? 'optional: this server has a key' : 'paste key'" />
              </label>
              <button class="demo-btn mono" type="button" :disabled="!ai.key && !serverKey" @click="testKey">TEST KEY</button>
            </div>
            <p v-if="keyNote" class="mono key-note">{{ keyNote }}</p>
          </div>

          <div class="actions-row">
            <button class="start-btn mono" :disabled="!canStart || starting" @click="startNewCase">
              🚀 {{ starting ? 'UPLOADING…' : 'INGEST & START CASE WORKSPACE' }}
            </button>
            <button class="demo-btn mono" @click="router.push('/case/scout')">LEAK SCOUT ONLY (NO DOCUMENT)</button>
          </div>
          <p v-if="error" class="err-line mono">{{ error }}</p>
        </div>

        <div class="intake-footer mono">
          <span>Data leaving this machine: {{ egress }}</span>
        </div>
      </div>
    </main>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { config } from '../store/session'
import { createCase, refreshConfig } from '../api/case'
import { ai, api } from '../api/index'

const router = useRouter()
const fileInputRef = ref(null)
const isDragOver = ref(false)
const selectedFile = ref(null)
const pastedText = ref('')
const consentAffirmed = ref(false)
const starting = ref(false)
const error = ref('')

const hasText = computed(() => pastedText.value.trim().length > 0)
const canStart = computed(() => (selectedFile.value || hasText.value) && consentAffirmed.value)
const keyNote = ref('')
const serverKey = computed(() => !!config.value?.llm.key_set)
const modeLabel = computed(() => {
  const c = config.value
  if (!c) return 'CONNECTING…'
  return c.local_only ? 'LOCAL-ONLY MODE' : `${ai.mode === 'ai' ? 'RULES + AI' : 'RULES ONLY'} · SEARCH: ${c.search_provider.toUpperCase()}`
})

const testKey = async () => {
  keyNote.value = 'Testing…'
  try {
    const r = await api.testLlm()
    keyNote.value = r.ok ? `Connected to ${r.model} (${r.latency_ms} ms).` : `Failed: ${r.error}`
  } catch (e) {
    keyNote.value = e.message
  }
}
const egress = computed(() => config.value?.data_leaving_machine.join(' · ') || 'loading…')

const onFileSelected = (e) => { selectedFile.value = e.target.files?.[0] || selectedFile.value }
const onFileDrop = (e) => {
  isDragOver.value = false
  selectedFile.value = e.dataTransfer.files?.[0] || selectedFile.value
}

const startNewCase = async () => {
  starting.value = true
  error.value = ''
  try {
    router.push(`/case/${await createCase(selectedFile.value, pastedText.value)}`)
  } catch (e) {
    error.value = e.message
  } finally {
    starting.value = false
  }
}

onMounted(refreshConfig)
</script>

<style scoped>
.home-view {
  width: 100vw;
  height: 100vh;
  display: flex;
  flex-direction: column;
  background-color: var(--fascia);
  overflow: hidden;
}

.home-header {
  height: 52px;
  background-color: var(--panel);
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
}

.brand-icon {
  font-size: 20px;
}

.brand-text {
  font-size: 18px;
  font-weight: 800;
  letter-spacing: 1.5px;
  color: var(--ink);
}

.mode-badge {
  font-size: 10.5px;
  font-weight: 700;
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 3px 8px;
  color: var(--blue);
}

.home-main {
  flex: 1;
  min-height: 0;
  display: flex;
  justify-content: center;
  padding: 24px;
  overflow-y: auto;
}

.intake-card {
  width: 100%;
  max-width: 680px;
  margin: auto; /* centres, but unlike align-items keeps the top reachable on short screens */
  background: var(--panel);
  border: 1px solid var(--ink);
  display: flex;
  flex-direction: column;
}

.intake-header {
  padding: 18px 24px;
  background: var(--fascia);
  border-bottom: 1px solid var(--line);
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.intake-title {
  font-size: 14px;
  font-weight: 800;
  letter-spacing: 0.8px;
  color: var(--ink);
}

.intake-subtitle {
  font-size: 12.5px;
  color: #6C727A;
}

.intake-body {
  padding: 24px;
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.dropzone {
  border: 2px dashed var(--line);
  background: var(--fascia);
  padding: 40px 20px;
  text-align: center;
  cursor: pointer;
  transition: all 0.15s ease;
}

.dropzone:hover, .dropzone.is-dragover {
  border-color: var(--ink);
  background: var(--panel);
}

.dropzone.has-file {
  border-color: #2E9E6B;
  background: rgba(46, 158, 107, 0.05);
}

.hidden-input {
  display: none;
}

.dropzone-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

.drop-icon {
  font-size: 32px;
}

.drop-primary {
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.5px;
  color: var(--ink);
}

.drop-secondary {
  font-size: 12px;
  color: #7E848A;
}

.consent-box {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 12px;
}

.consent-checkbox-label {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  cursor: pointer;
}

.consent-checkbox-label input {
  margin-top: 3px;
}

.consent-text {
  font-size: 12px;
  color: var(--ink);
  line-height: 1.4;
}

.actions-row {
  display: flex;
  gap: 12px;
}

.start-btn {
  flex: 1;
  background: var(--ink);
  color: var(--panel);
  border: 1px solid var(--ink);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0.5px;
  padding: 10px 16px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.start-btn:hover:not(:disabled) {
  background: var(--blue);
  border-color: var(--blue);
  color: #FFF;
}

.start-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.demo-btn {
  background: var(--fascia);
  border: 1px solid var(--line);
  color: var(--ink);
  font-size: 11px;
  font-weight: 700;
  padding: 10px 16px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.demo-btn:hover {
  border-color: var(--ink);
}

.intake-footer {
  padding: 10px 24px;
  background: var(--fascia);
  border-top: 1px solid var(--line);
  font-size: 10px;
  color: #7E848A;
}
.mode-box { display: flex; flex-direction: column; gap: 10px; }
.mode-title { font-size: 11px; font-weight: 600; }
.key-note { font-size: 11px; }
.mode-box .form-row { align-items: flex-end; margin-bottom: 0; }
</style>
