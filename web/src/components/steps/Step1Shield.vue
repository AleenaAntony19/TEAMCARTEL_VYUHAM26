<template>
  <div class="step-view">
    <div class="step-card">
      <div class="card-header">
        <div class="step-meta">
          <span class="step-badge mono">01</span>
          <span class="step-title">DOCUMENT INTAKE & OBJECT-LEVEL PROFILING</span>
        </div>
        <div class="step-status-tag mono" :class="session.job?.status === 'ready' ? 'completed' : 'pending'">
          {{ statusLabel }}
        </div>
      </div>

      <div class="card-content">
        <p class="step-desc">
          Shield parses every layer of the file (visible text, form fields, metadata, comments, embedded parts) and checks each candidate with validators such as Verhoeff and Luhn.
        </p>

        <p v-if="!session.job" class="empty-state mono">No document in this case. Start one from the home screen, or use Step 4 for a leak scout.</p>

        <div v-if="session.job" class="profile-grid">
          <div class="stat-card">
            <span class="stat-label mono">FORMAT</span>
            <span class="stat-value mono">{{ session.job.input_type.toUpperCase() }}</span>
          </div>
          <div class="stat-card">
            <span class="stat-label mono">SEVERITY</span>
            <span class="stat-value mono" :class="'sev-' + session.severity.toLowerCase()">{{ session.severity }} ({{ session.severityScore }})</span>
          </div>
          <div class="stat-card">
            <span class="stat-label mono">FINDINGS</span>
            <span class="stat-value mono">{{ session.job.findings.length }}</span>
          </div>
          <div class="stat-card">
            <span class="stat-label mono">ACTIVE LAYERS</span>
            <span class="stat-value layers-count mono">{{ (session.job.summary?.layers || []).join(', ') || 'none' }}</span>
          </div>
        </div>

        <div v-if="session.job?.findings.length" class="detected-box">
          <div class="box-title mono">DETECTED SENSITIVE DATA: CHOOSE WHAT TO REDACT</div>
          <table class="data-table">
            <thead>
              <tr><th class="mono">REDACT</th><th class="mono">TYPE</th><th class="mono">VALUE (MASKED)</th><th class="mono">LAYER</th><th class="mono">SEVERITY</th><th class="mono">ACTION</th></tr>
            </thead>
            <tbody>
              <tr v-for="f in session.job.findings" :key="f.id">
                <td><input type="checkbox" :aria-label="'Redact ' + f.type" :checked="!!session.selection[f.id]" :disabled="!f.actions.length" @change="toggle(f)" /></td>
                <td class="mono">{{ f.type }}</td>
                <td class="mono">{{ f.masked }}</td>
                <td class="mono">{{ f.layer }}</td>
                <td class="mono" :class="'sev-' + f.severity">{{ f.severity.toUpperCase() }}</td>
                <td>
                  <select v-if="session.selection[f.id]" class="field mono" :aria-label="'Action for ' + f.type" v-model="session.selection[f.id]">
                    <option v-for="a in f.actions" :key="a" :value="a">{{ a }}</option>
                  </select>
                </td>
              </tr>
            </tbody>
          </table>
          <div class="next-action-row">
            <button class="action-btn mono" :disabled="session.redacting || session.swarmRunning || !selectedCount" @click="redactNow">
              {{ session.redacting ? 'REDACTING…' : `REDACT ${selectedCount} VALUE(S) & VERIFY →` }}
            </button>
          </div>
        </div>
        <p v-else-if="session.job?.status === 'ready'" class="empty-state mono">Nothing sensitive was found in this file.</p>
      </div>
    </div>

    <div v-if="session.job?.findings.length" class="step-card">
      <div class="card-header">
        <div class="step-meta">
          <span class="step-badge mono">COMPARISON</span>
          <span class="step-title">COPY-PASTE TEST: ORIGINAL VS SHIELD SANITIZED</span>
        </div>
        <div class="step-status-tag mono" :class="session.redaction ? 'completed' : 'pending'">{{ session.redaction ? session.redaction.status : 'NOT REDACTED YET' }}</div>
      </div>

      <div class="card-content">
        <p class="step-desc">
          The black box in common PDF viewers is <strong>NOT</strong> redaction: the bytes stay in the file. Left is where those values sit now (masked here). Right is the text that can still be extracted from the sanitized output.
        </p>

        <div class="comparison-grid">
          <div class="compare-pane naive-pane">
            <div class="pane-header">
              <span class="pane-title mono">ORIGINAL FILE (values masked for display)</span>
              <span class="leak-badge mono">{{ session.job.findings.length }} EXPOSED ❌</span>
            </div>
            <div class="code-box mono">
              <div v-for="f in session.job.findings" :key="f.id" class="code-line leak-line">{{ f.evidence || f.masked }}</div>
            </div>
          </div>

          <div class="compare-pane clean-pane">
            <div class="pane-header">
              <span class="pane-title mono">SHIELD SANITIZED (extracted from output, masked)</span>
              <span v-if="session.redaction" class="clean-badge mono">{{ session.redaction.status }}</span>
            </div>
            <div class="code-box mono">
              <div v-if="session.redaction" class="code-line clean-line preserve">{{ session.redaction.preview_text || '(no extractable text)' }}</div>
              <div v-else class="code-line">Redact above to see the real output here.</div>
            </div>
            <div v-if="session.redaction" class="pane-footer mono">SHA-256 {{ session.redaction.sha256 }}</div>
          </div>
        </div>

        <div class="next-action-row">
          <button class="action-btn mono" @click="emit('next-step')">PROCEED TO STEP 2: AGENT SWARM →</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { session } from '../../store/session'
import { redactNow } from '../../api/case'

const emit = defineEmits(['next-step'])

const selectedCount = computed(() => Object.keys(session.selection).length)
const statusLabel = computed(() => (session.job ? session.job.status.toUpperCase() : 'NO DOCUMENT'))

const toggle = (f) => {
  if (session.selection[f.id]) delete session.selection[f.id]
  else session.selection[f.id] = f.actions.includes('token') ? 'token' : f.actions[0]
}
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

.step-desc {
  font-size: 12.5px;
  line-height: 1.45;
  color: var(--ink);
}

.profile-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  margin-top: 4px;
}

.stat-card {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.stat-label {
  font-size: 10px;
  font-weight: 700;
  color: #7E848A;
}

.stat-value {
  font-size: 13px;
  font-weight: 700;
  color: var(--ink);
}

.sev-critical { color: var(--red); }
.sev-high { color: #E9724C; }
.sev-medium { color: #D9622B; }
.sev-low { color: #2E9E6B; }

.tags-row {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.domain-tag {
  font-size: 9px;
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 1px 4px;
}

.detected-box {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 12px;
}

.box-title {
  font-size: 10px;
  font-weight: 800;
  color: var(--ink);
  letter-spacing: 0.5px;
  margin-bottom: 8px;
}

.entities-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.entity-pill {
  background: var(--panel);
  border: 1px solid var(--line);
  display: flex;
  align-items: center;
  font-size: 11px;
}

.ep-type {
  padding: 4px 8px;
  font-weight: 700;
  color: var(--ink);
}

.ep-count {
  background: var(--red);
  color: #FFF;
  padding: 4px 8px;
  font-weight: 800;
}

/* Comparison */
.comparison-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.compare-pane {
  border: 1px solid var(--line);
  background: var(--fascia);
  display: flex;
  flex-direction: column;
}

.pane-header {
  height: 32px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 10px;
}

.pane-title {
  font-size: 10px;
  font-weight: 700;
  color: var(--ink);
}

.leak-badge {
  background: var(--red);
  color: #FFF;
  font-size: 9px;
  font-weight: 700;
  padding: 2px 6px;
}

.clean-badge {
  background: #2E9E6B;
  color: #FFF;
  font-size: 9px;
  font-weight: 700;
  padding: 2px 6px;
}

.code-box {
  padding: 12px;
  font-size: 11px;
  line-height: 1.5;
  background: var(--console);
  color: var(--console-ink);
  min-height: 160px;
  overflow-x: auto;
}

.leak-line {
  color: #FF6B6B;
  background: rgba(200, 49, 43, 0.2);
  padding: 0 4px;
}

.clean-line {
  color: #4CAF50;
  background: rgba(76, 175, 80, 0.15);
  padding: 0 4px;
}

.pane-footer {
  padding: 6px 10px;
  font-size: 10px;
  color: #7E848A;
  background: var(--panel);
  border-top: 1px solid var(--line);
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
