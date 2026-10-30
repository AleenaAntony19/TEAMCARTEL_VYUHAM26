<template>
  <div class="step-view">
    <div class="step-card">
      <div class="card-header">
        <div class="step-meta">
          <span class="step-badge mono">03</span>
          <span class="step-title">RED TEAM ADVERSARIAL SELF-VERIFICATION</span>
        </div>
        <div class="step-status-tag mono" :class="!r ? 'pending' : isClean ? 'completed' : 'failed'">
          {{ !r ? 'NOT RUN' : isClean ? 'VERIFIED CLEAN ✅' : 'ATTACK FAILURE ❌' }}
        </div>
      </div>

      <div class="card-content">
        <p class="step-desc">
          Before a sanitized file is released, the red team tries to recover every redacted value from it. Any hit withholds the download.
        </p>

        <p v-if="!r" class="empty-state mono">No redaction yet. Choose findings in Step 1 and redact; the attacks run on the real output.</p>

        <template v-else>
          <div class="verification-banner" :class="isClean ? 'clean-banner' : 'fail-banner'">
            <div class="banner-icon">{{ isClean ? '🛡️' : '⚠️' }}</div>
            <div class="banner-text">
              <span class="banner-title mono">{{ isClean ? 'OBJECT-LEVEL SANITIZATION VERIFIED: CLEAN' : 'PRIVACY BREACH DETECTED: VALUES RECOVERED' }}</span>
              <span class="banner-subtitle">{{ r.note }}{{ r.retried_aggressive ? ' The first pass failed, so an aggressive retry ran.' : '' }}</span>
            </div>
          </div>

          <div class="table-container">
            <table class="attack-table">
              <thead>
                <tr>
                  <th class="mono">ATTACK VECTOR</th>
                  <th class="mono">EVIDENCE RECORD</th>
                  <th class="mono status-col">RESULT</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="atk in session.attacks" :key="atk.name" :class="{ 'attack-failed': !atk.passed }">
                  <td class="mono font-bold attack-name">{{ atk.name.toUpperCase() }}</td>
                  <td class="mono evidence-cell">
                    <span v-if="atk.passed" class="no-evidence">0 hits</span>
                    <span v-else class="leak-evidence">{{ atk.evidence?.join(', ') || 'values recovered' }}</span>
                  </td>
                  <td class="status-col">
                    <span class="status-badge mono" :class="atk.passed ? 'pass' : 'fail'">{{ atk.passed ? 'PASS ✅' : 'FAIL ❌' }}</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="hashes-box">
            <div class="box-header mono">CRYPTOGRAPHIC ARTIFACT INTEGRITY</div>
            <div class="hash-row">
              <span class="hash-label mono">OUTPUT SHA-256:</span>
              <span class="hash-val mono highlight-hash">{{ r.sha256 }}</span>
            </div>
            <div class="hash-row">
              <span class="hash-label mono">LEDGER HEAD:</span>
              <span class="hash-val mono">{{ r.ledger_head }}</span>
            </div>
          </div>
        </template>

        <div class="next-action-row">
          <button class="action-btn mono" @click="emit('next-step')">PROCEED TO STEP 4: LEAK SCOUT →</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { session } from '../../store/session'

const emit = defineEmits(['next-step'])
const r = computed(() => session.redaction)
const isClean = computed(() => r.value?.status === 'CLEAN')
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

.step-status-tag.failed {
  background: var(--red);
  color: #FFF;
  border-color: var(--red);
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

/* Big Banner */
.verification-banner {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 14px 18px;
  border: 1px solid;
}

.verification-banner.clean-banner {
  background: rgba(46, 158, 107, 0.1);
  border-color: #2E9E6B;
}

.verification-banner.fail-banner {
  background: rgba(200, 49, 43, 0.1);
  border-color: var(--red);
}

.banner-icon {
  font-size: 24px;
}

.banner-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.banner-title {
  font-size: 13px;
  font-weight: 800;
  letter-spacing: 0.5px;
  color: var(--ink);
}

.banner-subtitle {
  font-size: 12px;
  color: #6C727A;
}

/* Table */
.table-container {
  overflow-x: auto;
  border: 1px solid var(--line);
}

.attack-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: 12px;
  background: var(--fascia);
}

.attack-table th {
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  padding: 8px 12px;
  font-size: 10.5px;
  color: #7E848A;
  font-weight: 700;
}

.attack-table td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--line);
  vertical-align: middle;
}

.attack-table tr:last-child td {
  border-bottom: none;
}

.attack-name {
  color: var(--ink);
  font-size: 11px;
}

.mechanism-desc {
  font-size: 11.5px;
  color: var(--ink);
  line-height: 1.35;
}

.evidence-cell {
  font-size: 10.5px;
}

.no-evidence {
  color: #2E9E6B;
}

.leak-evidence {
  color: var(--red);
  font-weight: 700;
}

.status-col {
  text-align: right;
  width: 100px;
}

.status-badge {
  font-size: 10px;
  font-weight: 800;
  padding: 3px 8px;
  display: inline-block;
  border: 1px solid;
}

.status-badge.pass {
  background: #2E9E6B;
  color: #FFF;
  border-color: #2E9E6B;
}

.status-badge.fail {
  background: var(--red);
  color: #FFF;
  border-color: var(--red);
}

/* Hashes Box */
.hashes-box {
  background: var(--console);
  border: 1px solid var(--line);
  padding: 12px 14px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.box-header {
  font-size: 10px;
  font-weight: 800;
  color: #8C9298;
  letter-spacing: 0.5px;
  margin-bottom: 2px;
}

.hash-row {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 11px;
}

.hash-label {
  color: #6C727A;
  font-weight: 600;
  min-width: 115px;
}

.hash-val {
  color: var(--console-ink);
  word-break: break-all;
}

.highlight-hash {
  color: #4CAF50;
  font-weight: 700;
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
