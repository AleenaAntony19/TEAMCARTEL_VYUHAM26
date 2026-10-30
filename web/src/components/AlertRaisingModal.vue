<template>
  <div v-if="session.showAlertModal" class="alert-modal-backdrop" @click.self="dismiss" @keydown.esc="dismiss">
    <div class="alert-modal-window" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div class="modal-top-bar">
        <div class="top-title-group">
          <span class="alert-pulse-dot"></span>
          <span id="modal-title" class="alert-headline mono">SECURITY ALERT // SENSITIVE DATA DETECTED</span>
        </div>
        <button class="modal-close-btn mono" @click="dismiss" title="Close Alert Window">✕</button>
      </div>

      <div class="modal-body">
        <div class="alert-hero-row">
          <div class="alert-icon-box">⚠️</div>
          <div class="alert-hero-meta">
            <div class="alert-main-title">{{ session.severity }} SENSITIVE EXPOSURE</div>
            <div class="alert-sub-source mono">TARGET: {{ session.filename || 'NO DOCUMENT' }}</div>
          </div>
          <div class="score-badge mono">
            <span class="score-num">{{ session.severityScore }}/100</span>
            <span class="score-lbl">SEVERITY RATING</span>
          </div>
        </div>

        <p class="alert-summary-text">
          This file holds the identifiers listed below. Values stay masked here. A black box drawn over them would not remove them;
          object-level redaction does, and the red team then tries to recover them.
        </p>

        <div class="breached-entities-section">
          <div class="section-label mono">FLAGGED SENSITIVE ARTIFACTS:</div>
          <div class="chips-container">
            <div v-for="(n, type) in session.detectedCounts" :key="type" class="entity-chip mono">
              <span class="chip-dot"></span>
              <span class="chip-name">{{ type }} × {{ n }}</span>
            </div>
          </div>
        </div>

        <div class="telemetry-grid mono">
          <div class="tele-item">
            <span class="t-label">LAYERS INSPECTED:</span>
            <span class="t-val">{{ (session.job?.summary?.layers || []).join(', ') || 'none' }}</span>
          </div>
          <div class="tele-item">
            <span class="t-label">REDACTION:</span>
            <span class="t-val" :class="session.redaction?.status === 'CLEAN' ? 'text-blue' : 'text-red'">{{ session.redaction?.status || 'NOT DONE' }}</span>
          </div>
        </div>
        <p v-if="error" class="err-line mono">{{ error }}</p>
      </div>

      <div class="modal-action-bar">
        <button class="action-btn lock-btn mono" :disabled="session.redacting || session.swarmRunning || !hasSelection" @click="handleRedact">
          🔒 {{ session.redacting ? 'REDACTING…' : 'REDACT SELECTED NOW' }}
        </button>
        <a class="action-btn cert-btn mono" :href="api.dossierUrl(session.jobId)" download>📄 DOWNLOAD CERT-In / NCRP DRAFTS</a>
        <button class="action-btn dismiss-btn mono" @click="dismiss">DISMISS ALERT</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { session } from '../store/session'
import { api } from '../api/index'
import { redactNow } from '../api/case'

const error = ref('')
const hasSelection = computed(() => Object.keys(session.selection).length > 0)
const dismiss = () => { session.showAlertModal = false }

const handleRedact = async () => {
  await redactNow()
  if (session.redaction) dismiss()
  else error.value = 'Redaction failed. See the console below.'
}
</script>

<style scoped>
.alert-modal-backdrop {
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background-color: rgba(23, 25, 27, 0.75);
  backdrop-filter: blur(3px);
  z-index: 9999;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.alert-modal-window {
  width: 100%;
  max-width: 680px;
  background: var(--panel);
  border: 2px solid var(--red);
  box-shadow: 0 0 30px rgba(200, 49, 43, 0.35);
  display: flex;
  flex-direction: column;
  animation: modalSlide 0.2s cubic-bezier(0.2, 0.8, 0.2, 1);
}

@keyframes modalSlide {
  from {
    transform: scale(0.96) translateY(-10px);
    opacity: 0;
  }
  to {
    transform: scale(1) translateY(0);
    opacity: 1;
  }
}

.modal-top-bar {
  height: 44px;
  background: var(--red);
  color: #FFFFFF;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
}

.top-title-group {
  display: flex;
  align-items: center;
  gap: 10px;
}

.alert-pulse-dot {
  width: 9px;
  height: 9px;
  background: #FFFFFF;
  animation: pulse 1s infinite alternate;
}

@keyframes pulse {
  from { opacity: 0.4; }
  to { opacity: 1; }
}

.alert-headline {
  font-size: 11.5px;
  font-weight: 800;
  letter-spacing: 1px;
}

.modal-close-btn {
  background: transparent;
  border: none;
  color: #FFFFFF;
  font-size: 16px;
  font-weight: 800;
  cursor: pointer;
  padding: 4px 8px;
}

.modal-close-btn:hover {
  background: rgba(0, 0, 0, 0.2);
}

.modal-body {
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 16px;
  background: var(--panel);
}

.alert-hero-row {
  display: flex;
  align-items: center;
  gap: 16px;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--line);
}

.alert-icon-box {
  font-size: 32px;
}

.alert-hero-meta {
  flex: 1;
}

.alert-main-title {
  font-size: 16px;
  font-weight: 800;
  color: var(--ink);
  letter-spacing: 0.5px;
}

.alert-sub-source {
  font-size: 11px;
  color: #7E848A;
  margin-top: 2px;
}

.score-badge {
  background: #C8312B18;
  border: 1px solid var(--red);
  padding: 6px 12px;
  display: flex;
  flex-direction: column;
  align-items: center;
}

.score-num {
  font-size: 18px;
  font-weight: 900;
  color: var(--red);
}

.score-lbl {
  font-size: 8.5px;
  font-weight: 800;
  color: var(--ink);
  letter-spacing: 0.5px;
}

.alert-summary-text {
  font-size: 12.5px;
  line-height: 1.45;
  color: var(--ink);
}

.breached-entities-section {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.section-label {
  font-size: 10px;
  font-weight: 800;
  color: #7E848A;
}

.chips-container {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.entity-chip {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 5px 10px;
  font-size: 11px;
  font-weight: 700;
  color: var(--ink);
  display: flex;
  align-items: center;
  gap: 6px;
}

.chip-dot {
  width: 6px;
  height: 6px;
  background: var(--red);
}

.telemetry-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px 16px;
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 12px;
  font-size: 10.5px;
}

.tele-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.t-label {
  color: #7E848A;
  font-size: 9px;
  font-weight: 700;
}

.t-val {
  font-weight: 700;
  color: var(--ink);
}

.text-red {
  color: var(--red);
}

.text-blue {
  color: var(--blue);
}

.modal-action-bar {
  background: var(--fascia);
  border-top: 1px solid var(--line);
  padding: 12px 20px;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 12px;
}

.action-btn {
  padding: 8px 16px;
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.5px;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.15s ease;
}

.lock-btn {
  background: var(--red);
  color: #FFFFFF;
  border-color: var(--red);
}

.lock-btn:hover {
  background: #A02620;
}

.cert-btn {
  background: var(--ink);
  color: var(--panel);
  border-color: var(--ink);
}

.cert-btn:hover {
  background: var(--blue);
  border-color: var(--blue);
  color: #FFFFFF;
}

.dismiss-btn {
  background: transparent;
  color: var(--ink);
  border-color: var(--line);
}

.dismiss-btn:hover {
  border-color: var(--ink);
}
</style>
