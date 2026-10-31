<template>
  <header class="app-header">
    <div class="header-left">
      <div class="brand" @click="router.push('/')">
        <span class="brand-icon">🛡️</span>
        <span class="brand-text">SHIELD·SCOUT</span>
      </div>
      <span class="brand-tag clickable" @click="showKeyModal = true" title="Configure AI Provider & Keys">
        {{ llmLabel || 'CONFIGURE AI' }} ⚙️
      </span>
    </div>
    <ApiKeyModal v-model="showKeyModal" />

    <div class="header-center">
      <div class="view-switcher" role="group" aria-label="Layout view switcher">
        <button
          v-for="mode in ['graph', 'split', 'workbench']"
          :key="mode"
          class="switch-btn"
          :class="{ active: session.viewMode === mode }"
          @click="session.viewMode = mode"
        >
          {{ mode.toUpperCase() }}
        </button>
      </div>
    </div>

    <div class="header-right">
      <div class="workflow-step">
        <span class="step-num mono">Step {{ session.currentStep }}/5</span>
        <span class="step-name">{{ currentStepName }}</span>
      </div>

      <div class="step-divider"></div>

      <div class="status-indicator" :class="session.statusType">
        <span class="dot"></span>
        <span class="status-text mono">{{ session.status }}</span>
      </div>

      <div class="step-divider"></div>

      <button
        class="alert-badge-btn mono"
        :class="{ active: session.showAlertModal, flashing: session.severityScore >= 80 }"
        :disabled="!session.job"
        @click="session.showAlertModal = true"
        title="View Security Exposure Alert Window"
      >
        <span class="alert-icon">⚠️</span>
        <span>ALERT {{ session.severityScore ? `(${session.severityScore})` : '' }}</span>
      </button>

      <div class="step-divider"></div>

      <button class="wipe-btn mono" @click="handleWipe" title="Delete every job, upload, output and enrolment in this session">
        WIPE
      </button>
    </div>
  </header>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { config, currentStepName, session } from '../store/session'
import { wipeAll } from '../api/case'
import ApiKeyModal from './ApiKeyModal.vue'
import { ai } from '../api/index'

const router = useRouter()
const showKeyModal = ref(false)
const llmLabel = computed(() => (ai.mode === 'ai' ? `AI: ${ai.provider}` : 'RULES ONLY'))

const handleWipe = async () => {
  if (confirm('Delete every job, upload, sanitized output, reference hash and enrolment in this session, and forget any API key set here?')) {
    try {
      await wipeAll()
      router.push('/')
    } catch (e) {
      alert(`Wipe failed: ${e.message}`)
    }
  }
}
</script>


<style scoped>
.app-header {
  height: 52px;
  background-color: var(--panel);
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
  position: relative;
  z-index: 100;
  flex-shrink: 0;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  user-select: none;
}

.brand-icon {
  font-size: 18px;
}

.brand-text {
  font-family: var(--font-mono);
  font-weight: 800;
  font-size: 17px;
  letter-spacing: 1.5px;
  color: var(--ink);
}

.brand-tag {
  font-family: var(--font-mono);
  font-size: 10px;
  padding: 3px 8px;
  background: var(--fascia);
  color: var(--blue);
  border: 1px solid var(--line);
  font-weight: 600;
  letter-spacing: 0.5px;
  border-radius: 2px;
}

.brand-tag.clickable {
  cursor: pointer;
  user-select: none;
  transition: all 0.15s ease;
}

.brand-tag.clickable:hover {
  background: var(--surface);
  border-color: var(--blue);
  box-shadow: 0 0 6px rgba(59, 130, 246, 0.3);
}

.header-center {
  position: absolute;
  left: 50%;
  transform: translateX(-50%);
}

.view-switcher {
  display: flex;
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 2px;
  gap: 2px;
}

.switch-btn {
  border: 1px solid transparent;
  background: transparent;
  color: var(--ink);
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.5px;
  padding: 4px 14px;
  cursor: pointer;
  opacity: 0.7;
  transition: all 0.15s ease;
}

.switch-btn:hover {
  opacity: 1;
  background: rgba(255, 255, 255, 0.1);
}

.switch-btn.active {
  background: var(--panel);
  color: var(--ink);
  opacity: 1;
  border: 1px solid var(--ink);
}

.header-right {
  display: flex;
  align-items: center;
  gap: 14px;
}

.workflow-step {
  display: flex;
  align-items: center;
  gap: 8px;
}

.step-num {
  font-size: 12px;
  font-weight: 700;
  color: var(--blue);
}

.step-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--ink);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.step-divider {
  width: 1px;
  height: 16px;
  background-color: var(--line);
}

.status-indicator {
  display: flex;
  align-items: center;
  gap: 6px;
}

.status-text {
  font-size: 11px;
  font-weight: 600;
  color: var(--ink);
}

.dot {
  width: 7px;
  height: 7px;
  background: var(--line);
}

.status-indicator.ready .dot {
  background: #2E9E6B;
}

.status-indicator.processing .dot {
  background: #FF6B35;
  animation: statusBlink 1s infinite;
}

.status-indicator.completed .dot {
  background: #2E9E6B;
}

.status-indicator.error .dot {
  background: var(--red);
}

@keyframes statusBlink {
  50% { opacity: 0.3; }
}

.alert-badge-btn {
  background: transparent;
  color: var(--red);
  border: 1px solid var(--red);
  font-size: 10px;
  font-weight: 800;
  padding: 3px 8px;
  display: flex;
  align-items: center;
  gap: 5px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.alert-badge-btn:hover,
.alert-badge-btn.active {
  background: var(--red);
  color: #FFFFFF;
}

.alert-badge-btn.flashing {
  animation: alertPulse 1.2s infinite alternate;
}

@keyframes alertPulse {
  0% { background: transparent; color: var(--red); }
  100% { background: #C8312B25; color: var(--red); box-shadow: 0 0 8px rgba(200, 49, 43, 0.4); }
}

.wipe-btn {
  background: transparent;
  color: var(--red);
  border: 1px solid var(--red);
  font-size: 10px;
  font-weight: 700;
  padding: 3px 8px;
  letter-spacing: 0.5px;
  cursor: pointer;
  transition: background 0.15s ease;
}

.wipe-btn:hover {
  background: var(--red);
  color: #FFF;
}
</style>
