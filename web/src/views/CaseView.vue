<template>
  <div class="case-view">
    <AppHeader />

    <main class="content-area">
      <div class="panel-wrapper left-panel" :style="leftPanelStyle">
        <GraphPanel :graphData="session.graphData" @toggle-maximize="toggleMaximize('graph')" />
      </div>

      <div class="panel-wrapper right-panel" :style="rightPanelStyle">
        <div class="step-nav-bar">
          <button
            v-for="(name, idx) in stepNames"
            :key="idx"
            class="step-nav-btn mono"
            :class="{ active: session.currentStep === idx + 1 }"
            @click="session.currentStep = idx + 1"
          >
            <span class="step-idx">0{{ idx + 1 }}</span>
            <span class="step-title">{{ name }}</span>
          </button>
        </div>

        <div class="step-scroll-container">
          <Step1Shield v-if="session.currentStep === 1" @next-step="session.currentStep = 2" />
          <Step2Swarm v-else-if="session.currentStep === 2" @next-step="session.currentStep = 3" />
          <Step3RedTeam v-else-if="session.currentStep === 3" @next-step="session.currentStep = 4" />
          <Step4Scout v-else-if="session.currentStep === 4" @next-step="session.currentStep = 5" />
          <Step5Review v-else-if="session.currentStep === 5" />
        </div>
      </div>
    </main>

    <ConsoleStrip />
    <AlertRaisingModal />
  </div>
</template>

<script setup>
import { computed, onMounted, watch } from 'vue'
import { session, stepNames } from '../store/session'
import { refreshConfig, watchJob } from '../api/case'
import AppHeader from '../components/AppHeader.vue'
import AlertRaisingModal from '../components/AlertRaisingModal.vue'
import GraphPanel from '../components/GraphPanel.vue'
import ConsoleStrip from '../components/ConsoleStrip.vue'
import Step1Shield from '../components/steps/Step1Shield.vue'
import Step2Swarm from '../components/steps/Step2Swarm.vue'
import Step3RedTeam from '../components/steps/Step3RedTeam.vue'
import Step4Scout from '../components/steps/Step4Scout.vue'
import Step5Review from '../components/steps/Step5Review.vue'

const props = defineProps({ caseId: { type: String, default: '' } })

const leftPanelStyle = computed(() => {
  if (session.viewMode === 'graph') return { width: '100%', opacity: 1, transform: 'translateX(0)' }
  if (session.viewMode === 'workbench') return { width: '0%', opacity: 0, transform: 'translateX(-20px)', pointerEvents: 'none' }
  return { width: '50%', opacity: 1, transform: 'translateX(0)' }
})

const rightPanelStyle = computed(() => {
  if (session.viewMode === 'workbench') return { width: '100%', opacity: 1, transform: 'translateX(0)' }
  if (session.viewMode === 'graph') return { width: '0%', opacity: 0, transform: 'translateX(20px)', pointerEvents: 'none' }
  return { width: '50%', opacity: 1, transform: 'translateX(0)' }
})

const toggleMaximize = (target) => {
  session.viewMode = session.viewMode === target ? 'split' : target
}

const open = (id) => {
  if (id === 'scout') session.currentStep = 4 // scout-only case: no document
  else if (id && id !== session.jobId) watchJob(id)
}

onMounted(() => {
  refreshConfig()
  open(props.caseId)
})
watch(() => props.caseId, open)
</script>

<style scoped>
.case-view {
  width: 100vw;
  height: 100vh;
  display: flex;
  flex-direction: column;
  background-color: var(--fascia);
  overflow: hidden;
}

.content-area {
  flex: 1;
  display: flex;
  position: relative;
  overflow: hidden;
}

.panel-wrapper {
  height: 100%;
  overflow: hidden;
  transition: width 0.35s cubic-bezier(0.2, 0.8, 0.2, 1), opacity 0.25s ease, transform 0.25s ease;
  will-change: width, opacity, transform;
}

.panel-wrapper.left-panel {
  border-right: 1px solid var(--line);
}

.panel-wrapper.right-panel {
  display: flex;
  flex-direction: column;
  background: var(--fascia);
}

.step-nav-bar {
  height: 40px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: stretch;
  flex-shrink: 0;
  overflow-x: auto;
}

.step-nav-btn {
  background: transparent;
  border: none;
  border-right: 1px solid var(--line);
  padding: 0 16px;
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: var(--ink);
  opacity: 0.65;
  transition: all 0.15s ease;
  white-space: nowrap;
}

.step-nav-btn:hover {
  opacity: 1;
  background: rgba(0, 0, 0, 0.03);
}

.step-nav-btn.active {
  opacity: 1;
  background: var(--fascia);
  border-bottom: 2px solid var(--blue);
  font-weight: 700;
}

.step-idx {
  font-size: 11px;
  font-weight: 800;
  color: var(--blue);
}

.step-title {
  font-size: 12px;
  letter-spacing: 0.5px;
}

.step-scroll-container {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

/* Mobile responsive stack */
@media (max-width: 900px) {
  .content-area {
    flex-direction: column;
  }
  .panel-wrapper.left-panel, .panel-wrapper.right-panel {
    width: 100% !important;
    height: 50% !important;
    transform: none !important;
    opacity: 1 !important;
  }
}
</style>
