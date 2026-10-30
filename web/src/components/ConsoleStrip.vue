<template>
  <div class="console-strip" :class="{ collapsed: isCollapsed }">
    <div class="console-header" @click="isCollapsed = !isCollapsed">
      <div class="header-left">
        <span class="console-title mono">SYSTEM DASHBOARD</span>
        <span class="log-count mono">({{ session.systemLogs.length }} events)</span>
      </div>
      <div class="header-right">
        <span class="case-id mono">{{ session.caseId || 'NO CASE' }}</span>
        <button class="toggle-btn mono" :title="isCollapsed ? 'Expand console' : 'Collapse console'">
          {{ isCollapsed ? '▲ EXPAND' : '▼ COLLAPSE' }}
        </button>
      </div>
    </div>

    <div v-show="!isCollapsed" class="console-body" ref="logContainer">
      <div
        v-for="log in session.systemLogs"
        :key="log.id"
        class="log-row"
        :class="[log.level, { 'is-warn': isWarnMessage(log) }]"
      >
        <span class="log-time mono">{{ log.time }}</span>
        <span class="log-msg mono">{{ log.msg }}</span>
      </div>

      <div v-if="session.systemLogs.length === 0" class="log-empty mono">
        // Ready. Waiting for a document or a scout run...
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, watch, nextTick } from 'vue'
import { session } from '../store/session'

const isCollapsed = ref(false)
const logContainer = ref(null)

const isWarnMessage = (log) => {
  if (log.level === 'warn' || log.level === 'error') return true
  const msg = log.msg.toUpperCase()
  return msg.includes('FAIL') || msg.includes('WARN') || msg.includes('BLOCK') || 
         msg.includes('TAMPER') || msg.includes('KILL') || msg.includes('CRITICAL')
}

watch(
  () => session.systemLogs.length,
  async () => {
    await nextTick()
    if (logContainer.value) {
      logContainer.value.scrollTop = logContainer.value.scrollHeight
    }
  }
)
</script>

<style scoped>
.console-strip {
  background: var(--console);
  color: var(--console-ink);
  border-top: 1px solid #282C30;
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  z-index: 90;
  transition: height 0.2s ease;
}

.console-strip:not(.collapsed) {
  height: 140px;
}

.console-strip.collapsed {
  height: 28px;
}

.console-header {
  height: 28px;
  background: #111315;
  border-bottom: 1px solid #23272B;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
  cursor: pointer;
  user-select: none;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 10px;
}

.console-title {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 1px;
  color: #8C9298;
}

.log-count {
  font-size: 10px;
  color: #555A60;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.case-id {
  font-size: 10px;
  color: #2E9E6B;
  letter-spacing: 0.5px;
}

.toggle-btn {
  background: transparent;
  border: none;
  color: #7E848A;
  font-size: 9px;
  font-weight: 600;
  cursor: pointer;
}

.toggle-btn:hover {
  color: #FFF;
}

.console-body {
  flex: 1;
  overflow-y: auto;
  padding: 6px 16px;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.log-row {
  display: flex;
  gap: 12px;
  font-size: 11.5px;
  line-height: 1.4;
  color: #B2B7BC;
}

.log-time {
  color: #5C6268;
  min-width: 85px;
  flex-shrink: 0;
}

.log-msg {
  word-break: break-all;
}

/* WARN / FAIL / TAMPER lines in muted red */
.log-row.is-warn .log-msg,
.log-row.warn .log-msg,
.log-row.error .log-msg {
  color: var(--red) !important;
  font-weight: 600;
}

.log-row.is-warn .log-time {
  color: #8A3835;
}

.log-empty {
  font-size: 11px;
  color: #4A5056;
  font-style: italic;
  padding: 10px 0;
}
</style>
