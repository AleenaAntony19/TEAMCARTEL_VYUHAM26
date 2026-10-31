<template>
  <div class="step-view">
    <div class="step-card">
      <div class="card-header">
        <div class="step-meta">
          <span class="step-badge mono">02</span>
          <span class="step-title">AI AGENT SWARM</span>
        </div>
        <div class="step-status-tag mono" :class="session.swarmRunning ? 'pending' : 'completed'">{{ activeAgentCount }} ACTIVE AGENTS</div>
      </div>

      <div class="card-content">
        <p class="step-desc">
          MetaPlanner spawns specialists, PrivacyHawk, PragmaticDev and StatutoryAuditor debate, SwarmAdjudicator's plan is executed, and the red team attacks the result (up to 3 cycles). Agents see masked values only. Verified IDs are always redacted, whatever an agent says.
        </p>

        <div class="stats-grid">
          <div class="stat-box">
            <span class="stat-number mono">{{ session.agents.length }}</span>
            <span class="stat-caption mono">SPAWNED AGENTS</span>
          </div>
          <div class="stat-box">
            <span class="stat-number mono">{{ activeAgentCount }}</span>
            <span class="stat-caption mono">ACTIVE PROCESSES</span>
          </div>
          <div class="stat-box">
            <span class="stat-number mono">{{ session.deliberationLogs.length }}</span>
            <span class="stat-caption mono">DEBATED ENTITIES</span>
          </div>
          <div class="stat-box">
            <span class="stat-number mono">{{ (session.swarmResult?.tokens || 0).toLocaleString() }}</span>
            <span class="stat-caption mono">TOKENS USED</span>
          </div>
        </div>

        <div v-if="session.severity === 'CRITICAL' || session.severity === 'HIGH'" class="alert-window">
          <div class="alert-header">
            <span class="alert-icon">⚠️</span>
            <span class="alert-title mono">{{ session.severity }} SENSITIVE EXPOSURE DETECTED</span>
            <span class="alert-score mono">SCORE: {{ session.severityScore }}/100</span>
          </div>
          <div class="alert-footer-row">
            <div class="alert-tags">
              <span v-for="(cnt, t) in session.detectedCounts" :key="t" class="alert-tag mono">{{ t }}: {{ cnt }}</span>
            </div>
            <button class="open-alert-modal-btn mono" @click="session.showAlertModal = true">🚨 OPEN SECURITY ALERT WINDOW</button>
          </div>
        </div>

        <div class="next-action-row">
          <button class="action-btn mono" :disabled="!canRun" @click="runSwarm">
            {{ session.swarmRunning ? 'AGENTS WORKING…' : '▶ RUN AI AGENT SWARM' }}
          </button>
        </div>
        <p v-if="!session.job" class="err-line mono">The swarm needs a document. Start a case from the home screen.</p>
        <p v-else-if="!llmReady && !config.value?.local_only" class="err-line mono">Connect an AI provider below first.</p>
        <p v-if="session.swarmError" class="err-line mono">{{ session.swarmError }}</p>
        <p v-if="session.swarmResult" class="step-desc mono">
          {{ session.swarmResult.clean ? 'CLEAN' : 'NOT CLEAN' }} · {{ session.swarmResult.llm_calls }} LLM calls · {{ session.swarmResult.tool_calls }} tool calls · {{ session.swarmResult.cycles }} cycle(s)
          <template v-if="session.swarmResult.fail_safe_defaults"> · {{ session.swarmResult.fail_safe_defaults }} decided by the fail-safe, not an agent</template>
        </p>
      </div>
    </div>

    <div class="step-card">
      <div class="card-header">
        <div class="step-meta">
          <span class="step-badge mono">CONFIG</span>
          <span class="step-title">AI PROVIDER</span>
        </div>
        <span class="step-status-tag mono" :class="llmReady ? 'completed' : 'pending'">{{ !llmReady ? 'RULES ONLY' : ai.key ? ai.provider + ' / your key' : 'server key' }}</span>
      </div>
      <div class="card-content">
        <p v-if="config.value?.local_only" class="err-line mono">Local-only mode is on: remote AI is disabled.</p>
        <div class="form-row">
          <label class="mono">PROVIDER
            <select class="field mono" v-model="form.provider">
              <option value="none">None (rules only)</option>
              <option value="anthropic">Anthropic Claude</option>
              <option value="groq">Groq</option>
            </select>
          </label>
          <label class="mono grow">MODEL (EMPTY = DEFAULT)
            <input class="field mono" v-model="form.model" :placeholder="llm?.model || ''" />
          </label>
          <label class="mono grow">YOUR API KEY (kept in this tab only)
            <input class="field mono" type="password" autocomplete="off" v-model.trim="form.key" :placeholder="ai.key ? 'key set; leave empty to keep it' : llm?.key_set ? 'optional: this server has a key' : 'paste key'" />
          </label>
        </div>
        <div class="next-action-row">
          <button class="action-btn mono" @click="saveProvider">SAVE</button>
          <button class="action-btn mono" :disabled="!llmReady" @click="testProvider">TEST CONNECTION</button>
        </div>
        <p v-if="providerNote" class="step-desc mono">{{ providerNote }}</p>
      </div>
    </div>

    <div class="step-card">
      <div class="card-header">
        <div class="step-meta">
          <span class="step-badge mono">SWARM</span>
          <span class="step-title">AGENT PERSONAS</span>
        </div>
      </div>
      <div class="card-content">
        <div v-if="session.agents.length" class="agents-grid">
          <div v-for="agent in session.agents" :key="agent.name" class="agent-card">
            <div class="agent-card-header">
              <div class="agent-identity">
                <span class="agent-type-dot"></span>
                <span class="agent-name mono">{{ agent.name }}</span>
              </div>
              <span class="agent-state mono" :class="agent.state">{{ agent.state.toUpperCase() }}</span>
            </div>
            <div class="agent-scope">
              <span class="scope-label mono">TOOLS USED:</span>
              <span class="scope-text">{{ agent.tools.join(', ') || 'none yet' }}</span>
            </div>
            <div class="agent-params-grid mono">
              <div class="param-col"><span class="p-k">STEPS:</span><span class="p-v">{{ agent.steps }}</span></div>
              <div class="param-col"><span class="p-k">TOKENS:</span><span class="p-v">{{ agent.tokens }}</span></div>
            </div>
            <p v-if="agent.error" class="err-line mono">{{ agent.error }}</p>
          </div>
        </div>
        <p v-else class="empty-state mono">Agents appear here when the swarm runs.</p>
      </div>
    </div>

    <div class="step-card">
      <div class="card-header">
        <div class="step-meta">
          <span class="step-badge mono">CONSENSUS</span>
          <span class="step-title">RULE REVIEW OF EACH DETECTION</span>
        </div>
      </div>
      <div class="card-content">
        <p class="step-desc">Deterministic reviewers check every detection, so ambiguous values are confirmed or dismissed on evidence. This runs locally and needs no AI.</p>
        <div class="debates-list">
          <div v-for="(log, idx) in session.deliberationLogs" :key="idx" class="debate-block">
            <div class="debate-block-header">
              <div class="target-info mono">
                <span class="target-badge">ENTITY #{{ idx + 1 }}</span>
                <span class="target-val font-bold">{{ log.masked }}</span>
                <span class="target-type mono">({{ log.type }})</span>
              </div>
              <div class="verdict-badge mono" :class="log.verdict === 'dismissed' ? 'rejected' : 'confirmed'">
                VERDICT: {{ log.verdict.toUpperCase() }} (CONF: {{ Math.round(log.confidence * 100) }}%)
              </div>
            </div>
            <div class="turns-feed">
              <div v-for="(turn, tIdx) in log.turns" :key="tIdx" class="turn-row">
                <div class="turn-body">
                  <div class="turn-meta">
                    <span class="turn-persona mono">{{ turn.reviewer }}</span>
                    <span class="turn-action mono">[{{ turn.rule }}: {{ turn.passed ? 'pass' : 'fail' }}]</span>
                  </div>
                  <p class="turn-arg">{{ turn.evidence }}</p>
                </div>
              </div>
            </div>
          </div>
          <div v-if="!session.deliberationLogs.length" class="empty-state mono">Reviews appear here once analysis finishes.</div>
        </div>
        <div class="next-action-row">
          <button class="action-btn mono" @click="emit('next-step')">PROCEED TO STEP 3: RED TEAM VERIFICATION →</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { config, session } from '../../store/session'
import { refreshConfig, runSwarm } from '../../api/case'
import { ai, api } from '../../api/index'

const emit = defineEmits(['next-step'])
const form = reactive({ provider: 'none', model: '', key: '' })
const providerNote = ref('')

const llm = computed(() => config.value?.llm)
const llmReady = computed(() => ai.mode === 'ai' && (!!ai.key || !!llm.value?.key_set))
const canRun = computed(() => session.job?.status === 'ready' && llmReady.value && !session.swarmRunning)
const activeAgentCount = computed(() => session.agents.filter((a) => a.state === 'active').length)

const saveProvider = () => {
  ai.mode = form.provider === 'none' ? 'rules' : 'ai'
  if (form.provider !== 'none') ai.provider = form.provider
  ai.key = form.provider === 'none' ? '' : form.key || ai.key
  ai.model = form.model.trim()
  form.key = ''
  providerNote.value = 'Saved for this tab.'
}

const testProvider = async () => {
  providerNote.value = 'Testing…'
  try {
    const r = await api.testLlm()
    providerNote.value = r.ok ? `Connected to ${r.model} (${r.latency_ms} ms).` : `Failed: ${r.error}`
  } catch (e) {
    providerNote.value = e.message
  }
}

onMounted(async () => {
  await refreshConfig()
  form.provider = ai.mode === 'ai' ? ai.provider : 'none'
})
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

.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
}

.stat-box {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.stat-number {
  font-size: 22px;
  font-weight: 900;
  color: var(--blue);
}

.stat-caption {
  font-size: 9px;
  font-weight: 700;
  color: #7E848A;
}

.alert-window {
  border: 1px solid var(--red);
  background: #C8312B12;
  padding: 12px 14px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.alert-header {
  display: flex;
  align-items: center;
  gap: 8px;
}

.alert-icon {
  font-size: 16px;
}

.alert-title {
  font-size: 11.5px;
  font-weight: 800;
  color: var(--red);
}

.alert-score {
  margin-left: auto;
  font-size: 11px;
  font-weight: 800;
  color: var(--red);
  background: var(--panel);
  border: 1px solid var(--red);
  padding: 2px 6px;
}

.alert-desc {
  font-size: 12px;
  color: var(--ink);
  line-height: 1.35;
}

.alert-footer-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-top: 4px;
}

.alert-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.alert-tag {
  background: var(--panel);
  border: 1px solid var(--line);
  font-size: 9.5px;
  font-weight: 700;
  color: var(--ink);
  padding: 2px 6px;
}

.open-alert-modal-btn {
  background: var(--red);
  color: #FFFFFF;
  border: 1px solid var(--red);
  font-size: 10.5px;
  font-weight: 800;
  padding: 5px 12px;
  cursor: pointer;
  white-space: nowrap;
}

.open-alert-modal-btn:hover {
  background: #A02620;
}

/* Config sub-blocks */
.config-sub-block {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.sub-block-title {
  font-size: 10.5px;
  font-weight: 800;
  color: var(--ink);
  letter-spacing: 0.5px;
}

.time-metrics-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
}

.time-box {
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 8px 10px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.tb-label {
  font-size: 8.5px;
  font-weight: 700;
  color: #7E848A;
}

.tb-val {
  font-size: 13px;
  font-weight: 800;
  color: var(--blue);
}

.periods-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  font-size: 10px;
}

.period-chip {
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 4px 8px;
  display: flex;
  gap: 6px;
}

.pc-name {
  color: #7E848A;
  font-weight: 700;
}

.pc-val {
  color: var(--ink);
  font-weight: 800;
}

/* Platforms Grid */
.platforms-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.platform-col {
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.plat-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--line);
  padding-bottom: 6px;
}

.plat-name {
  font-size: 11px;
  font-weight: 800;
  color: var(--ink);
}

.plat-badge {
  background: var(--blue);
  color: #FFFFFF;
  font-size: 9px;
  font-weight: 800;
  padding: 2px 6px;
}

.plat-badge.darknet {
  background: var(--red);
}

.plat-params {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 10px;
}

.param-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.slider-meter {
  flex: 1;
  height: 6px;
  background: var(--fascia);
  border: 1px solid var(--line);
  position: relative;
}

.meter-bar {
  height: 100%;
  background: var(--blue);
}

/* Orchestration Content */
.narrative-box {
  background: var(--fascia);
  border: 1px solid var(--line);
  border-left: 3px solid var(--blue);
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.narrative-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 10px;
  font-weight: 800;
  color: var(--blue);
}

.narrative-text {
  font-size: 12px;
  color: var(--ink);
  line-height: 1.4;
  font-style: italic;
}

.topics-section {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.section-sub-title {
  font-size: 10px;
  font-weight: 800;
  color: #7E848A;
}

.hot-topics-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.hot-topic-tag {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 4px 8px;
  font-size: 10px;
  font-weight: 800;
  color: var(--blue);
}

.posts-timeline {
  display: flex;
  flex-direction: column;
  gap: 8px;
  position: relative;
  border-left: 2px solid var(--line);
  padding-left: 12px;
  margin-left: 4px;
}

.timeline-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  position: relative;
}

.timeline-marker {
  width: 8px;
  height: 8px;
  background: var(--blue);
  position: absolute;
  left: -17px;
  top: 4px;
}

.post-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 10px;
}

.post-role {
  font-weight: 800;
  padding: 1px 5px;
}

.role-threatactor { background: #C8312B20; color: var(--red); border: 1px solid var(--red); }
.role-analyst { background: #2E9E6B20; color: #2E9E6B; border: 1px solid #2E9E6B; }
.role-moderator { background: #4A617820; color: var(--blue); border: 1px solid var(--blue); }

.post-user { font-weight: 700; color: var(--ink); }
.post-agent-id { color: #7E848A; }
.post-time { margin-left: auto; color: #7E848A; }
.post-text { font-size: 11.5px; color: var(--ink); line-height: 1.35; background: var(--fascia); padding: 6px 10px; border: 1px solid var(--line); }

/* Agent Cards Grid */
.agent-count-selector {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 10px;
  font-weight: 700;
}

.scale-select {
  background: var(--panel);
  border: 1px solid var(--line);
  color: var(--ink);
  padding: 2px 6px;
  font-size: 10px;
}

.agents-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(290px, 1fr));
  gap: 12px;
}

.agent-card {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.agent-card.is-killed {
  opacity: 0.55;
  filter: grayscale(0.8);
}

.agent-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.agent-identity {
  display: flex;
  align-items: center;
  gap: 8px;
}

.agent-type-dot {
  width: 8px;
  height: 8px;
  background: #E9724C;
}

.agent-name {
  font-size: 11.5px;
  font-weight: 800;
  color: var(--ink);
}

.agent-state {
  font-size: 9px;
  font-weight: 800;
  padding: 2px 5px;
  background: var(--panel);
  border: 1px solid var(--line);
}

.agent-state.active {
  color: #2E9E6B;
  border-color: #2E9E6B;
}

.agent-state.killed {
  color: var(--red);
  border-color: var(--red);
}

.agent-scope {
  font-size: 11px;
  line-height: 1.3;
}

.scope-label {
  font-size: 9px;
  font-weight: 700;
  color: #7E848A;
  margin-right: 4px;
}

.scope-text {
  color: var(--ink);
}

/* 24h Mini Timeline */
.agent-timeline {
  display: flex;
  flex-direction: column;
  gap: 4px;
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 6px 8px;
}

.timeline-header-row {
  display: flex;
  justify-content: space-between;
  font-size: 8.5px;
  font-weight: 800;
  color: #7E848A;
}

.mini-timeline-bar {
  display: flex;
  height: 12px;
  gap: 1px;
  background: var(--fascia);
  border: 1px solid var(--line);
}

.timeline-slot {
  flex: 1;
  background: transparent;
}

.timeline-slot.active {
  background: var(--blue);
}

.timeline-ticks {
  display: flex;
  justify-content: space-between;
  font-size: 7.5px;
  color: #7E848A;
}

.agent-params-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 6px;
  font-size: 9.5px;
}

.param-col {
  display: flex;
  flex-direction: column;
  gap: 1px;
}

.p-k { color: #7E848A; font-size: 8px; font-weight: 700; }
.p-v { font-weight: 800; color: var(--ink); }

.budget-section {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.budget-meta {
  display: flex;
  justify-content: space-between;
  font-size: 9px;
  color: #7E848A;
}

.budget-track {
  height: 4px;
  background: var(--panel);
  border: 1px solid var(--line);
}

.budget-fill {
  height: 100%;
  transition: width 0.3s ease;
}

.agent-actions {
  display: flex;
  margin-top: 4px;
}

.kill-btn {
  width: 100%;
  background: transparent;
  border: 1px solid var(--line);
  color: var(--red);
  font-size: 10px;
  font-weight: 800;
  padding: 5px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.kill-btn:hover:not(:disabled) {
  background: var(--red);
  color: #FFFFFF;
  border-color: var(--red);
}

.kill-btn:disabled {
  border-color: var(--line);
  color: #7E848A;
  cursor: not-allowed;
}

/* Debates list */
.debates-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.debate-block {
  background: var(--fascia);
  border: 1px solid var(--line);
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.debate-block-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--line);
  padding-bottom: 6px;
}

.target-info {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 11px;
}

.target-badge {
  background: var(--blue);
  color: #FFFFFF;
  font-size: 9px;
  font-weight: 800;
  padding: 2px 5px;
}

.target-val {
  color: var(--ink);
}

.target-type {
  color: #7E848A;
}

.verdict-badge {
  font-size: 10px;
  font-weight: 800;
  padding: 2px 8px;
}

.verdict-badge.confirmed {
  background: #2E9E6B20;
  color: #2E9E6B;
  border: 1px solid #2E9E6B;
}

.verdict-badge.rejected {
  background: #C8312B20;
  color: var(--red);
  border: 1px solid var(--red);
}

.turns-feed {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.turn-row {
  display: flex;
  gap: 8px;
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 6px 8px;
}

.turn-avatar {
  font-size: 14px;
}

.turn-body {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.turn-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 9.5px;
}

.turn-persona {
  font-weight: 800;
  color: var(--blue);
}

.turn-action {
  color: #7E848A;
}

.turn-conf {
  margin-left: auto;
  color: #7E848A;
}

.turn-arg {
  font-size: 11px;
  color: var(--ink);
  line-height: 1.3;
}

.empty-state {
  font-size: 11px;
  color: #7E848A;
  font-style: italic;
  padding: 10px 0;
}

.next-action-row {
  display: flex;
  justify-content: flex-end;
  margin-top: 8px;
}

.action-btn {
  background: var(--ink);
  color: var(--panel);
  border: 1px solid var(--ink);
  font-size: 11px;
  font-weight: 800;
  padding: 8px 16px;
  cursor: pointer;
  letter-spacing: 0.5px;
  transition: all 0.15s ease;
}

.action-btn:hover {
  background: var(--blue);
  border-color: var(--blue);
  color: #FFFFFF;
}
</style>
