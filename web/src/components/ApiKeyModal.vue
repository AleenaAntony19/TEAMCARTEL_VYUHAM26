<template>
  <div v-if="modelValue" class="key-modal-backdrop" @click.self="close" @keydown.esc="close">
    <div class="key-modal-window" role="dialog" aria-modal="true">
      <div class="modal-top-bar">
        <div class="top-title-group">
          <span class="icon">🔑</span>
          <span class="title mono">AI PROVIDER & API KEY CONFIGURATION</span>
        </div>
        <button class="modal-close-btn mono" @click="close" title="Close">✕</button>
      </div>

      <div class="modal-body">
        <p class="desc mono">
          Public evaluation mode: Anyone can supply their own Groq or Anthropic Claude API key to run agent deliberations and natural language risk explanations.
          Keys are kept in server memory only and are never saved to disk.
        </p>

        <div class="field-group">
          <label class="field-label mono">AI PROVIDER</label>
          <select class="field-input mono" v-model="form.provider">
            <option value="none">None (Local Deterministic Only)</option>
            <option value="anthropic">Anthropic Claude (claude-haiku-5-5)</option>
            <option value="groq">Groq (High-Speed LLM Inference)</option>
          </select>
        </div>

        <div class="field-group">
          <label class="field-label mono">MODEL (OPTIONAL - LEAVE EMPTY FOR DEFAULT)</label>
          <input
            class="field-input mono"
            v-model="form.model"
            :placeholder="defaultModelPlaceholder"
          />
        </div>

        <div class="field-group">
          <label class="field-label mono">API KEY</label>
          <input
            class="field-input mono"
            type="password"
            autocomplete="off"
            v-model="form.key"
            :placeholder="config?.llm?.key_set ? 'Key is currently active; enter new key to replace' : 'Paste API Key (sk-ant-... or gsk_...)'"
          />
        </div>

        <div v-if="statusMsg" class="status-msg mono" :class="{ error: isError, success: !isError && !loading }">
          {{ statusMsg }}
        </div>
      </div>

      <div class="modal-action-bar">
        <button class="btn test-btn mono" :disabled="loading || form.provider === 'none'" @click="testKey">
          {{ loading ? 'TESTING…' : 'TEST CONNECTION' }}
        </button>
        <div class="action-right">
          <button class="btn cancel-btn mono" @click="close">CANCEL</button>
          <button class="btn save-btn mono" :disabled="loading" @click="saveKey">
            SAVE & APPLY
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { config } from '../store/session'
import { refreshConfig } from '../api/case'
import { api } from '../api/index'

const props = defineProps({
  modelValue: { type: Boolean, default: false }
})

const emit = defineEmits(['update:modelValue'])

const form = reactive({
  provider: 'anthropic',
  model: '',
  key: ''
})

const statusMsg = ref('')
const isError = ref(false)
const loading = ref(false)

const defaultModelPlaceholder = computed(() => {
  if (form.provider === 'anthropic') return 'claude-haiku-5-5 (default)'
  if (form.provider === 'groq') return 'openai/gpt-oss-120b or qwen/qwen3.8-27b'
  return 'default'
})

watch(() => props.modelValue, (isOpen) => {
  if (isOpen) {
    statusMsg.value = ''
    isError.value = false
    if (config.value?.llm?.provider && config.value.llm.provider !== 'none') {
      form.provider = config.value.llm.provider
      form.model = config.value.llm.model || ''
    }
  }
})

const close = () => {
  emit('update:modelValue', false)
}

const saveKey = async () => {
  loading.value = true
  statusMsg.value = 'Saving…'
  isError.value = false
  try {
    await api.setLlm({
      provider: form.provider,
      model: form.model.trim(),
      endpoint: '',
      api_key: form.key,
      timeout: 30,
      retries: 2
    })
    form.key = ''
    await refreshConfig()
    statusMsg.value = 'Settings applied successfully!'
    setTimeout(() => {
      close()
    }, 1200)
  } catch (err) {
    isError.value = true
    statusMsg.value = `Error saving: ${err.message}`
  } finally {
    loading.value = false
  }
}

const testKey = async () => {
  loading.value = true
  statusMsg.value = 'Testing provider connection…'
  isError.value = false
  try {
    if (form.key) {
      await api.setLlm({
        provider: form.provider,
        model: form.model.trim(),
        endpoint: '',
        api_key: form.key,
        timeout: 30,
        retries: 2
      })
      await refreshConfig()
    }
    const r = await api.testLlm()
    if (r.ok) {
      statusMsg.value = `Connected to ${r.model} (${r.latency_ms} ms latency)`
    } else {
      isError.value = true
      statusMsg.value = `Connection failed: ${r.error}`
    }
  } catch (err) {
    isError.value = true
    statusMsg.value = `Test failed: ${err.message}`
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.key-modal-backdrop {
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

.key-modal-window {
  width: 100%;
  max-width: 580px;
  background: var(--panel);
  border: 1px solid var(--line);
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
  display: flex;
  flex-direction: column;
}

.modal-top-bar {
  height: 44px;
  background: var(--surface);
  border-bottom: 1px solid var(--line);
  color: var(--text);
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

.icon {
  font-size: 16px;
}

.title {
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.5px;
}

.modal-close-btn {
  background: none;
  border: none;
  color: var(--dim);
  font-size: 16px;
  cursor: pointer;
  padding: 4px 8px;
}

.modal-close-btn:hover {
  color: var(--text);
}

.modal-body {
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.desc {
  font-size: 12px;
  line-height: 1.5;
  color: var(--dim);
  margin: 0;
}

.field-group {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.field-label {
  font-size: 11px;
  color: var(--dim);
  font-weight: 600;
}

.field-input {
  background: var(--bg);
  border: 1px solid var(--line);
  color: var(--text);
  padding: 8px 12px;
  font-size: 13px;
  border-radius: 2px;
  outline: none;
}

.field-input:focus {
  border-color: var(--primary, #3b82f6);
}

.status-msg {
  font-size: 12px;
  padding: 8px 12px;
  border-radius: 2px;
}

.status-msg.success {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
  border: 1px solid rgba(34, 197, 94, 0.3);
}

.status-msg.error {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
  border: 1px solid rgba(239, 68, 68, 0.3);
}

.modal-action-bar {
  padding: 12px 20px;
  background: var(--surface);
  border-top: 1px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.action-right {
  display: flex;
  gap: 10px;
}

.btn {
  padding: 8px 16px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  border-radius: 2px;
  border: 1px solid var(--line);
  background: var(--panel);
  color: var(--text);
  transition: all 0.15s ease;
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.test-btn:hover:not(:disabled) {
  border-color: var(--dim);
}

.cancel-btn:hover {
  background: var(--line);
}

.save-btn {
  background: #2563eb;
  border-color: #2563eb;
  color: #ffffff;
}

.save-btn:hover:not(:disabled) {
  background: #1d4ed8;
}
</style>
