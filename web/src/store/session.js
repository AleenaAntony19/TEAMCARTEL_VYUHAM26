import { reactive, computed } from 'vue'
import { addLog } from '../api/map.js'

const initialSession = () => ({
  caseId: '',
  jobId: '',
  filename: '',
  originalUrl: '', // browser-only link to the uploaded image, never sent anywhere
  job: null,
  currentStep: 1,
  viewMode: 'split', // 'graph' | 'split' | 'workbench'
  status: 'Ready',
  statusType: 'ready', // 'ready' | 'processing' | 'completed' | 'error'
  stagesSeen: 0,

  detectedCounts: {},
  severity: 'NONE',
  severityScore: 0,
  selection: {},
  selectionSet: false,
  redaction: null,
  redacting: false,

  agents: [],
  deliberationLogs: [],
  swarmRunning: false,
  swarmResult: null,
  swarmError: '',

  showAlertModal: false,
  attacks: [],

  enrolled: false,
  references: 0,
  registry: [],
  queries: [],
  textHits: [],
  matches: [],
  discovery: null,
  scoutJobId: '',
  scoutRunning: false,
  scoutError: '',
  counters: { pages: 0, images: 0, blocked: 0, matches: 0 },

  ledgers: [],
  tamperResult: null,

  graphData: { nodes: [], edges: [] },
  systemLogs: []
})

export const session = reactive(initialSession())
export const config = reactive({ value: null }) // survives a wipe: it describes the server, not the case

export const stepNames = ['Document Shield', 'Agent Swarm', 'Red Team', 'Leak Scout', 'Review & Ledger']
export const currentStepName = computed(() => stepNames[session.currentStep - 1] || 'Workspace')

export const log = (msg, level = 'info') => addLog(session, msg, level)

export function resetSession() {
  Object.assign(session, initialSession())
}
