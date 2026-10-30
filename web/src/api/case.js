// Case actions: every button that talks to the backend goes through here.
import { api } from './index.js'
import { applyAgentEvent, applyDeliberation, applyDiscovery, applyJob, applyRedaction, applyScoutEvent, applySwarmResult } from './map.js'
import { config, log, resetSession, session } from '../store/session.js'

const POLL_MS = 600
const ALERT_BANDS = new Set(['CRITICAL', 'HIGH'])
let pollTimer = null
const streams = new Set()

function setStatus(status, statusType) {
  session.status = status
  session.statusType = statusType
}

function fail(e, prefix) {
  log(`${prefix}: ${e.message}`, 'warn')
  setStatus('Error', 'error')
}

function stream(url, handlers) {
  const src = new EventSource(url)
  streams.add(src)
  const close = () => { src.close(); streams.delete(src) }
  for (const [name, fn] of Object.entries(handlers)) {
    src.addEventListener(name, (m) => fn(JSON.parse(m.data), close))
  }
  src.onerror = () => { close(); handlers.lost?.() }
  return close
}

function stopAll() {
  clearTimeout(pollTimer)
  for (const s of streams) s.close()
  streams.clear()
}

export const refreshConfig = () => api.config().then((c) => { config.value = c }, (e) => log(`API unreachable: ${e.message}`, 'warn'))

export async function createCase(file) {
  stopAll()
  resetSession()
  const { id } = await api.submitFile(file)
  return id
}

/** Follow an analysis job until it settles. Also restores a case after a page refresh. */
export function watchJob(id) {
  stopAll()
  if (session.jobId && session.jobId !== id) resetSession() // two cases must never share state
  session.jobId = session.caseId = id
  setStatus('Processing', 'processing')
  const tick = async () => {
    let job
    try {
      job = await api.job(id)
    } catch (e) {
      return fail(e, 'Case not available')
    }
    applyJob(session, job)
    if (job.status === 'queued' || job.status === 'running') {
      pollTimer = setTimeout(tick, POLL_MS)
    } else if (job.status === 'ready') {
      setStatus('Ready', 'completed')
      refreshLedgers()
      if (!session.deliberationLogs.length) deliberate()
      if (ALERT_BANDS.has(session.severity) && !session.redaction) session.showAlertModal = true
      if (job.agent_run?.status === 'running') followSwarm() // the page was refreshed during a run
      else if (job.agent_run?.result && !session.swarmResult) applySwarmResult(session, job.agent_run.result)
    } else {
      setStatus('Failed', 'error')
      log(`Analysis ${job.status}${job.error ? `: ${job.error}` : ''}`, 'warn')
    }
  }
  tick()
}

function deliberate() {
  stream(api.deliberateUrl(session.jobId), {
    turn: (ev) => applyDeliberation(session, ev),
    verdict: (ev) => applyDeliberation(session, ev),
    end: (_, close) => close()
  })
}

export async function redactNow() {
  const selections = Object.entries(session.selection).map(([finding_id, action]) => ({ finding_id, action }))
  session.redacting = true
  setStatus('Redacting', 'processing')
  try {
    const r = await api.redact(session.jobId, selections)
    applyRedaction(session, r)
    log(`[Redaction] ${r.status}: ${r.selected} value(s), SHA-256 ${r.sha256.slice(0, 16)}…`, r.status === 'CLEAN' ? 'info' : 'warn')
    setStatus('Ready', 'completed')
    session.currentStep = 3
    refreshLedgers()
  } catch (e) {
    fail(e, 'Redaction failed')
  } finally {
    session.redacting = false
  }
}

export async function runSwarm() {
  session.swarmError = ''
  session.swarmResult = null
  session.agents = []
  try {
    await api.swarmRun(session.jobId)
  } catch (e) {
    session.swarmError = e.message
    return
  }
  followSwarm()
}

function followSwarm() {
  session.swarmRunning = true
  setStatus('Agents working', 'processing')
  const finish = () => { session.swarmRunning = false; setStatus('Ready', 'completed') }
  stream(api.swarmEventsUrl(session.jobId), {
    agent: (ev) => applyAgentEvent(session, ev),
    end: async (end, close) => {
      close()
      finish()
      applySwarmResult(session, end.result || {})
      if (end.error) { session.swarmError = end.error; log(`[Swarm] ${end.error}`, 'warn') }
      applyJob(session, await api.job(session.jobId))
      refreshLedgers()
    },
    lost: () => { finish(); session.swarmError = 'lost the live connection to the swarm' }
  })
}

export async function runScout({ org, domain, entity_types, crawl }) {
  const requestedCrawl = crawl
  if (session.scoutRunning) return
  Object.assign(session, { queries: [], textHits: [], matches: [], discovery: null, scoutError: '', counters: { pages: 0, images: 0, blocked: 0, matches: 0 } })
  session.scoutRunning = true
  setStatus('Scouting', 'processing')
  const finish = () => { session.scoutRunning = false; setStatus('Ready', 'completed') }
  let id
  try {
    ({ id } = await api.discover({ org, domain, entity_types, crawl, use_faces: session.enrolled, job_id: session.jobId || undefined }))
  } catch (e) {
    session.scoutRunning = false
    session.scoutError = e.message
    return setStatus('Ready', 'completed')
  }
  session.scoutJobId = id
  stream(api.scoutEventsUrl(id), {
    scout: (ev) => applyScoutEvent(session, ev),
    end: async (_, close) => {
      close()
      finish()
      const job = await api.job(id)
      if (job.discovery) applyDiscovery(session, job.discovery)
      const crawl = job.stages.find((st) => st.name === 'crawl')
      if (job.status === 'failed') session.scoutError = job.error || 'scout failed'
      else if (requestedCrawl && crawl?.status === 'skipped') session.scoutError = `Crawl did not run: ${crawl.detail}`
      log(`[Scout] finished: ${session.textHits.length} text result(s), ${session.matches.length} image match(es)`)
      refreshLedgers()
    },
    lost: () => { finish(); session.scoutError = 'lost the live connection to the scout' }
  })
}

export async function reviewMatch(match, decision) {
  const reviewed = await api.review(session.scoutJobId, match.id, decision)
  session.matches[session.matches.findIndex((m) => m.id === match.id)] = reviewed // replaced, not merged: a reject removes the thumbnail
  log(`[Review] ${reviewed.source_url} marked ${reviewed.review}`)
  refreshLedgers()
}

export async function refreshLedgers() {
  const ids = [['Document case', session.jobId], ['Leak scout', session.scoutJobId]].filter(([, id]) => id)
  try {
    session.ledgers = await Promise.all(ids.map(async ([label, id]) => ({ label, id, ...(await api.ledger(id)) })))
  } catch (e) {
    log(`Ledger not available: ${e.message}`, 'warn') // the job expired or was wiped
  }
}

export async function tamperDemo(id) {
  session.tamperResult = { id, ...(await api.tamperDemo(id)) }
  log(`[Ledger] Tamper test: an edited copy of block #${session.tamperResult.tampered_seq} was detected`, 'warn')
}

export async function wipeAll() {
  await api.clearSession()
  stopAll()
  resetSession()
  refreshConfig()
}
