// Pure mapping from real backend data to the case state. No framework, so it runs under `node --test`.

const MAX_LOGS = 400
const MAX_PAGES_PER_SITE = 40
const PERSONAS = new Set(['PrivacyHawk', 'PragmaticDev', 'StatutoryAuditor'])
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

export function addLog(s, msg, level = 'info', ts = Date.now()) {
  const d = new Date(ts)
  const time = d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0')
  s.systemLogs.push({ id: s.systemLogs.length + '-' + ts, time, msg, level })
  if (s.systemLogs.length > MAX_LOGS) s.systemLogs.shift()
}

function ensureNode(s, uuid, name, type, summary = '', attributes = {}) {
  const found = s.graphData.nodes.find((n) => n.uuid === uuid)
  if (found) {
    Object.assign(found.attributes, attributes)
    return found
  }
  const node = { uuid, name, type, summary, attributes, created_at: new Date().toISOString() }
  s.graphData.nodes.push(node)
  return node
}

function ensureEdge(s, source, target, name, kind = 'rel') {
  const uuid = `${source}->${target}:${name}`
  if (!s.graphData.edges.some((e) => e.uuid === uuid)) {
    s.graphData.edges.push({ uuid, source_node_uuid: source, target_node_uuid: target, name, fact_type: name, kind })
  }
}

/** Everything medium or worse, plus people's names, is selected with the safest action the finding offers. */
export function defaultSelection(findings) {
  const out = {}
  for (const f of findings) {
    if (!f.actions?.length || (SEVERITY_ORDER[f.severity] > 2 && f.type !== 'PERSON')) continue
    out[f.id] = f.actions.includes('token') ? 'token' : f.actions[0]
  }
  return out
}

/** Copy one polled analysis job into the case. Safe to call repeatedly. */
export function applyJob(s, job) {
  s.job = job
  s.filename = job.display_name
  for (const st of job.stages.slice(s.stagesSeen)) {
    addLog(s, `[${st.name}] ${st.status}${st.detail ? ': ' + st.detail : ''}`, st.status === 'failed' ? 'warn' : 'info')
  }
  s.stagesSeen = job.stages.length

  const counts = {}
  for (const f of job.findings) counts[f.type] = (counts[f.type] || 0) + 1
  s.detectedCounts = counts
  s.severity = job.summary?.severity || 'NONE'
  s.severityScore = job.summary?.score || 0

  const doc = `doc_${job.id}`
  ensureNode(s, doc, job.display_name, 'Document', 'The uploaded file', { format: job.input_type, status: job.status })
  for (const [type, n] of Object.entries(counts)) {
    ensureNode(s, `pii_${type}`, type, 'Sensitive data', `${n} finding(s), values stay masked`, { count: n })
    ensureEdge(s, doc, `pii_${type}`, 'CONTAINS')
  }
  if (job.status === 'ready' && !s.selectionSet) {
    s.selection = defaultSelection(job.findings)
    s.selectionSet = true
  }
  if (job.redaction) applyRedaction(s, job.redaction)
}

export function applyRedaction(s, r) {
  s.redaction = r
  s.attacks = r.checks
}

function agentCard(s, name) {
  let a = s.agents.find((x) => x.name === name)
  if (!a) {
    a = { name, state: 'active', steps: 0, tokens: 0, tools: [], error: '' }
    s.agents.push(a)
    ensureNode(s, `agent_${name}`, name, 'Agent')
    if (s.job) ensureEdge(s, `agent_${name}`, `doc_${s.job.id}`, 'INSPECTS')
  }
  return a
}

/** One event from /api/v1/swarm/events. */
export function applyAgentEvent(s, ev) {
  if (!ev.agent || ev.agent === 'swarm') return // "swarm" marks round boundaries, it is not an agent
  const a = agentCard(s, ev.agent)
  const me = `agent_${ev.agent}`
  switch (ev.event) {
    case 'spawn':
      agentCard(s, ev.child)
      ensureEdge(s, me, `agent_${ev.child}`, 'SPAWNED')
      addLog(s, `[${ev.agent}] spawned ${ev.child}`, 'info', (ev.ts || 0) * 1000 || undefined)
      break
    case 'tool': {
      const tool = `tool_${ev.action}`
      ensureNode(s, tool, ev.action, 'MCP tool')
      ensureEdge(s, me, tool, 'CALLS')
      if (!a.tools.includes(ev.action)) a.tools.push(ev.action)
      addLog(s, `[${ev.agent}] → ${ev.action}: ${(ev.observation || '').slice(0, 140)}`, 'info', (ev.ts || 0) * 1000 || undefined)
      break
    }
    case 'final':
      a.state = 'done'
      if (PERSONAS.has(ev.agent)) {
        agentCard(s, 'SwarmAdjudicator')
        ensureEdge(s, me, 'agent_SwarmAdjudicator', 'DELIBERATES')
      }
      addLog(s, `[${ev.agent}] returned its verdict`)
      break
    case 'error':
      a.state = 'error'
      a.error = ev.error || ''
      addLog(s, `[${ev.agent}] error: ${ev.error}`, 'warn')
      break
    case 'binding_plan':
      addLog(s, `[${ev.agent}] binding plan: ${ev.decisions} decisions${ev.fail_safe ? `, ${ev.fail_safe} fail-safe` : ''}`)
      break
    case 'redaction':
    case 'refactor':
      addLog(s, `[${ev.agent}] executed: ${(ev.observation || '').slice(0, 140)}`)
      break
  }
}

/** The end event of a swarm run: step and token totals per agent. */
export function applySwarmResult(s, result) {
  s.swarmResult = result.agents ? result : null
  for (const a of s.agents) if (a.state === 'active') a.state = 'done' // the run is over, whatever it ended on
  for (const a of (result.agents || []).flatMap((x) => [x, ...(x.children || [])])) {
    const card = agentCard(s, a.name)
    card.steps += a.steps
    card.tokens += a.tokens
    if (card.state !== 'error') card.state = a.error ? 'error' : 'done'
    if (a.error) card.error = a.error
  }
}

/** One event from /api/v1/swarm/deliberate, grouped per entity. */
export function applyDeliberation(s, ev) {
  if (ev.event === 'turn' || ev.event === 'verdict') {
    let log = s.deliberationLogs.find((d) => d.entity === ev.entity)
    if (!log) {
      log = { entity: ev.entity, type: ev.type, masked: ev.masked, verdict: '', confidence: 0, turns: [] }
      s.deliberationLogs.push(log)
    }
    if (ev.event === 'turn') log.turns.push({ reviewer: ev.reviewer, rule: ev.rule, passed: ev.passed, evidence: ev.evidence })
    else Object.assign(log, { verdict: ev.verdict, confidence: ev.confidence })
  }
}

/** Host plus first path segment, so the graph shows which section of a site was scraped. */
export function area(url) {
  try {
    const u = new URL(url)
    const seg = u.pathname.split('/').filter(Boolean)[0]
    return seg && !seg.includes('.') ? `${u.host}/${seg}` : u.host
  } catch {
    return url
  }
}

/** One event from /api/v1/scout/events. */
export function applyScoutEvent(s, ev) {
  const hub = 'scout_hub'
  ensureNode(s, hub, 'Leak Scout', 'Agent', 'Runs firewalled searches and the registry crawl')
  const when = (ev.ts || 0) * 1000 || undefined
  if (ev.kind === 'query') {
    if (!s.queries.some((q) => q.query === ev.query)) s.queries.push({ query: ev.query, allowed: ev.allowed })
    addLog(s, `[Query firewall] ${ev.allowed ? 'ALLOWED' : 'BLOCKED'}: ${ev.query}`, ev.allowed ? 'info' : 'warn', when)
    return
  }
  if (ev.kind === 'search_error') {
    s.scoutError = ev.reason
    addLog(s, `[Search] failed: ${ev.reason}`, 'warn', when)
    return
  }
  if (!ev.url) return
  const site = `site_${area(ev.url)}`
  ensureNode(s, site, area(ev.url), 'Site', 'Seen during this scout run')
  if (ev.kind === 'search_hit') {
    ensureEdge(s, hub, site, 'FOUND')
    return
  }
  const refused = ev.kind === 'blocked' || ev.kind === 'robots_denied'
  ensureEdge(s, hub, site, refused ? 'BLOCKED' : 'SCRAPES', 'scrape') // web scraping is always the red flowing edge
  if (ev.kind === 'crawl_progress') {
    s.counters.pages = ev.pages ?? s.counters.pages + 1
    s.counters.images = ev.images ?? s.counters.images
    const pages = s.graphData.edges.filter((e) => e.source_node_uuid === site && e.name === 'PAGE').length
    if (pages < MAX_PAGES_PER_SITE) {
      const page = `page_${ev.url}`
      ensureNode(s, page, new URL(ev.url).pathname || '/', 'Site', ev.url)
      ensureEdge(s, site, page, 'PAGE')
    }
    addLog(s, `[Crawl] fetched ${ev.url}`, 'info', when)
  } else if (ev.kind === 'blocked' || ev.kind === 'robots_denied') {
    s.counters.blocked += 1
    addLog(s, `[Crawl] blocked ${ev.url}${ev.reason ? ` (${ev.reason})` : ' (robots.txt)'}`, 'warn', when)
  } else if (ev.kind === 'crawl_error') {
    addLog(s, `[Crawl] error on ${ev.url}`, 'warn', when)
  } else if (ev.kind === 'match') {
    const id = `match_${ev.image_url || ev.url}`
    ensureNode(s, id, `${ev.match} match`, 'Match', `${ev.verdict} on ${ev.url}`, { verdict: ev.verdict, image: ev.image_url })
    ensureEdge(s, site, id, 'MATCHED', 'scrape')
    if (s.enrolled && ev.match === 'face') {
      ensureNode(s, 'person_enrolled', 'Enrolled person', 'Person', 'Consented enrolment, held in memory only')
      ensureEdge(s, 'person_enrolled', id, 'LIKENESS')
    }
    addLog(s, `[Match] ${ev.verdict} ${ev.match} on ${ev.url}`, 'warn', when)
  }
}

/** Final discovery results split into the two lists the UI shows. */
export function applyDiscovery(s, discovery) {
  s.discovery = discovery
  s.textHits = discovery.results.filter((r) => r.match_type === 'text_search')
  s.matches = discovery.results.filter((r) => r.match_type !== 'text_search')
  s.counters.matches = s.matches.length
}

/** Report sections built only from what this case really produced. */
export function buildReport(s) {
  const sections = []
  const r = s.redaction
  if (s.job) {
    const types = Object.entries(s.detectedCounts).map(([t, n]) => `- ${t}: ${n}`).join('\n') || '- none'
    sections.push({ title: 'Document findings', content: `File: ${s.filename}\nSeverity: ${s.severity} (${s.severityScore}/100)\nLayers: ${(s.job.summary?.layers || []).join(', ')}\n\n${types}` })
  }
  if (r) {
    const checks = r.checks.map((c) => `- ${c.name}: ${c.passed ? 'PASS' : 'FAIL'}`).join('\n')
    sections.push({ title: 'Redaction and red team', content: `Status: ${r.status}\nValues redacted: ${r.selected}\nOutput SHA-256: ${r.sha256}\n\n${checks}` })
  }
  if (s.swarmResult) {
    const x = s.swarmResult
    sections.push({ title: 'Agent swarm', content: `Result: ${x.clean ? 'CLEAN' : 'NOT CLEAN'}\nCycles: ${x.cycles}\nLLM calls: ${x.llm_calls}\nTool calls: ${x.tool_calls}\nTokens: ${x.tokens}` })
  }
  if (s.discovery) {
    const rev = s.matches.map((m) => `- ${m.review || 'unreviewed'}: ${m.source_url}`).join('\n') || '- none'
    sections.push({ title: 'Leak scout', content: `Provider: ${s.discovery.provider}\nQueries: ${s.queries.length}\nText results (candidates): ${s.textHits.length}\nPages crawled: ${s.counters.pages}\n\nImage matches:\n${rev}` })
  }
  return sections
}
