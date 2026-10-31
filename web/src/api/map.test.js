import { test } from 'node:test'
import assert from 'node:assert/strict'
import { applyAgentEvent, applyDeliberation, applyDiscovery, applyJob, applyScoutEvent, applySwarmResult, area, buildReport, defaultSelection } from './map.js'

const state = () => ({ systemLogs: [], graphData: { nodes: [], edges: [] }, agents: [], deliberationLogs: [], queries: [], textHits: [], matches: [],
  counters: { pages: 0, images: 0, blocked: 0, matches: 0 }, detectedCounts: {}, stagesSeen: 0 })
const job = { id: 'j', display_name: 'a.pdf', input_type: 'pdf', status: 'ready', stages: [{ name: 'intake', status: 'done', detail: '' }],
  summary: { severity: 'HIGH', score: 80, layers: ['visible'] }, redaction: null,
  findings: [{ id: '1', type: 'IN_PAN', severity: 'high', actions: ['mask', 'token'] }, { id: '2', type: 'IN_PAN', severity: 'low', actions: ['token'] }, { id: '3', type: 'FACE', severity: 'high', actions: ['remove'] }] }

test('job maps to counts, graph and a safe default selection, and polling twice adds nothing', () => {
  const s = state()
  applyJob(s, job)
  applyJob(s, job)
  assert.deepEqual(s.detectedCounts, { IN_PAN: 2, FACE: 1 })
  assert.equal(s.graphData.nodes.length, 3)
  assert.equal(s.graphData.edges.length, 2)
  assert.equal(s.systemLogs.length, 1)
  assert.deepEqual(s.selection, { 1: 'token', 3: 'remove' })
  assert.deepEqual(defaultSelection([{ id: 'x', severity: 'medium', actions: [] }]), {})
  assert.deepEqual(defaultSelection([{ id: 'n', type: 'PERSON', severity: 'low', actions: ['token'] }]), { n: 'token' })
})

test('agent events build cards and links; totals arrive at the end; "swarm" is not an agent', () => {
  const s = state()
  applyJob(s, job)
  applyAgentEvent(s, { agent: 'swarm', event: 'round', round: 1 })
  assert.equal(s.agents.length, 0)
  applyAgentEvent(s, { agent: 'MetaPlanner', event: 'spawn', child: 'SovereignPIIAgent' })
  applyAgentEvent(s, { agent: 'PrivacyHawk', event: 'tool', action: 'list_findings', observation: 'x' })
  applyAgentEvent(s, { agent: 'PrivacyHawk', event: 'final' })
  applyAgentEvent(s, { agent: 'PragmaticDev', event: 'error', error: '429' })
  assert.ok(s.graphData.edges.some((e) => e.name === 'DELIBERATES' && e.target_node_uuid === 'agent_SwarmAdjudicator'))
  assert.equal(s.agents.find((a) => a.name === 'PragmaticDev').state, 'error')
  applySwarmResult(s, { agents: [{ name: 'PrivacyHawk', steps: 2, tokens: 900, children: [] }] })
  assert.equal(s.agents.find((a) => a.name === 'PrivacyHawk').tokens, 900)
})

test('scrape edges are red kind, blocks and matches count, failures surface', () => {
  const s = state()
  applyScoutEvent(s, { kind: 'query', query: 'q', allowed: false })
  applyScoutEvent(s, { kind: 'search_error', reason: 'bad key' })
  applyScoutEvent(s, { kind: 'crawl_progress', url: 'http://h:1/forum/a.html', pages: 3, images: 2 })
  applyScoutEvent(s, { kind: 'blocked', url: 'http://h:1/x/', reason: 'http_403' })
  applyScoutEvent(s, { kind: 'match', url: 'http://h:1/g/', image_url: 'http://h:1/g/i.jpg', match: 'pdq', verdict: 'confirmed' })
  assert.deepEqual(s.queries, [{ query: 'q', allowed: false }])
  assert.equal(s.scoutError, 'bad key')
  assert.equal(s.counters.pages, 3)
  assert.equal(s.counters.blocked, 1)
  assert.ok(s.graphData.edges.some((e) => e.kind === 'scrape' && e.name === 'SCRAPES'))
  applyDiscovery(s, { provider: 'serper', results: [{ match_type: 'text_search' }, { match_type: 'pdq:full', source_url: 'u' }] })
  assert.equal(s.counters.matches, 1)
  applyDiscovery(s, { provider: 'serper', crawl: { pages: 9, images: 380 }, results: [] })
  assert.equal(s.counters.images, 380)
  assert.equal(area('https://a.com/forum/t/1'), 'a.com/forum')
  assert.equal(area('https://a.com/x.html'), 'a.com')
})

test('ai_lead links the hub to the site without a scrape edge; ai_triage only logs', () => {
  const s = state()
  applyScoutEvent(s, { kind: 'ai_lead', url: 'https://a.com/forum/t/1', why: 'exposed scans' })
  applyScoutEvent(s, { kind: 'ai_lead', url: 'https://b.com/', why: '' })
  applyScoutEvent(s, { kind: 'ai_triage', read: 12, picked: 2, tokens: 340 })
  assert.deepEqual(s.graphData.edges.map((e) => [e.source_node_uuid, e.target_node_uuid, e.name, e.kind]),
    [['scout_hub', 'site_a.com/forum', 'LEAD', 'rel'], ['scout_hub', 'site_b.com', 'LEAD', 'rel']])
  assert.equal(s.systemLogs[0].msg, '[AI lead] https://a.com/forum/t/1 (exposed scans)')
  assert.equal(s.systemLogs[1].msg, '[AI lead] https://b.com/')
  assert.equal(s.systemLogs[2].msg, '[AI triage] read 12, picked 2, 340 tokens')
})

test('AI-picked hits come first in their own order; the report gives AI numbers only when used', () => {
  const s = state()
  const results = [{ source_url: 'a', match_type: 'text_search' }, { source_url: 'b', match_type: 'text_search', ai_why: 'x' }, { source_url: 'c', match_type: 'text_search' }, { source_url: 'd', match_type: 'text_search', ai_why: 'y' }]
  applyDiscovery(s, { provider: 'serper', results, ai: { used: true, calls: 1, tokens: 340, read: 12, leads: 2 } })
  assert.deepEqual(s.textHits.map((r) => r.source_url), ['b', 'd', 'a', 'c'])
  assert.deepEqual(results.map((r) => r.source_url), ['a', 'b', 'c', 'd'])
  assert.match(buildReport(s).at(-1).content, /AI read: 12\nAI leads: 2\nAI tokens: 340/)
  applyDiscovery(s, { provider: 'serper', results, ai: { used: false, calls: 0, tokens: 0, read: 0, leads: 0 } })
  assert.doesNotMatch(buildReport(s).at(-1).content, /AI /)
  applyDiscovery(s, { provider: 'serper', results })
  assert.doesNotMatch(buildReport(s).at(-1).content, /AI /)
})

test('each site agent appears as a spawned node that owns its scrape edge', () => {
  const s = state()
  applyScoutEvent(s, { kind: 'site_agent', site: 'forum@h', status: 'spawned' })
  applyScoutEvent(s, { kind: 'crawl_progress', url: 'http://h:1/forum/a.html', pages: 1, images: 0, site: 'forum@h' })
  applyScoutEvent(s, { kind: 'site_agent', site: 'forum@h', status: 'done', pages: 1, images: 0 })
  assert.equal(s.siteAgents['forum@h'], 'done')
  assert.ok(s.graphData.edges.some((e) => e.source_node_uuid === 'scout_hub' && e.target_node_uuid === 'siteagent_forum@h' && e.name === 'SPAWNED'))
  assert.ok(s.graphData.edges.some((e) => e.source_node_uuid === 'siteagent_forum@h' && e.kind === 'scrape'))
})

test('deliberation groups turns per entity; the report only states what happened', () => {
  const s = state()
  assert.deepEqual(buildReport(s), [])
  applyJob(s, job)
  applyDeliberation(s, { event: 'turn', entity: 0, type: 'IN_PAN', masked: 'A…F', reviewer: 'r', rule: 'pan', passed: true, evidence: 'e' })
  applyDeliberation(s, { event: 'verdict', entity: 0, verdict: 'confirmed', confidence: 0.9 })
  assert.equal(s.deliberationLogs[0].turns.length, 1)
  assert.equal(s.deliberationLogs[0].verdict, 'confirmed')
  assert.deepEqual(buildReport(s).map((x) => x.title), ['Document findings'])
})
