// Client for the Shield·Scout API. All calls are same-origin /api/*.
async function call(path, init = {}, retry = true) {
  const headers = new Headers(init.headers)
  if (typeof init.body === 'string') headers.set('Content-Type', 'application/json')
  const res = await fetch(path, { ...init, headers })
  if (res.status === 401 && retry) {
    const token = window.prompt('This server needs its access token:')
    if (token) {
      await fetch('/api/auth', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: json({ token }) })
      return call(path, init, false)
    }
  }
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = typeof body.detail === 'string' ? body.detail : body.detail.map((d) => `${d.loc.at(-1)}: ${d.msg}`).join('; ')
    } catch { /* non-JSON error body */ }
    throw new Error(detail)
  }
  return res.json()
}

const json = (body) => JSON.stringify(body)
const post = (path, body) => call(path, { method: 'POST', body: body === undefined ? undefined : json(body) })
const form = (path, fields) => {
  const f = new FormData()
  for (const [k, v] of Object.entries(fields)) f.append(k, v)
  return call(path, { method: 'POST', body: f })
}
const q = encodeURIComponent

export const api = {
  config: () => call('/api/config'),
  submitFile: (file) => form('/api/jobs', { file }),
  submitText: (text) => form('/api/jobs', { text }),
  job: (id) => call(`/api/jobs/${id}`),
  redact: (id, selections) => post(`/api/jobs/${id}/redact`, { selections }),
  downloadUrl: (id) => `/api/jobs/${id}/download`,
  previewImageUrl: (id, sha) => `/api/jobs/${id}/preview.png?v=${sha}`,
  clearSession: () => call('/api/session', { method: 'DELETE' }),
  discover: (body) => post('/api/discovery', body),
  addReference: (file, label) => form('/api/references', { file, label, authorized: 'true' }),
  references: () => call('/api/references'),
  registry: () => call('/api/v1/scout/registry'),
  enroll: (photo, selfie) => {
    const f = new FormData()
    f.append('photo', photo)
    f.append('selfie', selfie, 'selfie.jpg')
    f.append('consent', 'true')
    return call('/api/v1/scout/enroll', { method: 'POST', body: f })
  },
  unenroll: () => call('/api/v1/scout/enroll', { method: 'DELETE' }),
  review: (job_id, match_id, decision) => post('/api/v1/scout/review', { job_id, match_id, decision }),
  ledger: (id) => call(`/api/v1/ledger?job_id=${q(id)}`),
  tamperDemo: (id) => post(`/api/v1/ledger/tamper-demo?job_id=${q(id)}`),
  dossierUrl: (id) => `/api/v1/dossier/export?job_id=${q(id)}`,
  swarmRun: (job_id) => post('/api/v1/swarm/run', { job_id }),
  swarmEventsUrl: (id) => `/api/v1/swarm/events?job_id=${q(id)}`,
  scoutEventsUrl: (id) => `/api/v1/scout/events?job_id=${q(id)}`,
  deliberateUrl: (id) => `/api/v1/swarm/deliberate?job_id=${q(id)}`,
  llm: () => call('/api/llm'),
  setLlm: (body) => call('/api/llm', { method: 'PUT', body: json(body) }),
  testLlm: () => post('/api/llm/test')
}
