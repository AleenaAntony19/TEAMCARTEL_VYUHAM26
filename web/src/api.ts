// Typed client for the Shield·Scout API (shield/api/server.py). All calls are same-origin /api/*.

export type Severity = "critical" | "high" | "medium" | "low";
export type Action = "token" | "mask" | "remove";

export interface Check { reviewer: string; rule: string; passed: boolean; evidence: string }
export interface Finding {
  id: string; type: string; severity: Severity; confidence: number; layer: string;
  location: { layer: string; start?: number; end?: number; where?: string; bbox?: string | null };
  masked: string; evidence: string; analyzer: string; checks: Check[]; recommendation: string; actions: Action[];
  opinions?: { persona: string; stance: "redact" | "keep" | "unsure"; reason: string }[];
}
export interface Stage { name: string; status: string; detail: string; ms: number }
export interface AttackCheck { name: string; passed: boolean; evidence: string[] }
export interface Redaction {
  status: "CLEAN" | "FAILED"; checks: AttackCheck[]; retried_aggressive: boolean; selected: number;
  output_name: string; sha256: string; preview_text: string; has_preview_image: boolean; note: string;
}
export interface DiscoveryResult {
  source_url: string; image_url?: string; title: string; excerpt: string; timestamp: string;
  match_type: string; score: number | null; evidence_status: string; provider?: string; query?: string;
}
export interface Discovery {
  provider: string; queries: { query: string; allowed: boolean }[]; results: DiscoveryResult[];
  crawl: Record<string, number | string> | null;
}
export interface Job {
  id: string; kind: "analysis" | "discovery"; status: "queued" | "running" | "ready" | "failed" | "cancelled";
  display_name: string; input_type: string; stages: Stage[]; findings: Finding[];
  redaction: Redaction | null; discovery: Discovery | null; error: string;
}
export interface LLMState {
  provider: "none" | "groq" | "anthropic"; model: string; endpoint: string; timeout: number; retries: number;
  key_set: boolean; local_only?: boolean; providers?: string[];
}
export interface Config {
  local_only: boolean; search_provider: string; face_regions: boolean; data_leaving_machine: string[]; llm: LLMState;
  limits: { max_upload_mb: number; max_text_chars: number; max_pdf_pages: number; allowed: string[]; job_ttl_seconds: number;
    max_concurrent_jobs: number; crawl_max_pages: number; crawl_max_depth: number };
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) { super(message); this.status = status; }
}

let token = "";
export const setToken = (t: string) => { token = t; };

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && typeof init.body === "string") headers.set("Content-Type", "application/json");
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch { /* non-JSON error body */ }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

const json = (body: unknown) => JSON.stringify(body);

export const api = {
  config: () => call<Config>("/api/config"),
  submitText: (text: string) => { const f = new FormData(); f.append("text", text); return call<{ id: string }>("/api/jobs", { method: "POST", body: f }); },
  submitFile: (file: File) => { const f = new FormData(); f.append("file", file); return call<{ id: string }>("/api/jobs", { method: "POST", body: f }); },
  job: (id: string) => call<Job>(`/api/jobs/${id}`),
  cancel: (id: string) => call(`/api/jobs/${id}/cancel`, { method: "POST" }),
  remove: (id: string) => call(`/api/jobs/${id}`, { method: "DELETE" }),
  clearSession: () => call<{ cleared_jobs: number }>("/api/session", { method: "DELETE" }),
  preview: (id: string, selections: { finding_id: string; action: Action }[]) =>
    call<{ preview_text?: string; plan?: { finding_id: string; type: string; layer: string; masked: string; replacement: string }[]; note?: string }>(
      `/api/jobs/${id}/redact`, { method: "POST", body: json({ selections, dry_run: true }) }),
  redact: (id: string, selections: { finding_id: string; action: Action }[]) =>
    call<Redaction>(`/api/jobs/${id}/redact`, { method: "POST", body: json({ selections }) }),
  fingerprint: (id: string) => call<{ pdq: { hex: string; quality: number; region: string }[]; note: string }>(`/api/jobs/${id}/fingerprint`, { method: "POST" }),
  downloadUrl: (id: string) => `/api/jobs/${id}/download`,
  previewImageUrl: (id: string) => `/api/jobs/${id}/preview.png`,
  discover: (body: { org: string; domain: string; entity_types: string[]; crawl: boolean; job_id?: string }) =>
    call<{ id: string }>("/api/discovery", { method: "POST", body: json(body) }),
  addReference: (file: File, label: string) => {
    const f = new FormData(); f.append("file", file); f.append("label", label); f.append("authorized", "true");
    return call<{ id: string; stored: string }>("/api/references", { method: "POST", body: f });
  },
  references: () => call<{ references: { id: string; label: string }[]; hash_rows: number }>("/api/references"),
  swarmRun: (job_id: string) => call<{ status: string }>("/api/v1/swarm/run", { method: "POST", body: json({ job_id }) }),
  swarmEventsUrl: (job_id: string) => `/api/v1/swarm/events?job_id=${encodeURIComponent(job_id)}`,
  scoutEventsUrl: (job_id: string) => `/api/v1/scout/events?job_id=${encodeURIComponent(job_id)}`,
  llm: () => call<LLMState>("/api/llm"),
  setLlm: (body: { provider: string; model: string; endpoint: string; api_key: string; timeout: number; retries: number }) =>
    call<LLMState>("/api/llm", { method: "PUT", body: json(body) }),
  testLlm: () => call<{ ok: boolean; latency_ms?: number; error?: string; model: string }>("/api/llm/test", { method: "POST" }),
  explain: (job_id: string, finding_id: string) =>
    call<{ explanation: string; provider: string; model: string; sent_fields: string[] }>("/api/llm/explain", { method: "POST", body: json({ job_id, finding_id }) }),
};

// Poll a job until it leaves queued/running. Returns a stop function.
export function poll(id: string, onUpdate: (j: Job) => void, onError: (e: Error) => void, everyMs = 600): () => void {
  let stopped = false;
  const tick = async () => {
    if (stopped) return;
    try {
      const j = await api.job(id);
      onUpdate(j);
      // keep polling while background stages (e.g. AI personas) are still running after the job is ready
      if (j.status === "queued" || j.status === "running" || j.stages.some((s) => s.status === "running")) setTimeout(tick, everyMs);
    } catch (e) { onError(e as Error); }
  };
  tick();
  return () => { stopped = true; };
}

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

// Default selection: everything medium+ that has an action, using the safest available action.
export function defaultSelection(findings: Finding[]): Record<string, Action> {
  const out: Record<string, Action> = {};
  for (const f of findings) {
    if (!f.actions.length || SEVERITY_ORDER[f.severity] > 2) continue;
    out[f.id] = f.actions.includes("token") ? "token" : f.actions[0];
  }
  return out;
}
