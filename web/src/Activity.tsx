import { api, type Job, type Stage } from "./api.ts";

// Real pipeline stages reported by the API: name, status, duration. No simulated agent chatter.
export function Stages({ stages }: { stages: Stage[] }) {
  if (!stages.length) return <p className="muted small">Waiting for a worker…</p>;
  return (
    <ol className="stages">
      {stages.map((s, i) => (
        <li key={i} className={`st-${s.status}`}>
          <span className="dot" aria-hidden />
          <span className="name">{s.name}</span>
          <span className="status">{s.status}</span>
          {s.ms > 0 && <span className="muted small">{s.ms} ms</span>}
          {s.detail && <span className="muted small">· {s.detail}</span>}
        </li>
      ))}
    </ol>
  );
}

export function Activity({ jobs, onDeleted }: { jobs: Job[]; onDeleted: (id: string) => void }) {
  if (!jobs.length) return <section className="card"><p className="muted">No jobs yet in this browser session.</p></section>;
  return (
    <div className="grid">
      {jobs.map((j) => (
        <section className="card" key={j.id}>
          <h3>
            {j.display_name || j.kind} <span className={`pill st-${j.status}`}>{j.status}</span>
          </h3>
          <p className="muted small">{j.kind} · {j.id.slice(0, 8)} · {j.findings.length} findings{j.redaction ? ` · redaction ${j.redaction.status}` : ""}</p>
          <Stages stages={j.stages} />
          <div className="row">
            {(j.status === "queued" || j.status === "running") && <button className="ghost" onClick={() => api.cancel(j.id)}>Cancel</button>}
            <button className="ghost danger" onClick={async () => { await api.remove(j.id).catch(() => undefined); onDeleted(j.id); }}>Delete</button>
          </div>
        </section>
      ))}
    </div>
  );
}
