import { useEffect, useRef, useState } from "react";
import { api, poll, type Job } from "./api.ts";
import { Stages } from "./Activity.tsx";

const TYPES = ["IN_AADHAAR", "IN_PAN", "CREDIT_CARD", "EMAIL_ADDRESS", "MOBILE_IN", "IN_BANK_ACCOUNT"];

export function Discovery({ analysisId, onJob }: { analysisId: string | null; onJob: (j: Job) => void }) {
  const [org, setOrg] = useState("");
  const [domain, setDomain] = useState("");
  const [types, setTypes] = useState<string[]>(["IN_AADHAAR", "IN_PAN"]);
  const [crawl, setCrawl] = useState(false);
  const [linkJob, setLinkJob] = useState(true);
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState("");
  const [refs, setRefs] = useState<{ id: string; label: string }[]>([]);
  const [refFile, setRefFile] = useState<File | null>(null);
  const [refLabel, setRefLabel] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const stop = useRef<() => void>(() => {});

  useEffect(() => { api.references().then((r) => setRefs(r.references), () => undefined); return () => stop.current(); }, []);

  const start = async () => {
    setError("");
    try {
      const { id } = await api.discover({ org, domain, entity_types: types, crawl, job_id: linkJob && analysisId ? analysisId : undefined });
      stop.current();
      stop.current = poll(id, (j) => { setJob(j); onJob(j); }, (e) => setError(e.message));
    } catch (e) { setError((e as Error).message); }
  };

  const addRef = async () => {
    setError("");
    try {
      await api.addReference(refFile!, refLabel || refFile!.name);
      setRefs((await api.references()).references);
      setRefFile(null);
    } catch (e) { setError((e as Error).message); }
  };

  const d = job?.discovery;
  return (
    <div className="grid">
      <section className="card">
        <h2>Search for leaks</h2>
        <p className="muted small">Only organisation/domain context and entity <em>types</em> are used to build queries. Every query passes the privacy firewall before it is sent; values from your analysed document are blocked.</p>
        <label>Organisation<input value={org} onChange={(e) => setOrg(e.target.value)} placeholder="Acme Corp" maxLength={100} /></label>
        <label>Domain (optional)<input value={domain} onChange={(e) => setDomain(e.target.value.toLowerCase())} placeholder="acme.in" maxLength={253} /></label>
        <fieldset>
          <legend>Entity types to look for</legend>
          {TYPES.map((t) => (
            <label key={t} className="check">
              <input type="checkbox" checked={types.includes(t)} onChange={() => setTypes((x) => (x.includes(t) ? x.filter((y) => y !== t) : [...x, t]))} /> {t}
            </label>
          ))}
        </fieldset>
        <label className="check"><input type="checkbox" checked={linkJob} disabled={!analysisId} onChange={(e) => setLinkJob(e.target.checked)} /> Block values from my current analysis in queries</label>
        <label className="check"><input type="checkbox" checked={crawl} onChange={(e) => setCrawl(e.target.checked)} /> Also crawl configured registry sites for my reference images (PDQ)</label>
        <div className="row">
          <button className="primary" disabled={org.trim().length < 2} onClick={start}>Start discovery</button>
          {job && (job.status === "running" || job.status === "queued") && <button className="ghost" onClick={() => api.cancel(job.id)}>Cancel</button>}
        </div>
        {error && <div className="banner error">{error}</div>}
        {job && <Stages stages={job.stages} />}
      </section>

      <section className="card">
        <h2>Reference images</h2>
        <p className="muted small">Images you are authorised to match (e.g. your own leaked ID scan). Only PDQ hashes are kept; the image is discarded. Matching is perceptual, not face recognition.</p>
        <input type="file" accept=".png,.jpg,.jpeg" aria-label="Reference image" onChange={(e) => setRefFile(e.target.files?.[0] ?? null)} />
        <label>Label<input value={refLabel} onChange={(e) => setRefLabel(e.target.value)} maxLength={60} /></label>
        <label className="check"><input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} /> I am authorised to use this image for matching</label>
        <button disabled={!refFile || !authorized} onClick={addRef}>Add reference</button>
        <ul>{refs.map((r) => <li key={r.id}>{r.label}</li>)}</ul>
      </section>

      {d && (
        <section className="card wide">
          <h2>Where candidate content appeared <span className="muted">via {d.provider}</span></h2>
          {d.provider === "offline" && <div className="banner">Offline provider: these are bundled demo fixtures, not live web results. Configure Brave or Google Programmable Search for live discovery.</div>}
          <details>
            <summary>{d.queries.length} queries ({d.queries.filter((q) => !q.allowed).length} blocked by firewall)</summary>
            <ul className="mono small">{d.queries.map((q) => <li key={q.query}>{q.allowed ? "sent" : "BLOCKED"} · {q.query}</li>)}</ul>
          </details>
          {d.crawl && <p className="muted small">Crawl: {Object.entries(d.crawl).map(([k, v]) => `${k} ${v}`).join(" · ")}</p>}
          {d.results.length === 0 ? <p>No candidates found.</p> : (
            <div className="table-wrap">
              <table className="findings">
                <thead><tr><th>Status</th><th>Source</th><th>Excerpt (masked)</th><th>Match</th><th>Seen</th></tr></thead>
                <tbody>
                  {d.results.map((r, i) => (
                    <tr key={i}>
                      <td><span className={`pill ${r.evidence_status.startsWith("confirmed") ? "bad" : ""}`}>{r.evidence_status}</span></td>
                      <td><a href={r.source_url} target="_blank" rel="noopener noreferrer nofollow">{r.title || r.source_url}</a><div className="muted small">{r.source_url}</div></td>
                      <td className="small">{r.excerpt}</td>
                      <td className="small">{r.match_type}{r.score !== null ? ` (d=${r.score})` : ""}</td>
                      <td className="small">{r.timestamp}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
