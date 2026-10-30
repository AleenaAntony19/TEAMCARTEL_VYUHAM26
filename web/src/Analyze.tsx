import { useEffect, useMemo, useRef, useState } from "react";
import { api, defaultSelection, poll, type Action, type Config, type Finding, type Job, type Redaction } from "./api.ts";
import { Stages } from "./Activity.tsx";

interface Props { config: Config | null; jobId: string | null; setJobId: (id: string | null) => void; onJob: (j: Job) => void }

export function Analyze({ config, jobId, setJobId, onJob }: Props) {
  const [mode, setMode] = useState<"text" | "file">("text");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const stop = useRef<() => void>(() => {});

  const watch = (id: string) => {
    stop.current();
    stop.current = poll(id, (j) => { setJob(j); onJob(j); }, (e) => setError(e.message));
  };
  // resume polling the job the parent remembers when this tab remounts
  useEffect(() => { if (jobId) watch(jobId); return () => stop.current(); }, []);

  const maxMb = config?.limits.max_upload_mb ?? 25;
  const tooBig = !!file && file.size > maxMb * 1024 * 1024;

  const submit = async () => {
    setError("");
    setBusy(true);
    try {
      const { id } = mode === "text" ? await api.submitText(text) : await api.submitFile(file!);
      setJobId(id);
      watch(id);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const running = job?.status === "queued" || job?.status === "running";

  return (
    <div className="grid">
      <section className="card">
        <h2>1 · Submit</h2>
        <div className="seg" role="radiogroup">
          <button aria-pressed={mode === "text"} onClick={() => setMode("text")}>Paste text</button>
          <button aria-pressed={mode === "file"} onClick={() => setMode("file")}>Upload file</button>
        </div>
        {mode === "text" ? (
          <>
            <textarea value={text} onChange={(e) => setText(e.target.value)} rows={8} placeholder="Paste text to scan…" aria-label="Text to scan" maxLength={config?.limits.max_text_chars} />
            <p className="muted small">{text.length.toLocaleString()} / {(config?.limits.max_text_chars ?? 0).toLocaleString()} characters</p>
          </>
        ) : (
          <>
            <input type="file" aria-label="File to scan" accept={config?.limits.allowed.join(",")} onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            <p className={`small ${tooBig ? "error-text" : "muted"}`}>
              {config ? `${config.limits.allowed.join(", ")} · up to ${maxMb} MB · PDFs up to ${config.limits.max_pdf_pages} pages` : ""}
              {tooBig && " · this file is too large"}
            </p>
          </>
        )}
        <div className="row">
          <button className="primary" disabled={busy || running || (mode === "text" ? !text.trim() : !file || tooBig)} onClick={submit}>
            {busy ? "Uploading…" : "Analyze"}
          </button>
          {job && running && <button className="ghost" onClick={() => api.cancel(job.id)}>Cancel</button>}
          {job && !running && (
            <button className="ghost danger" onClick={async () => { await api.remove(job.id); stop.current(); setJob(null); setJobId(null); }}>
              Delete job &amp; files
            </button>
          )}
        </div>
        {error && <div className="banner error">{error}</div>}
        {job && (
          <>
            <h3>Progress <span className={`pill st-${job.status}`}>{job.status}</span></h3>
            <Stages stages={job.stages} />
            {job.error && <p className="error-text small">Failed in stage processing ({job.error}).</p>}
          </>
        )}
      </section>

      {job?.status === "ready" && job.kind === "analysis" && <Review key={job.id} job={job} />}
    </div>
  );
}

function Review({ job }: { job: Job }) {
  const [sel, setSel] = useState<Record<string, Action>>(() => defaultSelection(job.findings));
  const [preview, setPreview] = useState<Awaited<ReturnType<typeof api.preview>> | null>(null);
  const [result, setResult] = useState<Redaction | null>(job.redaction);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [explained, setExplained] = useState<Record<string, string>>({});
  const [fp, setFp] = useState<Awaited<ReturnType<typeof api.fingerprint>> | null>(null);

  const selections = useMemo(() => Object.entries(sel).map(([finding_id, action]) => ({ finding_id, action })), [sel]);
  useEffect(() => setPreview(null), [selections]); // a preview is only valid for the selection it was made from
  const toggle = (f: Finding) => setSel(({ [f.id]: had, ...rest }) => (had ? rest : { ...rest, [f.id]: f.actions[0] }));
  const run = async (fn: () => Promise<void>) => {
    setError(""); setBusy(true);
    try { await fn(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  };
  const isImage = ["png", "jpg", "jpeg"].includes(job.input_type);

  return (
    <>
      <section className="card wide">
        <h2>2 · Review findings <span className="muted">({job.findings.length})</span></h2>
        {job.findings.length === 0 ? (
          <p>No sensitive data detected by the enabled analyzers. That is not proof the content is safe; see the analyzer list in Activity.</p>
        ) : (
          <div className="table-wrap">
            <table className="findings">
              <thead>
                <tr><th aria-label="Select" /><th>Type</th><th>Severity</th><th>Confidence</th><th>Where</th><th>Evidence (masked)</th><th>Action</th></tr>
              </thead>
              <tbody>
                {job.findings.map((f) => (
                  <tr key={f.id} className={sel[f.id] ? "selected" : ""}>
                    <td><input type="checkbox" aria-label={`Select ${f.type}`} disabled={!f.actions.length} checked={!!sel[f.id]} onChange={() => toggle(f)} /></td>
                    <td>
                      <strong>{f.type}</strong>
                      <div className="muted small">{f.analyzer}</div>
                    </td>
                    <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
                    <td>{Math.round(f.confidence * 100)}%</td>
                    <td className="small">{f.location.where ?? `${f.layer}${f.location.start !== undefined ? ` @${f.location.start}` : ""}`}</td>
                    <td>
                      <code className="ev">{f.evidence || f.masked}</code>
                      <details className="small">
                        <summary>Why &amp; checks</summary>
                        <p>{f.recommendation}</p>
                        <ul>{f.checks.map((c, i) => <li key={i}>{c.passed ? "✓" : "✗"} <b>{c.reviewer}</b> · {c.rule}: {c.evidence}</li>)}</ul>
                        {explained[f.id] ? <p className="llm">{explained[f.id]}<br /><span className="muted">AI explanation: advice, not evidence.</span></p> : (
                          <button className="link" onClick={() => run(async () => { const r = await api.explain(job.id, f.id); setExplained((x) => ({ ...x, [f.id]: r.explanation })); })}>
                            Explain with AI (sends type and masked evidence only)
                          </button>
                        )}
                      </details>
                    </td>
                    <td>
                      {f.actions.length === 0 ? <span className="muted small">not supported</span> : (
                        <select aria-label={`Action for ${f.type}`} value={sel[f.id] ?? f.actions[0]} disabled={!sel[f.id]}
                          onChange={(e) => setSel((s) => ({ ...s, [f.id]: e.target.value as Action }))}>
                          {f.actions.map((a) => <option key={a} value={a}>{a === "remove" && f.actions.length === 1 ? "remove (opaque fill)" : a}</option>)}
                        </select>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="row">
          <button disabled={!selections.length || busy} onClick={() => run(async () => { setPreview(await api.preview(job.id, selections)); setResult(null); })}>
            Preview changes
          </button>
          <button className="primary" disabled={!preview || busy} onClick={() => run(async () => setResult(await api.redact(job.id, selections)))}>
            {busy ? "Working…" : "Apply & verify"}
          </button>
          {isImage && <button className="ghost" onClick={() => run(async () => setFp(await api.fingerprint(job.id)))}>Compute PDQ fingerprint</button>}
        </div>
        <p className="muted small">Token = <code>[REDACTED-TYPE]</code>, mask = same-length <code>X</code>s, remove = deleted. PDFs and images always use an opaque fill that destroys the underlying text/pixels.</p>
        {error && <div className="banner error">{error}</div>}
        {fp && (
          <div className="banner">
            <strong>{fp.note}</strong>
            <ul className="mono small">{fp.pdq.map((r) => <li key={r.region + r.hex}>{r.region}: {r.hex} (q={r.quality})</li>)}</ul>
          </div>
        )}
      </section>

      {preview && !result && (
        <section className="card wide">
          <h2>3 · Preview (nothing written yet)</h2>
          {preview.preview_text !== undefined ? <pre className="preview">{preview.preview_text}</pre> : (
            <>
              <table className="kv"><tbody>
                {preview.plan?.map((p) => <tr key={p.finding_id}><th>{p.type} <span className="muted">({p.layer})</span></th><td><code>{p.masked || "region"}</code> → {p.replacement || <em>removed</em>}</td></tr>)}
              </tbody></table>
              <p className="muted small">{preview.note}</p>
            </>
          )}
        </section>
      )}

      {result && (
        <section className="card wide">
          <h2>4 · Verification <span className={`pill ${result.status === "CLEAN" ? "ok" : "bad"}`}>{result.status}</span></h2>
          <ul className="checks">
            {result.checks.map((c) => (
              <li key={c.name} className={c.passed ? "pass" : "fail"}>
                {c.passed ? "PASS" : "FAIL"} · {c.name.replace("_", " ")} {c.evidence.length > 0 && <span className="muted">: {c.evidence.join("; ")}</span>}
              </li>
            ))}
          </ul>
          {result.retried_aggressive && <p className="muted small">First pass failed a check; an aggressive pass (rasterize/raw-byte replace) was run and re-verified.</p>}
          {result.status === "CLEAN" ? (
            <a className="button primary" href={api.downloadUrl(job.id)} download>Download {result.output_name}</a>
          ) : (
            <div className="banner error">Not verified clean, so the download is withheld. Adjust selections or sanitize manually.</div>
          )}
          <p className="muted small">SHA-256 <code className="hash">{result.sha256}</code>. {result.note}</p>
          <div className="previews">
            {result.has_preview_image && <img src={`${api.previewImageUrl(job.id)}?t=${result.sha256.slice(0, 8)}`} alt="Sanitized output, first page" />}
            <pre className="preview" aria-label="Text extracted from the sanitized output">{result.preview_text || "(no extractable text)"}</pre>
          </div>
        </section>
      )}
    </>
  );
}
