import { useEffect, useState } from "react";
import { api, type Config, type Job } from "./api.ts";
import { Analyze } from "./Analyze.tsx";
import { Discovery } from "./Discovery.tsx";
import { Activity } from "./Activity.tsx";
import { Provider } from "./Provider.tsx";

const TABS = ["Analyze & redact", "Discovery", "Activity", "AI provider", "Privacy"] as const;
type Tab = (typeof TABS)[number];

export function App() {
  const [tab, setTab] = useState<Tab>("Analyze & redact");
  const [config, setConfig] = useState<Config | null>(null);
  const [configError, setConfigError] = useState("");
  const [jobs, setJobs] = useState<Record<string, Job>>({});
  const [analysisId, setAnalysisId] = useState<string | null>(null);

  const refreshConfig = () => api.config().then(setConfig, (e: Error) => setConfigError(e.message));
  useEffect(() => { refreshConfig(); }, []);

  const track = (j: Job) => setJobs((prev) => ({ ...prev, [j.id]: j }));

  const clearAll = async () => {
    if (!confirm("Delete every job, upload, sanitized output and reference hash in this session, and forget any API key set here?")) return;
    await api.clearSession();
    setJobs({});
    setAnalysisId(null);
    refreshConfig();
  };

  return (
    <div className="shell">
      <header className="top">
        <div className="brand">
          <span className="logo" aria-hidden>◈</span>
          <div>
            <h1>Shield·Scout</h1>
            <p className="muted">Find, redact and verify sensitive data. Discover where it surfaced.</p>
          </div>
        </div>
        <div className="top-actions">
          {config && (
            <span className={`pill ${config.local_only ? "ok" : ""}`} title={config.data_leaving_machine.join("\n")}>
              {config.local_only ? "Local-only mode" : `LLM: ${config.llm.provider}`}
            </span>
          )}
          <button className="ghost danger" onClick={clearAll}>Clear session data</button>
        </div>
      </header>

      {configError && <div className="banner error">API unreachable: {configError}. Start it with <code>python -m shield.api</code>.</div>}

      <nav className="tabs" role="tablist">
        {TABS.map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? "active" : ""} onClick={() => setTab(t)}>
            {t}
          </button>
        ))}
      </nav>

      <main>
        {tab === "Analyze & redact" && <Analyze config={config} jobId={analysisId} setJobId={setAnalysisId} onJob={track} />}
        {tab === "Discovery" && <Discovery analysisId={analysisId} onJob={track} />}
        {tab === "Activity" && <Activity jobs={Object.values(jobs)} onDeleted={(id) => setJobs(({ [id]: _, ...rest }) => rest)} />}
        {tab === "AI provider" && <Provider onChange={refreshConfig} />}
        {tab === "Privacy" && config && <Privacy config={config} />}
      </main>
    </div>
  );
}

function Privacy({ config }: { config: Config }) {
  const l = config.limits;
  return (
    <section className="card">
      <h2>What leaves this machine</h2>
      <ul>{config.data_leaving_machine.map((d) => <li key={d}>{d}</li>)}</ul>
      <p className="muted">
        Deterministic detection, redaction and verification run locally. Raw uploads stay in an isolated temp folder (mode 0700)
        and are deleted when you delete the job, clear the session, or after {Math.round(l.job_ttl_seconds / 60)} minutes.
        Face handling is region detection only (to remove photos); no identification is performed.
      </p>
      <h2>Limits</h2>
      <table className="kv">
        <tbody>
          <tr><th>Upload size</th><td>{l.max_upload_mb} MB</td></tr>
          <tr><th>Pasted text</th><td>{l.max_text_chars.toLocaleString()} characters</td></tr>
          <tr><th>PDF pages</th><td>{l.max_pdf_pages}</td></tr>
          <tr><th>File types</th><td>{l.allowed.join(", ")}</td></tr>
          <tr><th>Concurrent jobs</th><td>{l.max_concurrent_jobs}</td></tr>
          <tr><th>Crawl</th><td>{l.crawl_max_pages} pages, depth {l.crawl_max_depth}, registry domains only, robots.txt honoured</td></tr>
          <tr><th>Search provider</th><td>{config.search_provider}</td></tr>
        </tbody>
      </table>
    </section>
  );
}
