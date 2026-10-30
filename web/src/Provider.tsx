import { useEffect, useState } from "react";
import { api, type LLMState } from "./api.ts";

const PRESETS = {
  groq: { label: "Groq", note: "Development: fast hosted open models.", model: "llama-3.3-70b-versatile" },
  anthropic: { label: "Anthropic Claude", note: "Production: Claude via the Anthropic API.", model: "claude-haiku-5-5" },
} as const;

// "AI provider" tab: connect Groq or Claude. The key is sent once to the local API, kept in memory only, never shown again.
export function Provider({ onChange }: { onChange: () => void }) {
  const [state, setState] = useState<LLMState | null>(null);
  const [provider, setProvider] = useState<"none" | "groq" | "anthropic">("none");
  const [model, setModel] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [key, setKey] = useState("");
  const [timeout, setTimeoutS] = useState(20);
  const [retries, setRetries] = useState(2);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = (s: LLMState) => {
    setState(s); setProvider(s.provider); setModel(s.model); setEndpoint(s.endpoint); setTimeoutS(s.timeout); setRetries(s.retries);
  };
  useEffect(() => { api.llm().then(load, (e: Error) => setMsg({ ok: false, text: e.message })); }, []);

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const s = await api.setLlm({ provider, model, endpoint, api_key: key, timeout, retries });
      load(s); setKey(""); onChange();
      setMsg({ ok: true, text: provider === "none" ? "AI explanations disabled." : `Saved. Key ${s.key_set ? "is set" : "is NOT set"}.` });
    } catch (e) { setMsg({ ok: false, text: (e as Error).message }); } finally { setBusy(false); }
  };
  const test = async () => {
    setBusy(true); setMsg(null);
    try {
      const r = await api.testLlm();
      setMsg(r.ok ? { ok: true, text: `Connected to ${r.model} in ${r.latency_ms} ms.` } : { ok: false, text: r.error ?? "failed" });
    } catch (e) { setMsg({ ok: false, text: (e as Error).message }); } finally { setBusy(false); }
  };

  if (!state) return <section className="card"><p className="muted">Loading…</p>{msg && <div className="banner error">{msg.text}</div>}</section>;
  if (state.local_only) return <section className="card"><h2>AI provider</h2><p>Local-only mode is on (<code>SHIELD_LOCAL_ONLY=1</code>): remote LLMs are disabled. All detection still works.</p></section>;

  return (
    <section className="card">
      <h2>AI provider</h2>
      <p className="muted">Optional. Used only for plain-language explanations and extra discovery queries. Detection, redaction and verification never depend on it.</p>
      <div className="providers" role="radiogroup" aria-label="Provider">
        {(["none", "groq", "anthropic"] as const).map((p) => (
          <button key={p} role="radio" aria-checked={provider === p} className={`provider ${provider === p ? "active" : ""}`}
            onClick={() => { setProvider(p); if (p !== "none") { setModel(PRESETS[p].model); setEndpoint(""); } }}>
            <strong>{p === "none" ? "None" : PRESETS[p].label}</strong>
            <span className="muted small">{p === "none" ? "Deterministic analyzers only." : PRESETS[p].note}</span>
          </button>
        ))}
      </div>
      {provider !== "none" && (
        <div className="form">
          <label>API key
            <input type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)}
              placeholder={state.key_set && state.provider === provider ? "•••••• (set; leave blank to keep)" : provider === "groq" ? "gsk_…" : "sk-ant-…"} />
          </label>
          <label>Model<input value={model} onChange={(e) => setModel(e.target.value)} /></label>
          <label>Endpoint (optional)<input value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="provider default (https only)" /></label>
          <div className="row">
            <label>Timeout (s)<input type="number" min={1} max={120} value={timeout} onChange={(e) => setTimeoutS(Number(e.target.value))} /></label>
            <label>Retries<input type="number" min={0} max={5} value={retries} onChange={(e) => setRetries(Number(e.target.value))} /></label>
          </div>
        </div>
      )}
      <div className="row">
        <button className="primary" disabled={busy} onClick={save}>Save</button>
        <button disabled={busy || state.provider === "none" || !state.key_set} onClick={test}>Test connection</button>
      </div>
      {msg && <div className={`banner ${msg.ok ? "" : "error"}`}>{msg.text}</div>}
      <p className="muted small">
        Sent to the provider: finding type, rule, severity and <em>masked</em> evidence only. Keys live in the API process memory (or
        <code> GROQ_API_KEY</code>/<code>ANTHROPIC_API_KEY</code> env vars) and are cleared by “Clear session data”. Never paste a key that was shared in chat or committed: rotate it first.
      </p>
    </section>
  );
}
