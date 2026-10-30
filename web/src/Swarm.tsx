import { useEffect, useRef, useState } from "react";
import { api, type Redaction } from "./api.ts";

interface AgentEvent { agent: string; event: string; action?: string; child?: string; tools?: string[]; observation?: string; ms?: number; error?: string; decisions?: number; fail_safe?: number; round?: number }
interface AgentSummary { name: string; steps: number; tokens: number; tools: string[]; error: string; children: AgentSummary[] }
interface SwarmResult { clean: boolean; cycles: number; llm_calls: number; tool_calls: number; tokens: number; fail_safe_defaults: number;
  decisions: { finding_id: string; action: string; reason: string }[]; agents: AgentSummary[] }

// Binding LLM agent swarm: live SSE log of real tool calls, then the verified result it produced.
export function Swarm({ jobId, onDone }: { jobId: string; onDone: (r: Redaction | null) => void }) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [status, setStatus] = useState<"idle" | "running" | "done" | "failed">("idle");
  const [result, setResult] = useState<SwarmResult | null>(null);
  const [error, setError] = useState("");
  const es = useRef<EventSource | null>(null);
  useEffect(() => () => es.current?.close(), []);

  const start = async () => {
    setError(""); setEvents([]); setResult(null);
    try {
      await api.swarmRun(jobId);
    } catch (e) { setError((e as Error).message); return; }
    setStatus("running");
    const src = new EventSource(api.swarmEventsUrl(jobId));
    es.current = src;
    src.addEventListener("agent", (m) => setEvents((x) => [...x, JSON.parse((m as MessageEvent).data)]));
    src.addEventListener("end", async (m) => {
      src.close();
      const end = JSON.parse((m as MessageEvent).data);
      setStatus(end.status === "done" ? "done" : "failed");
      setResult(end.result);
      if (end.error) setError(end.error);
      onDone((await api.job(jobId)).redaction);
    });
    src.onerror = () => { src.close(); setStatus((s) => (s === "running" ? "failed" : s)); };
  };

  const line = (e: AgentEvent) => {
    if (e.event === "spawn") return `spawned ${e.child} with [${e.tools?.join(", ")}]`;
    if (e.event === "tool") return `→ ${e.action} (${e.ms} ms) ${(e.observation ?? "").slice(0, 160)}`;
    if (e.event === "final") return "returned its verdict";
    if (e.event === "round") return `round ${e.round} finished`;
    if (e.event === "binding_plan") return `binding plan: ${e.decisions} decisions${e.fail_safe ? `, ${e.fail_safe} fail-safe` : ""}`;
    if (e.event === "redaction" || e.event === "refactor") return `executed: ${(e.observation ?? "").slice(0, 160)}`;
    if (e.event === "error") return `error: ${e.error}`;
    return e.event;
  };

  return (
    <section className="card wide">
      <h2>AI agent swarm <span className="muted small">(binding)</span></h2>
      <p className="muted small">
        MetaPlanner spawns specialists → PrivacyHawk / PragmaticDev / StatutoryAuditor debate → FormatGuard optimizes → SwarmAdjudicator's plan is
        executed → red team attacks (up to 3 cycles). Agents act through real MCP tools and see masked values only. Verified identifiers, PAN,
        bank, passport, UPI, GSTIN, coordinates and faces are always redacted whatever an agent says.
      </p>
      <button className="primary" disabled={status === "running"} onClick={start}>{status === "running" ? "Agents working…" : "Run AI agent swarm"}</button>
      {error && <div className="banner error">{error}</div>}
      {events.length > 0 && (
        <ol className="agentlog" aria-live="polite">
          {events.map((e, i) => (
            <li key={i} className={`ev-${e.event}`} style={{ paddingLeft: `${(e as { depth?: number }).depth ? 16 : 0}px` }}>
              <b>{e.agent}</b> <span className="small">{line(e)}</span>
            </li>
          ))}
        </ol>
      )}
      {result && (
        <>
          <p className="small">
            <span className={`pill ${result.clean ? "ok" : "bad"}`}>{result.clean ? "CLEAN" : "NOT CLEAN"}</span>{" "}
            {result.llm_calls} LLM calls · {result.tool_calls} tool calls · <b>{result.tokens.toLocaleString()} tokens</b> · {result.cycles} redaction cycle(s)
            {result.fail_safe_defaults > 0 && ` · ${result.fail_safe_defaults} fail-safe default(s)`}
          </p>
          <table className="kv small"><tbody>
            {result.agents.flatMap((a) => [a, ...a.children]).map((a, i) => (
              <tr key={i}><th>{a.name}</th><td>{a.steps} steps · {a.tokens} tok · {a.tools.join(", ") || "no tools"}{a.error && <span className="error-text"> · {a.error}</span>}</td></tr>
            ))}
          </tbody></table>
        </>
      )}
    </section>
  );
}
