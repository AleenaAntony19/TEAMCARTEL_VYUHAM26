import { useCallback, useEffect, useRef, useState } from "react";
import { api, type Redaction } from "./api.ts";
import { Graph3D } from "./Graph3D.tsx";
import { GraphModel, describeAgent, roleOf, type AgentEvent } from "./graph.ts";
import { LiveLog, type LogRow } from "./LiveLog.tsx";

interface AgentSummary { name: string; steps: number; tokens: number; tools: string[]; error: string; children: AgentSummary[] }
interface SwarmResult { clean: boolean; cycles: number; llm_calls: number; tool_calls: number; tokens: number; fail_safe_defaults: number;
  decisions: { finding_id: string; action: string; reason: string }[]; agents: AgentSummary[] }

// Binding LLM agent swarm: 3D graph + live log driven by the real SSE events, then the verified result.
export function Swarm({ jobId, onDone }: { jobId: string; onDone: (r: Redaction | null) => void }) {
  const model = useRef(new GraphModel());
  const [rows, setRows] = useState<LogRow[]>([]);
  const [tick, setTick] = useState(0);
  const [pulses, setPulses] = useState<string[]>([]);
  const [filter, setFilter] = useState<string>();
  const [status, setStatus] = useState<"idle" | "running" | "done" | "failed">("idle");
  const [result, setResult] = useState<SwarmResult | null>(null);
  const [error, setError] = useState("");
  const es = useRef<EventSource | null>(null);
  useEffect(() => () => es.current?.close(), []);
  const select = useCallback((id: string) => setFilter(id.replace(/^agent:/, "")), []);

  const start = async () => {
    setError(""); setRows([]); setResult(null); setFilter(undefined);
    model.current = new GraphModel();
    try {
      await api.swarmRun(jobId);
    } catch (e) { setError((e as Error).message); return; }
    setStatus("running");
    const src = new EventSource(api.swarmEventsUrl(jobId));
    es.current = src;
    src.addEventListener("agent", (m) => {
      const ev = JSON.parse((m as MessageEvent).data) as AgentEvent & { observation?: string };
      setPulses(model.current.applyAgent(ev));
      setTick((t) => t + 1);
      setRows((r) => [...r, { ts: ev.ts, who: ev.agent ?? "?", text: describeAgent(ev), tone: roleOf(ev.agent ?? ""), level: ev.event === "error" ? "error" : "info" }]);
    });
    src.addEventListener("end", async (m) => {
      src.close();
      const end = JSON.parse((m as MessageEvent).data);
      setStatus(end.status === "done" ? "done" : "failed");
      setResult(end.result);
      if (end.result?.agents) { model.current.applyTotals(end.result.agents); setTick((t) => t + 1); }
      if (end.error) setError(end.error);
      onDone((await api.job(jobId)).redaction);
    });
    src.onerror = () => { src.close(); setStatus((s) => (s === "running" ? "failed" : s)); };
  };

  return (
    <section className="card wide">
      <h2>AI agent swarm <span className="muted small">(binding)</span></h2>
      <p className="muted small">
        MetaPlanner spawns specialists → PrivacyHawk / PragmaticDev / StatutoryAuditor debate → FormatGuard optimizes → SwarmAdjudicator's plan is
        executed → red team attacks (up to 3 cycles). Every dot travelling along a link is a real message or MCP tool call. Agents see masked values
        only; verified identifiers, PAN, bank, passport, UPI, GSTIN, coordinates and faces are always redacted whatever an agent says.
      </p>
      <button className="primary" disabled={status === "running"} onClick={start}>{status === "running" ? "Agents working…" : "Run AI agent swarm"}</button>
      {error && <div className="banner error">{error}</div>}
      {status !== "idle" && (
        <>
          <Graph3D model={model.current} tick={tick} pulses={pulses} onSelect={select} title="Agent communication graph" />
          <LiveLog rows={rows} filter={filter} onClearFilter={() => setFilter(undefined)} />
        </>
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
