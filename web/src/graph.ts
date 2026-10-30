// Turns real SSE events (agent swarm or discovery crawl) into a growing node/link model plus "pulses":
// links to animate for that event. Node/link objects are kept stable so the 3D layout does not jump.

export type NodeKind = "agent" | "tool" | "hub" | "site" | "page" | "provider";
export type Status = "idle" | "active" | "done" | "error" | "blocked" | "match";

export interface GNode { id: string; label: string; kind: NodeKind; group: string; status: Status; steps: number; tokens: number; calls: number }
export interface GLink { id: string; source: string; target: string; kind: string }

export interface AgentEvent { agent?: string; event?: string; depth?: number; action?: string; child?: string; error?: string; ts?: number }
export interface ScoutEvent { kind?: string; url?: string; query?: string; allowed?: boolean; provider?: string; reason?: string; match?: string; ts?: number }

const PERSONAS = new Set(["PrivacyHawk", "PragmaticDev", "StatutoryAuditor"]);
const OPTIMIZERS = new Set(["FormatGuard", "RefactorBot"]);
const MAX_PAGES_PER_SITE = 40;

export function roleOf(name: string): string {
  if (name === "MetaPlanner") return "planner";
  if (PERSONAS.has(name)) return "persona";
  if (OPTIMIZERS.has(name)) return "optimizer";
  if (name === "SwarmAdjudicator") return "adjudicator";
  if (name === "AdversarialRedTeamAgent") return "redteam";
  if (name === "executor") return "executor";
  return "specialist";
}

export function host(url: string): string {
  try { return new URL(url).host || url; } catch { return url; }
}

/** Site "area": host plus first path segment (forum, gallery, paste…), so cards show which section is being scraped. */
export function area(url: string): string {
  try {
    const u = new URL(url);
    const seg = u.pathname.split("/").filter(Boolean)[0];
    return seg && !seg.includes(".") ? `${u.host}/${seg}` : u.host;
  } catch { return url; }
}

export class GraphModel {
  nodes: GNode[] = [];
  links: GLink[] = [];
  private byId = new Map<string, GNode>();
  private linkIds = new Set<string>();
  changed = false; // structure changed since the renderer last read it

  node(id: string, label: string, kind: NodeKind, group: string): GNode {
    let n = this.byId.get(id);
    if (!n) {
      n = { id, label, kind, group, status: "idle", steps: 0, tokens: 0, calls: 0 };
      this.byId.set(id, n);
      this.nodes.push(n);
      this.changed = true;
    }
    return n;
  }

  get(id: string): GNode | undefined { return this.byId.get(id); }

  link(source: string, target: string, kind: string): string {
    const id = `${source}->${target}`;
    if (!this.linkIds.has(id)) {
      this.linkIds.add(id);
      this.links.push({ id, source, target, kind });
      this.changed = true;
    }
    return id;
  }

  private agent(name: string): GNode {
    const n = this.node(`agent:${name}`, name, "agent", roleOf(name));
    // keep the graph connected: every agent hangs off the planner unless spawned by someone
    if (name !== "MetaPlanner" && roleOf(name) !== "specialist") this.link("agent:MetaPlanner", n.id, "orchestrates");
    return n;
  }

  /** Apply one swarm event; returns link ids to pulse. */
  applyAgent(ev: AgentEvent): string[] {
    if (!ev.agent || ev.agent === "swarm") return []; // "swarm" marks round boundaries, it is not an agent
    this.agent("MetaPlanner");
    const me = this.agent(ev.agent);
    const pulses: string[] = [];
    if (me.status === "idle") me.status = "active";
    switch (ev.event) {
      case "spawn": {
        const child = this.node(`agent:${ev.child}`, ev.child ?? "?", "agent", "specialist");
        child.status = "active";
        pulses.push(this.link(me.id, child.id, "spawn"));
        break;
      }
      case "tool": {
        const tool = this.node(`tool:${ev.action}`, ev.action ?? "tool", "tool", "tool");
        me.calls += 1;
        tool.calls += 1;
        pulses.push(this.link(me.id, tool.id, "tool"), this.link(tool.id, me.id, "result"));
        break;
      }
      case "final":
        me.status = "done";
        if (roleOf(ev.agent) === "persona" || roleOf(ev.agent) === "optimizer") pulses.push(this.link(me.id, this.agent("SwarmAdjudicator").id, "debate"));
        break;
      case "error":
        me.status = "error";
        break;
      case "binding_plan": {
        this.agent("executor");
        pulses.push(this.link(me.id, "agent:executor", "plan"));
        break;
      }
      case "redaction":
      case "refactor":
        this.agent("AdversarialRedTeamAgent");
        pulses.push(this.link(me.id, "agent:AdversarialRedTeamAgent", "verify"));
        break;
    }
    return pulses;
  }

  /** Copy per-agent step/token totals from the run result (end event). */
  applyTotals(agents: { name: string; steps: number; tokens: number; error?: string; children?: { name: string; steps: number; tokens: number }[] }[]) {
    for (const a of agents.flatMap((x) => [x, ...(x.children ?? [])])) {
      const n = this.get(`agent:${a.name}`);
      if (n) { n.steps += a.steps; n.tokens += a.tokens; if (n.status !== "error") n.status = "done"; }
    }
  }

  /** Apply one discovery event; returns link ids to pulse. */
  applyScout(ev: ScoutEvent): string[] {
    const hub = this.node("hub:scout", "Leak Scout", "hub", "hub");
    hub.status = "active";
    if (ev.kind === "query") {
      const fw = this.node("agent:QueryFirewall", "QueryFirewall", "agent", "persona");
      const ids = [this.link(hub.id, fw.id, "query")];
      if (ev.allowed && ev.provider) ids.push(this.link(fw.id, this.node(`provider:${ev.provider}`, `search: ${ev.provider}`, "provider", "tool").id, "search"));
      fw.calls += 1;
      return ids;
    }
    if (!ev.url) return [];
    const site = this.node(`site:${area(ev.url)}`, area(ev.url), "site", "site");
    if (ev.kind === "search_hit" && ev.provider) return [this.link(`provider:${ev.provider}`, site.id, "hit")];
    const ids = [this.link(hub.id, site.id, "crawl")];
    site.calls += 1;
    if (ev.kind === "blocked" || ev.kind === "robots_denied") site.status = "blocked";
    else if (ev.kind === "match") site.status = "match";
    else if (site.status === "idle") site.status = "active";
    // count by id: the 3D renderer replaces link.source with the node object
    const pages = this.links.filter((l) => l.id.startsWith(`${site.id}->page:`)).length;
    if (pages < MAX_PAGES_PER_SITE || ev.kind === "match") {
      let path = ev.url;
      try { path = new URL(ev.url).pathname || "/"; } catch { /* keep raw */ }
      const page = this.node(`page:${ev.url}`, path, "page", "page");
      page.status = ev.kind === "match" ? "match" : ev.kind === "crawl_progress" ? "done" : ev.kind === "crawl_error" ? "error" : "blocked";
      ids.push(this.link(site.id, page.id, "page"));
    }
    return ids;
  }
}

/** One readable log line per real event (no invented text). */
export function describeAgent(e: AgentEvent & { observation?: string; tools?: string[]; ms?: number; decisions?: number; round?: number; fail_safe?: number }): string {
  switch (e.event) {
    case "spawn": return `spawned ${e.child} with [${(e.tools ?? []).join(", ")}]`;
    case "tool": return `→ ${e.action} (${e.ms ?? 0} ms) ${(e.observation ?? "").slice(0, 140)}`;
    case "final": return "returned its verdict";
    case "round": return `debate round ${e.round} closed`;
    case "binding_plan": return `binding plan: ${e.decisions} decisions${e.fail_safe ? `, ${e.fail_safe} fail-safe` : ""}`;
    case "redaction": case "refactor": return `executed: ${(e.observation ?? "").slice(0, 140)}`;
    case "error": return `error: ${e.error}`;
    default: return e.event ?? "";
  }
}

export function describeScout(e: ScoutEvent & { pages?: number; images?: number; image_url?: string; verdict?: string }): string {
  switch (e.kind) {
    case "query": return `${e.allowed ? "sent" : "BLOCKED by firewall"}: ${e.query}`;
    case "search_hit": return `hit ${e.url}`;
    case "crawl_progress": return `fetched ${e.url}  (pages ${e.pages ?? "?"}, images ${e.images ?? "?"})`;
    case "blocked": return `blocked ${e.url} (${e.reason})`;
    case "robots_denied": return `robots.txt disallows ${e.url}`;
    case "crawl_error": return `error on ${e.url}`;
    case "match": return `⚠ ${e.verdict} ${e.match} match on ${e.url}`;
    default: return e.kind ?? "";
  }
}
