import { test } from "node:test";
import assert from "node:assert/strict";
import { GraphModel, describeScout } from "./graph.ts";

test("agent events build a connected graph and pulse the right links", () => {
  const g = new GraphModel();
  assert.deepEqual(g.applyAgent({ agent: "MetaPlanner", event: "spawn", child: "SovereignPIIAgent" }), ["agent:MetaPlanner->agent:SovereignPIIAgent"]);
  const p = g.applyAgent({ agent: "StatutoryAuditor", event: "tool", action: "validate_checksum" });
  assert.deepEqual(p, ["agent:StatutoryAuditor->tool:validate_checksum", "tool:validate_checksum->agent:StatutoryAuditor"]);
  assert.ok(g.links.some((l) => l.id === "agent:MetaPlanner->agent:StatutoryAuditor"), "persona hangs off the planner");
  g.applyAgent({ agent: "StatutoryAuditor", event: "final" });
  assert.equal(g.get("agent:StatutoryAuditor")?.status, "done");
  assert.ok(g.links.some((l) => l.id === "agent:StatutoryAuditor->agent:SwarmAdjudicator"));
  g.applyAgent({ agent: "PrivacyHawk", event: "error", error: "429" });
  assert.equal(g.get("agent:PrivacyHawk")?.status, "error");
  const before = g.nodes.length;
  g.applyAgent({ agent: "StatutoryAuditor", event: "tool", action: "validate_checksum" });
  assert.equal(g.nodes.length, before, "repeat tool calls reuse nodes");
  g.applyTotals([{ name: "StatutoryAuditor", steps: 2, tokens: 900 }]);
  assert.equal(g.get("agent:StatutoryAuditor")?.tokens, 900);
});

test("scout events map sites, pages, blocks and matches", () => {
  const g = new GraphModel();
  g.applyScout({ kind: "query", query: 'site:pastebin.com "Acme"', allowed: true, provider: "offline" });
  g.applyScout({ kind: "crawl_progress", url: "http://127.0.0.1:8765/forum/thread1_page1.html" });
  g.applyScout({ kind: "blocked", url: "http://127.0.0.1:8765/blocked/", reason: "http_403" });
  g.applyScout({ kind: "match", url: "http://127.0.0.1:8765/gallery/", match: "pdq" });
  assert.equal(g.get("site:127.0.0.1:8765/gallery")?.status, "match");
  assert.equal(g.get("site:127.0.0.1:8765/blocked")?.status, "blocked");
  assert.equal(g.get("site:127.0.0.1:8765/forum")?.status, "active", "one blocked area does not mark the others");
  assert.equal(g.get("page:http://127.0.0.1:8765/forum/thread1_page1.html")?.label, "/forum/thread1_page1.html");
  assert.match(describeScout({ kind: "query", query: "q", allowed: false }), /BLOCKED/);
});
