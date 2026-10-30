import { useEffect, useRef, useState } from "react";
import type { ForceGraph3DInstance } from "3d-force-graph";
import type * as THREE_NS from "three";
import type { GLink, GNode, GraphModel } from "./graph.ts";

const GROUP_COLOR: Record<string, string> = {
  planner: "#a78bfa", persona: "#38bdf8", specialist: "#34d399", optimizer: "#f472b6", adjudicator: "#fbbf24",
  redteam: "#f87171", executor: "#e5e7eb", tool: "#94a3b8", hub: "#a78bfa", site: "#22d3ee", page: "#64748b",
};
const STATUS_COLOR: Partial<Record<GNode["status"], string>> = { error: "#ef4444", blocked: "#64748b", match: "#f59e0b" };
const SIZE: Record<GNode["kind"], number> = { hub: 12, agent: 9, site: 7, provider: 5, tool: 4, page: 2.5 };
const LINK_COLOR: Record<string, string> = { spawn: "#a78bfa", tool: "#38bdf8", result: "#34d399", debate: "#fbbf24", plan: "#f472b6", verify: "#f87171", crawl: "#22d3ee", page: "#475569", query: "#a78bfa", search: "#94a3b8", hit: "#22d3ee", orchestrates: "#334155" };

export const colorOf = (n: GNode) => STATUS_COLOR[n.status] ?? GROUP_COLOR[n.group] ?? "#cbd5e1";

function label(THREE: typeof THREE_NS, text: string, color: string): THREE_NS.Sprite {
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d")!;
  const font = "600 28px ui-sans-serif, system-ui, sans-serif";
  ctx.font = font;
  canvas.width = Math.ceil(ctx.measureText(text).width) + 16;
  canvas.height = 40;
  ctx.font = font;
  ctx.fillStyle = color;
  ctx.textBaseline = "middle";
  ctx.fillText(text, 8, 20);
  const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: new THREE.CanvasTexture(canvas), depthWrite: false, transparent: true }));
  sprite.scale.set(canvas.width / 3.5, canvas.height / 3.5, 1);
  return sprite;
}

interface Props {
  model: GraphModel;
  tick: number;          // bump after applying events
  pulses: string[];      // link ids to animate for the latest events
  onSelect?: (nodeId: string) => void;
  height?: number;
  title: string;         // accessible name; the live log is the text equivalent
}

// 3D force graph (three.js), loaded on demand so the rest of the app stays light.
export function Graph3D({ model, tick, pulses, onSelect, height = 420, title }: Props) {
  const el = useRef<HTMLDivElement>(null);
  const g = useRef<ForceGraph3DInstance | null>(null);
  const three = useRef<typeof THREE_NS | null>(null);
  const [failed, setFailed] = useState("");
  const reduced = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

  useEffect(() => {
    let alive = true;
    let ro: ResizeObserver | undefined;
    Promise.all([import("3d-force-graph"), import("three")]).then(([mod, THREE]) => {
      if (!alive || !el.current) return;
      three.current = THREE;
      try {
        const graph = new mod.default(el.current, { controlType: "orbit" })
          .backgroundColor("#0b1020")
          .width(el.current.clientWidth)
          .height(height)
          .showNavInfo(false)
          .nodeLabel((n) => (n as GNode).label)
          .nodeThreeObject((n) => {
            const node = n as GNode;
            const group = new THREE.Group();
            const color = colorOf(node);
            const sphere = new THREE.Mesh(
              new THREE.SphereGeometry(SIZE[node.kind] ?? 4, 20, 20),
              new THREE.MeshLambertMaterial({ color, emissive: color, emissiveIntensity: node.status === "active" ? 0.6 : 0.25, transparent: true, opacity: 0.92 }),
            );
            group.add(sphere);
            if (node.kind !== "page") {
              const badge = node.tokens ? ` · ${node.steps} st · ${node.tokens} tok` : node.calls ? ` · ${node.calls}` : "";
              const text = label(THREE, node.label + badge, "#e2e8f0");
              text.position.y = (SIZE[node.kind] ?? 4) + 5;
              group.add(text);
            }
            return group;
          })
          .linkColor((l) => LINK_COLOR[(l as GLink).kind] ?? "#334155")
          .linkOpacity(0.45)
          .linkWidth((l) => ((l as GLink).kind === "orchestrates" ? 0 : 0.6))
          .linkDirectionalParticleWidth(3)
          .linkDirectionalParticleSpeed(0.015)
          .linkDirectionalParticleColor((l) => LINK_COLOR[(l as GLink).kind] ?? "#e2e8f0")
          .onNodeClick((n) => onSelect?.((n as GNode).id))
          .cooldownTicks(120)
          .onEngineStop(() => graph.zoomToFit(600, 20));
        // spread nodes so labels do not overlap
        (graph.d3Force("charge") as unknown as { strength: (v: number) => void } | undefined)?.strength(-260);
        (graph.d3Force("link") as unknown as { distance: (v: number) => void } | undefined)?.distance(70);
        const controls = graph.controls() as { autoRotate?: boolean; autoRotateSpeed?: number };
        controls.autoRotate = !reduced;
        controls.autoRotateSpeed = 0.6;
        g.current = graph;
        ro = new ResizeObserver(() => el.current && graph.width(el.current.clientWidth));
        ro.observe(el.current);
      } catch (e) {
        setFailed(e instanceof Error ? e.message : "WebGL unavailable");
      }
    }, (e: Error) => setFailed(e.message));
    return () => { alive = false; ro?.disconnect(); g.current?._destructor(); g.current = null; };
  }, [height, onSelect, reduced]);

  useEffect(() => {
    const graph = g.current;
    if (!graph) return;
    if (model.changed) {
      // copies: the model keeps pushing into its arrays, which the running engine must not see before re-init
      graph.graphData({ nodes: [...model.nodes], links: [...model.links] });
      model.changed = false;
    } else {
      graph.nodeThreeObject(graph.nodeThreeObject()); // statuses/badges changed: rebuild node meshes
    }
    if (reduced) return;
    const byId = new Map(graph.graphData().links.map((l) => [(l as GLink).id, l]));
    for (const id of pulses) {
      const link = byId.get(id);
      // a link added this tick is not wired to node objects until the engine's next pass
      if (link && typeof link.source === "object" && typeof link.target === "object") graph.emitParticle(link);
    }
  }, [tick, model, pulses, reduced]);

  return (
    <div className="graph3d" role="img" aria-label={`${title}: ${model.nodes.length} nodes, ${model.links.length} links. The log below lists every step.`}>
      {failed ? <p className="muted small">3D view unavailable ({failed}). The live log below shows every step.</p> : <div ref={el} style={{ height }} />}
      <div className="legend small">
        {Object.entries({ planner: "planner", persona: "persona", specialist: "specialist", optimizer: "optimizer", adjudicator: "adjudicator", redteam: "red team", tool: "MCP tool" }).map(([k, v]) => (
          <span key={k}><i style={{ background: GROUP_COLOR[k] }} />{v}</span>
        ))}
      </div>
    </div>
  );
}
