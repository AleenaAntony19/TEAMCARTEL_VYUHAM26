import { useEffect, useRef, useState } from "react";

export interface LogRow { ts?: number; who: string; text: string; tone: string; level?: "info" | "warn" | "error" }

// Terminal-style log of real events: newest at the bottom, auto-follows unless the user scrolls up.
export function LiveLog({ rows, filter, onClearFilter, height = 260 }: { rows: LogRow[]; filter?: string; onClearFilter?: () => void; height?: number }) {
  const box = useRef<HTMLOListElement>(null);
  const [follow, setFollow] = useState(true);
  const shown = filter ? rows.filter((r) => r.who === filter) : rows;

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [shown.length, follow]);

  const t0 = rows[0]?.ts;
  return (
    <div className="livelog">
      <div className="livelog-bar small">
        <span className="dot-live" aria-hidden /> live log · {shown.length} event{shown.length === 1 ? "" : "s"}
        {filter && <button className="link" onClick={onClearFilter}>showing {filter} only · show all</button>}
        {!follow && <button className="link" onClick={() => setFollow(true)}>jump to live ↓</button>}
      </div>
      <ol
        ref={box}
        style={{ maxHeight: height }}
        aria-live="polite"
        onScroll={(e) => {
          const el = e.currentTarget;
          setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 24);
        }}
      >
        {shown.map((r, i) => (
          <li key={i} className={`row lvl-${r.level ?? "info"}`}>
            <span className="t">{r.ts && t0 ? `+${(r.ts - t0).toFixed(1)}s` : ""}</span>
            <span className={`who tone-${r.tone}`}>{r.who}</span>
            <span className="msg">{r.text}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}
