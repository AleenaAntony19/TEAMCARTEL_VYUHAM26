// Pure helpers (no `vscode` import) so they run under `node --test`.

export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  id: string; engine: string; rule: string; severity: Severity; file: string;
  line: number; col: number; end_line: number; end_col: number;
  message: string; masked: string; fixes: string[]; in_history: boolean;
  confidence: number; evidence: string; recommendation: string; bbox: number[] | null; rationale?: string;
}

export interface ScanResult {
  version: number; root: string; findings: Finding[];
  stats: { files: number; ms: number; engines: Record<string, string>; errors: { file: string; engine: string; error: string }[]; ocr: string; timed_out?: boolean;
    cognitive?: { sent: number; cached: number; skipped: number; truncated: number; model: string; error?: string } };
}

// Same model as shield/codescan/fix.py: replace [line:col, end_line:end_col); lines 1-based, cols 0-based.
export interface TextEdit { file: string; line: number; col: number; end_line: number; end_col: number; new_text: string }
export interface FixPlan { edits: TextEdit[]; file_ops: { op: string; file: string; summary: string }[]; notes: string[]; error?: string }

export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function parseScan(stdout: string): ScanResult {
  const data = JSON.parse(stdout);
  if (!data || !Array.isArray(data.findings) || typeof data.stats !== "object") throw new Error("scanner returned an unexpected shape");
  return data as ScanResult;
}

export function atLeast(sev: Severity, min: Severity): boolean {
  return SEVERITY_RANK[sev] <= SEVERITY_RANK[min];
}

/** 0-based VS Code range for a finding; whole-file findings (line 0) point at the first line. */
export function findingRange(f: Finding): { startLine: number; startCol: number; endLine: number; endCol: number } {
  if (!f.line) return { startLine: 0, startCol: 0, endLine: 0, endCol: 0 };
  const startCol = Math.max(0, f.col - 1);
  const endLine = Math.max(f.line, f.end_line || f.line) - 1;
  const endCol = f.end_col > 0 ? f.end_col - 1 : Number.MAX_SAFE_INTEGER;
  return { startLine: f.line - 1, startCol, endLine, endCol };
}

export function describe(f: Finding): string {
  const where = f.bbox ? ` [x=${f.bbox[0]} y=${f.bbox[1]} w=${f.bbox[2]} h=${f.bbox[3]}]` : "";
  const ev = f.evidence ? ` · ${f.evidence}` : f.masked ? ` · ${f.masked}` : "";
  return `${f.rule}: ${f.message}${where}${ev} (confidence ${Math.round(f.confidence * 100)}%)`;
}

export function applyEdits(text: string, edits: TextEdit[]): string {
  const lines = text.split("\n");
  const starts = [0];
  for (const ln of lines) starts.push(starts[starts.length - 1] + ln.length + 1);
  const offset = (line: number, col: number) => {
    const l = Math.max(1, Math.min(line, lines.length));
    return starts[l - 1] + Math.min(col, lines[l - 1].length);
  };
  const sorted = [...edits].sort((a, b) => b.line - a.line || b.col - a.col);
  for (const e of sorted) {
    const a = offset(e.line, e.col);
    const b = offset(e.end_line, e.end_col);
    text = text.slice(0, a) + e.new_text + text.slice(b);
  }
  return text;
}

export const FIX_TITLES: Record<string, string> = {
  move_to_env: "Move secret to .env (then rotate it)",
  gitignore_add: "Add to .gitignore",
  untrack_file: "Stop tracking file (git rm --cached)",
  redact_pii: "Replace with [REDACTED-TYPE] token",
  fake_pii: "Replace with a synthetic test value",
  redact_image: "Redact image (opaque fill + strip metadata)",
  strip_exif: "Strip image metadata",
  yaml_safe_load: "Use yaml.safe_load",
  requests_verify: "Re-enable TLS verification",
  hash_pdq: "Add PDQ hash to leak-monitoring bank (not redaction)",
  ignore: "Ignore this finding (.shieldignore)",
};

/** Engines whose findings can be re-located by scanning only their file. */
export const FILE_SCOPED = new Set(["secrets", "pii", "media", "document", "cognitive"]);

export function scanArgs(root: string, opts: { engines: string[]; ocr: boolean; maxFileMB: number; exclude: string[]; concurrency: number; timeout: number; files?: string[]; cognitive?: boolean }): string[] {
  const args = ["-m", "shield.codescan", "scan", root, "--format", "json", "--workers", String(opts.concurrency),
    "--timeout", String(opts.timeout), "--max-file-mb", String(opts.maxFileMB), "--engines", opts.engines.join(",")];
  if (!opts.ocr) args.push("--no-ocr");
  if (opts.cognitive) args.push("--cognitive");
  for (const e of opts.exclude) args.push("--exclude", e);
  if (opts.files?.length) args.push("--files", ...opts.files);
  return args;
}

export function debounce<A extends unknown[]>(fn: (...a: A) => void, ms: number): (...a: A) => void {
  let t: ReturnType<typeof setTimeout> | undefined;
  return (...a: A) => { if (t) clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

/**
 * How to start the engine. A bundled engine (platform VSIX) needs no Python; otherwise run the
 * `shield` package with the configured interpreter (`py -3` on Windows: `python3`/`python` there is often
 * only the Microsoft Store stub). `args` are always given in module form: ["-m", "shield.codescan", ...].
 */
export function resolveEngine(
  args: string[], opts: { bundled: string | null; pythonPath: string; platform: string },
): { command: string; args: string[] } {
  if (opts.bundled && !opts.pythonPath) {
    const [flag, mod, ...rest] = args;
    if (flag !== "-m") return { command: opts.bundled, args };
    const mode = mod === "shield.llm" ? ["llm"] : mod === "shield.mcp" ? ["mcp"] : [];
    return { command: opts.bundled, args: [...mode, ...rest] };
  }
  if (opts.pythonPath) return { command: opts.pythonPath, args };
  return opts.platform === "win32" ? { command: "py", args: ["-3", ...args] } : { command: "python3", args };
}

/** Turn "python not found" style failures into an actionable message. */
export function explainStartFailure(message: string, platform: string): string {
  if (/Microsoft Store|ENOENT|not found|not recognized/i.test(message)) {
    return platform === "win32"
      ? "Python was not found. Install the Windows build of Shield·Code (it bundles the engine), or install Python 3.11 and set shieldCode.pythonPath to python.exe."
      : "Python was not found. Install the platform build of Shield·Code (bundled engine), or set shieldCode.pythonPath.";
  }
  return message;
}

export const RETIRED_MODELS = new Set(["claude-3-7-sonnet", "claude-3-5-haiku"]);
