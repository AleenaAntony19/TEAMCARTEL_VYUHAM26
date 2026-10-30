import { chmodSync, existsSync, statSync } from "node:fs";
import { spawn } from "node:child_process";
import * as path from "node:path";
import * as vscode from "vscode";
import { explainStartFailure, resolveEngine } from "./core.ts";

export interface RunResult { code: number | null; stdout: string; stderr: string }

export class RunError extends Error {}

let extensionRoot = "";
export function setExtensionRoot(root: string) { extensionRoot = root; }

/** Path of the engine shipped inside a platform VSIX, or null (universal VSIX / development). */
export function bundledEngine(): string | null {
  if (!extensionRoot) return null;
  const exe = path.join(extensionRoot, "engine", "shield-engine", process.platform === "win32" ? "shield-engine.exe" : "shield-engine");
  if (!existsSync(exe)) return null;
  if (process.platform !== "win32" && !(statSync(exe).mode & 0o111)) chmodSync(exe, 0o755); // zip may drop the exec bit
  return exe;
}

/** Command, args and env for the engine: bundled binary first, else the shield package via Python. */
export function engineSpawn(args: string[], extraEnv: Record<string, string> = {}) {
  const cfg = vscode.workspace.getConfiguration("shieldCode");
  const enginePath = cfg.get<string>("enginePath") || "";
  const resolved = resolveEngine(args, { bundled: bundledEngine(), pythonPath: cfg.get<string>("pythonPath") || "", platform: process.platform });
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && k !== "ELECTRON_RUN_AS_NODE") env[k] = v;
  Object.assign(env, extraEnv, { PYTHONUNBUFFERED: "1" });
  if (enginePath) env.PYTHONPATH = [enginePath, process.env.PYTHONPATH].filter(Boolean).join(path.delimiter);
  return { ...resolved, env };
}

/** Run the engine. Never blocks the editor; cancellable; time-boxed. */
export function runPython(
  args: string[],
  opts: { cwd: string; token?: vscode.CancellationToken; timeoutMs: number; stdin?: string; env?: Record<string, string> },
): Promise<RunResult> {
  const { command, args: argv, env } = engineSpawn(args, opts.env);
  return new Promise((resolve, reject) => {
    const child = spawn(command, argv, { cwd: opts.cwd, env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (fn: () => void) => { if (!settled) { settled = true; clearTimeout(timer); sub?.dispose(); fn(); } };
    const timer = setTimeout(() => { child.kill(); finish(() => reject(new RunError(`timed out after ${Math.round(opts.timeoutMs / 1000)} s`))); }, opts.timeoutMs);
    const sub = opts.token?.onCancellationRequested(() => { child.kill(); finish(() => reject(new vscode.CancellationError())); });
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr = (stderr + d).slice(-4000); });
    child.on("error", (e) => finish(() => reject(new RunError(explainStartFailure(`cannot start ${command}: ${e.message}`, process.platform)))));
    child.on("close", (code) => finish(() => {
      // the Windows Store stub exits 9009 and prints its install hint on stderr
      if (code !== 0 && code !== 1 && /Microsoft Store|was not found/i.test(stderr)) reject(new RunError(explainStartFailure(stderr, process.platform)));
      else resolve({ code, stdout, stderr });
    }));
    child.stdin.end(opts.stdin ?? "");
  });
}
