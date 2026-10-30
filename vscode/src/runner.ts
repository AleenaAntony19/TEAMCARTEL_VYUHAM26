import { spawn } from "node:child_process";
import * as path from "node:path";
import * as vscode from "vscode";

export interface RunResult { code: number | null; stdout: string; stderr: string }

export class RunError extends Error {}

/** Run the configured Python with the shield package on PYTHONPATH. Never blocks the editor; cancellable; time-boxed. */
export function runPython(
  args: string[],
  opts: { cwd: string; token?: vscode.CancellationToken; timeoutMs: number; stdin?: string; env?: Record<string, string> },
): Promise<RunResult> {
  const cfg = vscode.workspace.getConfiguration("shieldCode");
  const python = cfg.get<string>("pythonPath") || "python3";
  const enginePath = cfg.get<string>("enginePath") || "";
  const env: NodeJS.ProcessEnv = { ...process.env, ...opts.env, PYTHONUNBUFFERED: "1" };
  if (enginePath) env.PYTHONPATH = [enginePath, process.env.PYTHONPATH].filter(Boolean).join(path.delimiter);

  return new Promise((resolve, reject) => {
    const child = spawn(python, args, { cwd: opts.cwd, env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (fn: () => void) => { if (!settled) { settled = true; clearTimeout(timer); sub?.dispose(); fn(); } };
    const timer = setTimeout(() => { child.kill(); finish(() => reject(new RunError(`timed out after ${Math.round(opts.timeoutMs / 1000)} s`))); }, opts.timeoutMs);
    const sub = opts.token?.onCancellationRequested(() => { child.kill(); finish(() => reject(new vscode.CancellationError())); });
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr = (stderr + d).slice(-4000); });
    child.on("error", (e) => finish(() => reject(new RunError(`cannot start ${python}: ${e.message}`))));
    child.on("close", (code) => finish(() => resolve({ code, stdout, stderr })));
    child.stdin.end(opts.stdin ?? "");
  });
}
