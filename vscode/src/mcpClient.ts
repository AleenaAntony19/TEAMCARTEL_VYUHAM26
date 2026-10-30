import * as path from "node:path";
import * as vscode from "vscode";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

/** Talk to the engine's MCP server over stdio (`python -m shield.mcp`). */
export async function withMcp<T>(root: string, extraEnv: Record<string, string>, fn: (c: Client) => Promise<T>): Promise<T> {
  const cfg = vscode.workspace.getConfiguration("shieldCode");
  const enginePath = cfg.get<string>("enginePath") || "";
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && k !== "ELECTRON_RUN_AS_NODE") env[k] = v;
  Object.assign(env, extraEnv, { SHIELD_MCP_ROOT: root, PYTHONUNBUFFERED: "1" });
  if (enginePath) env.PYTHONPATH = [enginePath, process.env.PYTHONPATH].filter(Boolean).join(path.delimiter);
  const transport = new StdioClientTransport({ command: cfg.get<string>("pythonPath") || "python3", args: ["-m", "shield.mcp"], env, cwd: root, stderr: "pipe" });
  const client = new Client({ name: "shield-code-vscode", version: "0.3.0" });
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

/** Parse the JSON text a Shield MCP tool returns. */
export function toolJson(res: unknown): Record<string, unknown> {
  const content = (res as { content?: { type: string; text?: string }[] }).content ?? [];
  const text = content.find((c) => c.type === "text")?.text ?? "{}";
  return JSON.parse(text);
}
