import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { engineSpawn } from "./runner.ts";

/** Talk to the engine's MCP server over stdio (`python -m shield.mcp`). */
export async function withMcp<T>(root: string, extraEnv: Record<string, string>, fn: (c: Client) => Promise<T>): Promise<T> {
  const { command, args, env } = engineSpawn(["-m", "shield.mcp"], { ...extraEnv, SHIELD_MCP_ROOT: root });
  const transport = new StdioClientTransport({ command, args, env, cwd: root, stderr: "pipe" });
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
