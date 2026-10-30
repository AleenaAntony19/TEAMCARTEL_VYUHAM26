import { randomBytes } from "node:crypto";
import * as vscode from "vscode";
import { runPython } from "./runner.ts";

type Provider = "none" | "groq" | "anthropic";
const KEY_ENV: Record<Exclude<Provider, "none">, string> = { groq: "GROQ_API_KEY", anthropic: "ANTHROPIC_API_KEY" };
const DEFAULT_MODEL: Record<Exclude<Provider, "none">, string> = { groq: "openai/gpt-oss-20b", anthropic: "claude-haiku-5-5" };
const secretId = (p: string) => `shieldCode.llmKey.${p}`;

/** Env for `python -m shield.llm`, with the key from VS Code Secret Storage; null when not configured. */
export async function llmEnv(ctx: vscode.ExtensionContext): Promise<Record<string, string> | null> {
  const cfg = vscode.workspace.getConfiguration("shieldCode");
  const provider = (cfg.get<string>("llm.provider") ?? "none") as Provider;
  if (provider === "none") return null;
  const key = await ctx.secrets.get(secretId(provider));
  if (!key) return null;
  return { SHIELD_LLM_PROVIDER: provider, SHIELD_LLM_MODEL: cfg.get<string>("llm.model") || DEFAULT_MODEL[provider], [KEY_ENV[provider]]: key };
}

// "AI Provider" sidebar panel: choose Groq or Claude, store the key in Secret Storage, test the connection.
export class AiViewProvider implements vscode.WebviewViewProvider {
  private ctx: vscode.ExtensionContext;
  constructor(ctx: vscode.ExtensionContext) { this.ctx = ctx; }

  async resolveWebviewView(view: vscode.WebviewView) {
    view.webview.options = { enableScripts: true, localResourceRoots: [] };
    const nonce = randomBytes(16).toString("base64");
    view.webview.html = html(nonce, view.webview.cspSource);

    const state = async () => {
      const cfg = vscode.workspace.getConfiguration("shieldCode");
      const provider = (cfg.get<string>("llm.provider") ?? "none") as Provider;
      const keys = { groq: !!(await this.ctx.secrets.get(secretId("groq"))), anthropic: !!(await this.ctx.secrets.get(secretId("anthropic"))) };
      return { type: "state", provider, model: cfg.get<string>("llm.model") ?? "", keys };
    };
    const post = (m: unknown) => view.webview.postMessage(m);

    view.webview.onDidReceiveMessage(async (msg: { type: string; provider?: Provider; model?: string; key?: string }) => {
      try {
        if (msg.type === "ready") return void post(await state());
        if (msg.type === "save" && msg.provider) {
          const cfg = vscode.workspace.getConfiguration("shieldCode");
          await cfg.update("llm.provider", msg.provider, vscode.ConfigurationTarget.Global);
          await cfg.update("llm.model", msg.provider === "none" ? "" : (msg.model || DEFAULT_MODEL[msg.provider]), vscode.ConfigurationTarget.Global);
          if (msg.provider !== "none" && msg.key?.trim()) await this.ctx.secrets.store(secretId(msg.provider), msg.key.trim());
          post(await state());
          return void post({ type: "status", ok: true, text: msg.provider === "none" ? "AI explanations disabled." : "Saved. The key is in VS Code Secret Storage." });
        }
        if (msg.type === "forget" && msg.provider && msg.provider !== "none") {
          await this.ctx.secrets.delete(secretId(msg.provider));
          post(await state());
          return void post({ type: "status", ok: true, text: `${msg.provider} key removed.` });
        }
        if (msg.type === "test") {
          const env = await llmEnv(this.ctx);
          if (!env) return void post({ type: "status", ok: false, text: "Choose a provider and save a key first." });
          const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();
          const res = await runPython(["-m", "shield.llm", "test"], { cwd, timeoutMs: 60_000, env });
          const out = JSON.parse(res.stdout || "{}");
          return void post({ type: "status", ok: !!out.ok, text: out.ok ? `Connected to ${out.model} (${out.latency_ms} ms).` : `Failed: ${out.error ?? (res.stderr.trim().split("\n").pop() || "no output")}` });
        }
      } catch (e) {
        post({ type: "status", ok: false, text: e instanceof Error ? e.message : String(e) });
      }
    });
  }
}

function html(nonce: string, csp: string): string {
  return `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${csp} 'unsafe-inline'; script-src 'nonce-${nonce}';">
<style>
 body{font-family:var(--vscode-font-family);color:var(--vscode-foreground);padding:8px}
 label{display:block;margin:8px 0 2px} input,select{width:100%;box-sizing:border-box;background:var(--vscode-input-background);color:var(--vscode-input-foreground);border:1px solid var(--vscode-input-border,transparent);padding:4px}
 button{margin:8px 6px 0 0;background:var(--vscode-button-background);color:var(--vscode-button-foreground);border:0;padding:5px 10px;cursor:pointer}
 button.sec{background:var(--vscode-button-secondaryBackground);color:var(--vscode-button-secondaryForeground)}
 .muted{opacity:.75;font-size:.9em} .ok{color:var(--vscode-testing-iconPassed)} .bad{color:var(--vscode-errorForeground)}
</style></head><body>
<label for="p">Provider</label>
<select id="p"><option value="none">None (deterministic only)</option><option value="groq">Groq (development)</option><option value="anthropic">Anthropic Claude (production)</option></select>
<div id="cfg">
 <label for="k">API key <span id="ks" class="muted"></span></label><input id="k" type="password" autocomplete="off" placeholder="leave blank to keep the stored key">
 <label for="m">Model</label><input id="m" placeholder="provider default">
</div>
<button id="save">Save</button><button id="test" class="sec">Test</button><button id="forget" class="sec">Forget key</button>
<p id="st" role="status"></p>
<p class="muted">Used only for “Explain with AI”. Sent: rule, engine, severity and masked evidence; never file contents or raw values. Keys live in VS Code Secret Storage. Rotate any key that was ever pasted into chat or committed.</p>
<script nonce="${nonce}">
 const vs=acquireVsCodeApi(); const $=id=>document.getElementById(id); let keys={};
 const sync=()=>{const p=$('p').value;$('cfg').style.display=p==='none'?'none':'block';$('ks').textContent=p!=='none'&&keys[p]?'(stored)':'(not set)';$('forget').disabled=p==='none'||!keys[p]};
 $('p').onchange=()=>{$('m').value='';sync()};
 $('save').onclick=()=>{vs.postMessage({type:'save',provider:$('p').value,model:$('m').value,key:$('k').value});$('k').value=''};
 $('test').onclick=()=>{$('st').textContent='Testing…';$('st').className='';vs.postMessage({type:'test'})};
 $('forget').onclick=()=>vs.postMessage({type:'forget',provider:$('p').value});
 window.addEventListener('message',e=>{const m=e.data;
  if(m.type==='state'){keys=m.keys;$('p').value=m.provider;$('m').value=m.model;sync()}
  if(m.type==='status'){$('st').textContent=m.text;$('st').className=m.ok?'ok':'bad'}});
 vs.postMessage({type:'ready'});
</script></body></html>`;
}
