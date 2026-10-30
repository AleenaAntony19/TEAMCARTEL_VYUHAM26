import * as path from "node:path";
import * as vscode from "vscode";
import {
  FILE_SCOPED, FIX_TITLES, applyEdits, atLeast, debounce, describe, findingRange, parseScan, scanArgs,
  type Finding, type FixPlan, type ScanResult, type Severity,
} from "./core.ts";
import { RunError, runPython, setExtensionRoot } from "./runner.ts";
import { AiViewProvider, llmEnv } from "./aiView.ts";
import { toolJson, withMcp } from "./mcpClient.ts";

const PREVIEW_SCHEME = "shield-preview";

let output: vscode.OutputChannel;
let diagnostics: vscode.DiagnosticCollection;
let status: vscode.StatusBarItem;
const results = new Map<string, ScanResult>(); // workspace root -> last scan
const byDiagnostic = new WeakMap<vscode.Diagnostic, Finding>();
const previews = new Map<string, string>();

function settings() {
  const c = vscode.workspace.getConfiguration("shieldCode");
  return {
    engines: c.get<string[]>("engines") ?? [],
    ocr: c.get<boolean>("ocr.enabled") ?? true,
    maxFileMB: c.get<number>("maxFileSizeMB") ?? 2,
    exclude: c.get<string[]>("exclude") ?? [],
    concurrency: c.get<number>("concurrency") ?? 4,
    timeout: c.get<number>("timeoutSeconds") ?? 300,
    minSeverity: (c.get<string>("minSeverity") ?? "low") as Severity,
    scanOnSave: c.get<boolean>("scanOnSave") ?? true,
  };
}

// ---------- results → diagnostics / tree ----------
class FindingsTree implements vscode.TreeDataProvider<vscode.TreeItem> {
  private emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.emitter.event;
  refresh() { this.emitter.fire(); }

  getTreeItem(e: vscode.TreeItem) { return e; }

  getChildren(parent?: vscode.TreeItem): vscode.TreeItem[] {
    const min = settings().minSeverity;
    const all = [...results.entries()].flatMap(([root, r]) => r.findings.filter((f) => atLeast(f.severity, min)).map((f) => ({ root, f })));
    if (!parent) {
      const groups: vscode.TreeItem[] = (["critical", "high", "medium", "low"] as Severity[])
        .map((s) => ({ s, n: all.filter((x) => x.f.severity === s).length }))
        .filter((g) => g.n)
        .map((g) => Object.assign(new vscode.TreeItem(`${g.s} (${g.n})`, vscode.TreeItemCollapsibleState.Expanded), { id: `sev:${g.s}`, contextValue: g.s }));
      const notes = problems();
      if (notes.length) groups.push(Object.assign(new vscode.TreeItem(`Scan problems (${notes.length})`, vscode.TreeItemCollapsibleState.Collapsed), { id: "problems", contextValue: "problems", iconPath: new vscode.ThemeIcon("warning") }));
      if (!groups.length) {
        const item = new vscode.TreeItem(results.size ? "No findings" : "▶ Click here to Scan Workspace");
        if (!results.size) {
          item.command = { command: "shieldCode.scanWorkspace", title: "Scan Workspace" };
          item.iconPath = new vscode.ThemeIcon("play");
        }
        groups.push(item);
      }
      return groups;
    }
    if (parent.id === "problems") return problems().map((t) => new vscode.TreeItem(t));
    return all.filter((x) => x.f.severity === parent.contextValue).map(({ root, f }) => {
      const item = new vscode.TreeItem(`${f.rule} · ${f.file}${f.line ? `:${f.line}` : ""}`);
      item.description = f.masked || f.engine;
      const tip = new vscode.MarkdownString(`**${f.rule}** (${f.engine}, ${Math.round(f.confidence * 100)}% confidence)\n\n${f.message}\n\n${f.evidence ? "`" + f.evidence.replace(/`/g, "'") + "`\n\n" : ""}_${f.recommendation}_`);
      if (f.rationale) tip.appendMarkdown("\n\n**Why:** ").appendText(f.rationale); // model text: never rendered as markdown
      item.tooltip = tip;
      item.contextValue = "finding";
      item.command = { command: "shieldCode.revealFinding", title: "Reveal", arguments: [root, f] };
      item.iconPath = new vscode.ThemeIcon(f.severity === "critical" || f.severity === "high" ? "error" : "warning");
      return Object.assign(item, { finding: { root, f } });
    });
  }
}

function problems(): string[] {
  return [...results.values()].flatMap((r) => [
    ...(r.stats.ocr?.startsWith("unavailable") ? [`OCR ${r.stats.ocr}`] : []),
    ...Object.entries(r.stats.engines).filter(([, v]) => v !== "ok").map(([k, v]) => `engine ${k}: ${v}`),
    ...(r.stats.cognitive?.error ? [`AI deep scan: ${r.stats.cognitive.error}`] : []),
    ...(r.stats.errors ?? []).map((e) => `${e.file}: ${e.engine} failed (${e.error})`),
  ]);
}

function publish(tree: FindingsTree) {
  diagnostics.clear();
  const min = settings().minSeverity;
  let crit = 0;
  for (const [r, res] of results) {
    const perFile = new Map<string, vscode.Diagnostic[]>();
    for (const f of res.findings) {
      if (!atLeast(f.severity, min) || f.file === "history") continue;
      if (f.severity === "critical") crit++;
      const rg = findingRange(f);
      const d = new vscode.Diagnostic(
        new vscode.Range(rg.startLine, rg.startCol, rg.endLine, Math.min(rg.endCol, 10_000)),
        `${describe(f)}\n→ ${f.recommendation}`,
        f.severity === "critical" || f.severity === "high" ? vscode.DiagnosticSeverity.Error : f.severity === "medium" ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information,
      );
      d.source = `Shield/${f.engine}`;
      d.code = f.rule;
      byDiagnostic.set(d, f);
      const list = perFile.get(f.file) ?? [];
      list.push(d);
      perFile.set(f.file, list);
    }
    for (const [file, list] of perFile) diagnostics.set(vscode.Uri.file(path.join(r, file)), list);
  }
  status.text = `$(shield) ${crit} critical`;
  status.show();
  tree.refresh();
}

// ---------- scanning ----------
async function scan(root: string, tree: FindingsTree, files?: string[], token?: vscode.CancellationToken, aiEnv?: Record<string, string>) {
  const s = settings();
  const engines = files ? s.engines.filter((e) => FILE_SCOPED.has(e)) : s.engines;
  const res = await runPython(scanArgs(root, { ...s, engines, files, cognitive: !!aiEnv }), { cwd: root, token, timeoutMs: (s.timeout + 15) * 1000, env: aiEnv });
  if (res.code !== 0 && res.code !== 1) throw new RunError(`scanner exited ${res.code}: ${res.stderr.trim().split("\n").pop() ?? ""}`);
  if (!res.stdout.trim()) throw new RunError(`engine produced no output (exit ${res.code}): ${res.stderr.trim().split("\n").slice(-3).join(" | ") || "no stderr"}`);
  const result = parseScan(res.stdout);
  if (files && results.has(root)) {
    // merge: replace only this file's findings from file-scoped engines
    const prev = results.get(root)!;
    const keep = prev.findings.filter((f) => !(files.includes(f.file) && FILE_SCOPED.has(f.engine)));
    results.set(root, { ...result, findings: [...keep, ...result.findings] });
  } else {
    results.set(root, result);
  }
  const st = result.stats;
  output.appendLine(`[${new Date().toISOString()}] ${root}: ${result.findings.length} findings, ${st.files} files, ${st.ms} ms, engines ${JSON.stringify(st.engines)}, OCR ${st.ocr}`);
  for (const e of st.errors ?? []) output.appendLine(`  error: ${e.file} (${e.engine}): ${e.error}`);
  const ai = st.cognitive;
  if (ai) output.appendLine(`  AI pass ${ai.model || "(cache only)"}: ${ai.sent} sent, ${ai.cached} cached, ${ai.skipped} over the file limit, ${ai.truncated} cut short`);
  if (aiEnv && ai?.error) void vscode.window.showWarningMessage(`Shield: AI deep scan stopped: ${ai.error}. Run it again to carry on; finished files are kept.`);
  if (aiEnv && ai?.skipped) void vscode.window.showWarningMessage(`Shield: ${ai.skipped} file(s) were not sent (30 per run). Run AI Deep Scan again for the next batch.`);
  if (aiEnv && ai?.truncated) void vscode.window.showWarningMessage(`Shield: ${ai.truncated} file(s) were longer than the AI limit; only the start of each was checked.`);
  if (st.ocr?.startsWith("unavailable") && s.ocr) void vscode.window.showWarningMessage(`Shield: OCR ${st.ocr}. Image text was not scanned.`);
  if (st.timed_out) void vscode.window.showWarningMessage("Shield: some analyzers timed out; results are partial (see Scan problems).");
  publish(tree);
}

/** Per-scan consent: raw text only leaves the machine after this dialog. Null means do not scan. */
async function deepScanConsent(ctx: vscode.ExtensionContext): Promise<Record<string, string> | null> {
  const env = await llmEnv(ctx);
  if (!env) {
    const go = await vscode.window.showInformationMessage("Shield: connect Groq or Claude in the AI Provider panel first.", "Open panel");
    if (go) await vscode.commands.executeCommand("shieldCode.ai.focus");
    return null;
  }
  const choice = await vscode.window.showWarningMessage(
    `Send image, document and text-note content from this workspace to ${env.SHIELD_LLM_PROVIDER}?`,
    { modal: true, detail: "Used to find sensitive data no rule covers. Values Shield already detected are blanked first, the rest is sent as raw text. Source code is not sent. Up to 30 files per run, 48,000 characters each; unchanged files come from a local cache." },
    "Send and scan",
  );
  return choice ? env : null;
}

function whyFlagged(f: Finding) {
  output.appendLine(`\n[Why flagged] ${f.rule} in ${f.file}${f.line ? `:${f.line}` : ""} · ${f.engine} · ${Math.round(f.confidence * 100)}% confidence`);
  output.appendLine(`  ${f.message}${f.masked ? ` (${f.masked})` : ""}`);
  if (f.rationale) output.appendLine(`  AI reason (advice, not evidence): ${f.rationale}`);
  if (f.evidence) output.appendLine(`  context: ${f.evidence}`);
  output.appendLine(`  next: ${f.recommendation}`);
  output.show(true);
}

async function pickFix(root: string, f: Finding, tree: FindingsTree) {
  const pick = await vscode.window.showQuickPick(f.fixes.map((fix) => ({ label: FIX_TITLES[fix] ?? fix, fix })), { title: `Fix ${f.rule} in ${f.file}` });
  if (pick) await previewFix(root, f, pick.fix, tree);
}

function scanAll(tree: FindingsTree, aiEnv?: Record<string, string>) {
  return vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: aiEnv ? "Shield: AI deep scan" : "Shield: scanning workspace", cancellable: true },
    async (progress, token) => {
      const rs = roots();
      if (!rs.length) return void vscode.window.showInformationMessage("Shield: open a folder first.");
      for (const [i, r] of rs.entries()) {
        progress.report({ message: `${path.basename(r)} (${i + 1}/${rs.length})`, increment: 100 / rs.length });
        await scan(r, tree, undefined, token, aiEnv);
      }
    },
  ).then(undefined, report);
}

function roots(): string[] {
  return (vscode.workspace.workspaceFolders ?? []).filter((f) => f.uri.scheme === "file").map((f) => f.uri.fsPath);
}

let lastError = "";

function report(e: unknown) {
  if (e instanceof vscode.CancellationError) return;
  const msg = e instanceof Error ? e.message : String(e);
  lastError = msg;
  output.appendLine(`error: ${msg}`);
  void vscode.window.showErrorMessage(`Shield: ${msg}`, "Show log").then((c) => c && output.show());
}

// ---------- fixes ----------
async function runFix(root: string, f: Finding, kind: string, dryRun: boolean): Promise<FixPlan> {
  const args = ["-m", "shield.codescan", "fix", root, "--id", f.id, "--kind", kind];
  if (FILE_SCOPED.has(f.engine)) args.push("--file", f.file);
  if (dryRun) args.push("--dry-run");
  const res = await runPython(args, { cwd: root, timeoutMs: 120_000 });
  const plan = JSON.parse(res.stdout || "{}") as FixPlan;
  if (plan.error || (res.code ?? 1) !== 0) throw new RunError(plan.error ?? res.stderr.trim().split("\n").pop() ?? "fix failed");
  return plan;
}

async function previewFix(root: string, f: Finding, kind: string, tree: FindingsTree) {
  const fileUri = vscode.Uri.file(path.join(root, f.file));
  const open = vscode.workspace.textDocuments.find((d) => d.uri.fsPath === fileUri.fsPath);
  if (open?.isDirty) {
    const ok = await vscode.window.showWarningMessage(`Save ${f.file} before previewing the fix?`, { modal: true }, "Save");
    if (ok !== "Save" || !(await open.save())) return;
  }
  const plan = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "Shield: preparing fix preview…" }, () => runFix(root, f, kind, true));
  if (!plan.edits.length && !plan.file_ops.length) {
    void vscode.window.showInformationMessage(`Shield: nothing to change. ${plan.notes.join(" ")}`);
    return;
  }
  if (plan.edits.length) {
    const original = Buffer.from(await vscode.workspace.fs.readFile(fileUri)).toString("utf8");
    const key = `/${f.file}?${Date.now()}`;
    previews.set(key, applyEdits(original, plan.edits.filter((e) => e.file === f.file)));
    await vscode.commands.executeCommand("vscode.diff", fileUri, vscode.Uri.from({ scheme: PREVIEW_SCHEME, path: `/${f.file}`, query: key }), `Shield fix preview: ${f.file}`);
  }
  const detail = [
    ...plan.edits.map((e) => `edit ${e.file}:${e.line}`),
    ...plan.file_ops.map((o) => o.summary || `${o.op} ${o.file}`),
    ...plan.notes.map((n) => `⚠ ${n}`),
  ].join("\n");
  const choice = await vscode.window.showWarningMessage(`Apply “${FIX_TITLES[kind] ?? kind}”?`, { modal: true, detail }, "Apply");
  if (choice !== "Apply") return;
  const applied = await runFix(root, f, kind, false);
  const rotate = applied.notes.filter((n) => /rotate/i.test(n));
  if (rotate.length) void vscode.window.showWarningMessage(`Shield: ${rotate.join(" ")}`);
  await scan(root, tree, FILE_SCOPED.has(f.engine) ? [f.file] : undefined);
}

async function explain(f: Finding, ctx: vscode.ExtensionContext) {
  const env = await llmEnv(ctx);
  if (!env) {
    const go = await vscode.window.showInformationMessage("Shield: connect Groq or Claude in the AI Provider panel first.", "Open panel");
    if (go) await vscode.commands.executeCommand("shieldCode.ai.focus");
    return;
  }
  const root = roots()[0] ?? process.cwd();
  // python filters to type/rule/engine/severity/masked/message before sending; raw values never leave
  const res = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "Shield: asking AI…" }, () =>
    runPython(["-m", "shield.llm", "explain"], { cwd: root, timeoutMs: 60_000, stdin: JSON.stringify(f), env }));
  const out = JSON.parse(res.stdout || "{}");
  if (out.error) throw new RunError(out.error);
  output.appendLine(`\n[AI ${out.provider}/${out.model}] ${f.rule} in ${f.file}:${f.line} (advice, not evidence)\n${out.explanation}`);
  output.show(true);
}

// ---------- activation ----------
export function activate(ctx: vscode.ExtensionContext): { lastError: () => string } {
  setExtensionRoot(ctx.extensionPath); // locates the bundled engine in platform builds
  output = vscode.window.createOutputChannel("Shield·Code");
  diagnostics = vscode.languages.createDiagnosticCollection("shield");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = "shieldCode.scanWorkspace";
  status.text = "$(shield) Shield";
  status.show();
  const tree = new FindingsTree();

  ctx.subscriptions.push(
    output, diagnostics, status,
    vscode.window.registerTreeDataProvider("shieldCode.findings", tree),
    vscode.window.registerWebviewViewProvider("shieldCode.ai", new AiViewProvider(ctx)),
    vscode.workspace.registerTextDocumentContentProvider(PREVIEW_SCHEME, { provideTextDocumentContent: (uri) => previews.get(uri.query) ?? "" }),

    vscode.commands.registerCommand("shieldCode.scanWorkspace", () => scanAll(tree)),
    vscode.commands.registerCommand("shieldCode.deepScan", async () => {
      const aiEnv = await deepScanConsent(ctx);
      if (aiEnv) await scanAll(tree, aiEnv);
    }),

    vscode.commands.registerCommand("shieldCode.scanFile", async () => {
      const doc = vscode.window.activeTextEditor?.document;
      const folder = doc && vscode.workspace.getWorkspaceFolder(doc.uri);
      if (!doc || !folder) return;
      await scan(folder.uri.fsPath, tree, [path.relative(folder.uri.fsPath, doc.uri.fsPath)]).catch(report);
    }),

    vscode.commands.registerCommand("shieldCode.revealFinding", async (root: string, f: Finding) => {
      const uri = vscode.Uri.file(path.join(root, f.file));
      if (!f.line) return vscode.commands.executeCommand("vscode.open", uri);
      const rg = findingRange(f);
      await vscode.window.showTextDocument(uri, { selection: new vscode.Range(rg.startLine, rg.startCol, rg.endLine, Math.min(rg.endCol, 10_000)) });
    }),

    vscode.commands.registerCommand("shieldCode.previewFix", (root: string, f: Finding, kind: string) => previewFix(root, f, kind, tree).catch(report)),
    vscode.commands.registerCommand("shieldCode.explainFinding", (f: Finding) => explain(f, ctx).catch(report)),
    vscode.commands.registerCommand("shieldCode.showOutput", () => output.show()),
    vscode.commands.registerCommand("shieldCode.whyFlagged", (item: { finding: { f: Finding } }) => whyFlagged(item.finding.f)),
    vscode.commands.registerCommand("shieldCode.pickFix", (item: { finding: { root: string; f: Finding } }) => pickFix(item.finding.root, item.finding.f, tree).catch(report)),

    vscode.commands.registerCommand("shieldCode.runSwarm", async () => {
      const root = roots()[0];
      if (!root) return;
      const env = await llmEnv(ctx);
      if (!env) {
        const go = await vscode.window.showInformationMessage("Shield: connect Groq or Claude in the AI Provider panel first.", "Open panel");
        if (go) await vscode.commands.executeCommand("shieldCode.ai.focus");
        return;
      }
      const ok = await vscode.window.showWarningMessage(
        "Run the AI agent swarm on this workspace?",
        { modal: true, detail: "Agents (MetaPlanner, PrivacyHawk, PragmaticDev, StatutoryAuditor, RefactorBot, SwarmAdjudicator, red team) decide and APPLY code fixes via MCP tools: secrets move to .env, test PII becomes synthetic. Originals are backed up to .shield/backup/. Findings are sent masked to the AI provider." },
        "Run swarm",
      );
      if (ok !== "Run swarm") return;
      await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "Shield: agent swarm (MCP)…", cancellable: false }, async (progress) => {
        await withMcp(root, env, async (client) => {
          progress.report({ message: "open_workspace" });
          const opened = toolJson(await client.callTool({ name: "open_workspace", arguments: { path: root } }));
          if (opened.error || !opened.session_id) throw new RunError(String(opened.error ?? "open_workspace failed"));
          progress.report({ message: `run_agent_swarm on ${opened.count} findings` });
          const res = toolJson(await client.callTool({ name: "run_agent_swarm", arguments: { session_id: opened.session_id } }, undefined, { timeout: 900_000 }));
          if (res.error) throw new RunError(String(res.error));
          output.appendLine(`\n[agent swarm] clean=${res.clean} cycles=${res.cycles} llm_calls=${res.llm_calls} tool_calls=${res.tool_calls} tokens=${res.tokens}`);
          for (const a of (res.agents as { name: string; steps: number; tokens: number; tools: string[]; error: string }[]) ?? [])
            output.appendLine(`  ${a.name}: ${a.steps} steps, ${a.tokens} tok, tools [${a.tools.join(", ")}] ${a.error}`);
          for (const d of (res.decisions as { finding_id: string; action: string; reason: string }[]) ?? [])
            output.appendLine(`  decision ${d.finding_id}: ${d.action} (${d.reason})`);
          output.show(true);
          void vscode.window.showInformationMessage(`Shield swarm: ${res.clean ? "clean" : "findings remain"} · ${res.tokens} tokens. Secrets moved to .env must still be rotated.`);
        });
        await scan(root, tree);
      }).then(undefined, report);
    }),

    vscode.commands.registerCommand("shieldCode.exportSarif", async () => {
      const root = roots()[0];
      if (!root) return;
      const target = await vscode.window.showSaveDialog({ defaultUri: vscode.Uri.file(path.join(root, "shield-report.sarif")), filters: { SARIF: ["sarif", "json"] } });
      if (!target) return;
      const s = settings();
      await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "Shield: exporting SARIF", cancellable: true }, (_p, token) => {
        const args = scanArgs(root, s);
        args[args.indexOf("--format") + 1] = "sarif";
        return runPython([...args, "--out", target.fsPath], { cwd: root, token, timeoutMs: (s.timeout + 15) * 1000 });
      },
      ).then(() => vscode.window.showInformationMessage(`Shield: SARIF written to ${target.fsPath}`), report);
    }),

    vscode.languages.registerCodeActionsProvider({ scheme: "file" }, {
      provideCodeActions(doc, _range, context) {
        const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
        if (!folder) return [];
        const actions: vscode.CodeAction[] = [];
        for (const d of context.diagnostics) {
          const f = byDiagnostic.get(d);
          if (!f) continue;
          for (const kind of f.fixes) {
            const a = new vscode.CodeAction(`Shield: ${FIX_TITLES[kind] ?? kind}…`, vscode.CodeActionKind.QuickFix);
            a.diagnostics = [d];
            a.command = { command: "shieldCode.previewFix", title: "Preview fix", arguments: [folder.uri.fsPath, f, kind] };
            actions.push(a);
          }
          const why = new vscode.CodeAction("Shield: Why flagged", vscode.CodeActionKind.QuickFix); // an empty kind is hidden from the Quick Fix menu
          why.command = { command: "shieldCode.whyFlagged", title: "Why flagged", arguments: [{ finding: { f } }] };
          actions.push(why);
          const ex = new vscode.CodeAction("Shield: Explain with AI (masked data only)", vscode.CodeActionKind.QuickFix);
          ex.command = { command: "shieldCode.explainFinding", title: "Explain", arguments: [f] };
          actions.push(ex);
        }
        return actions;
      },
    }, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
  );

  const onSave = debounce((doc: vscode.TextDocument) => {
    const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
    if (!folder || !settings().scanOnSave || !results.has(folder.uri.fsPath)) return; // only after a first full scan
    scan(folder.uri.fsPath, tree, [path.relative(folder.uri.fsPath, doc.uri.fsPath)]).catch(report);
  }, 1000);
  ctx.subscriptions.push(vscode.workspace.onDidSaveTextDocument(onSave));
  return { lastError: () => lastError }; // used by the integration test
}

export function deactivate() { }
