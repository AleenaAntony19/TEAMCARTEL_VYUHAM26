// Runs inside a real VS Code instance (via run.mjs). Plain asserts, no test framework.
const assert = require("node:assert/strict");
const path = require("node:path");
const vscode = require("vscode");

async function until(fn, ms = 120000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("timed out waiting for condition");
}

exports.run = async () => {
  const ws = vscode.workspace.workspaceFolders[0].uri.fsPath;
  const ext = vscode.extensions.getExtension("shield-scout.shield-code");
  assert.ok(ext, "extension installed");
  const api = await ext.activate();
  const fs = require("node:fs");
  const exe = path.join(ext.extensionPath, "engine", "shield-engine", process.platform === "win32" ? "shield-engine.exe" : "shield-engine");
  console.log(`SHIELD-IT engine: ${exe} exists=${fs.existsSync(exe)} pythonPath=${JSON.stringify(vscode.workspace.getConfiguration("shieldCode").get("pythonPath"))}`);

  await vscode.commands.executeCommand("shieldCode.scanWorkspace");
  const cfg = vscode.Uri.file(path.join(ws, "app", "config.py"));
  const diags = await until(() => { const d = vscode.languages.getDiagnostics(cfg); return d.length ? d : null; })
    .catch((e) => { throw new Error(`${e.message}; extension error: ${api.lastError()}`); });
  const secret = diags.find((d) => d.code === "OpenAI Token");
  assert.ok(secret, "OpenAI key diagnostic in config.py");
  assert.ok(!secret.message.includes(process.env.SHIELD_TEST_KEY), "diagnostic must not show the raw key");

  const doc = await vscode.workspace.openTextDocument(cfg);
  const actions = await vscode.commands.executeCommand("vscode.executeCodeActionProvider", doc.uri, secret.range);
  const titles = actions.map((a) => a.title);
  assert.ok(titles.some((t) => t.includes("Move secret to .env")), `quick fix offered: ${titles}`);

  const img = vscode.Uri.file(path.join(ws, "docs", "kyc.png"));
  const imgDiags = vscode.languages.getDiagnostics(img);
  assert.ok(imgDiags.some((d) => d.code === "OCR_PII" && /x=\d+ y=\d+/.test(d.message)), "OCR finding with bounding box on image");

  const users = vscode.Uri.file(path.join(ws, "tests", "users.json"));
  assert.ok(vscode.languages.getDiagnostics(users).some((d) => d.code === "IN_AADHAAR"), "Aadhaar in fixture");
  console.log(`SHIELD-IT OK: ${diags.length} config.py diags, ${imgDiags.length} image diags, actions: ${titles.join(" | ")}`);
};
