// Downloads a separate VS Code build and runs suite.cjs against a generated leaky workspace.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { runTests } from "@vscode/test-electron";

delete process.env.ELECTRON_RUN_AS_NODE; // set when launched from a VS Code terminal; Electron must not run as plain Node
const here = path.dirname(new URL(import.meta.url).pathname);
const ext = path.resolve(here, "../..");
const engine = path.resolve(ext, "..");
const python = process.env.SHIELD_PYTHON || "python3";

const ws = mkdtempSync(path.join(tmpdir(), "shield-ws-"));
const key = "sk-proj-" + randomBytes(36).toString("base64url").replace(/[-_]/g, "a").slice(0, 48);
for (const d of ["app", "tests", "docs", ".vscode"]) mkdirSync(path.join(ws, d), { recursive: true });
writeFileSync(path.join(ws, "app/config.py"), `DEBUG = False\nOPENAI_API_KEY = "${key}"\n`);
writeFileSync(path.join(ws, "tests/users.json"), JSON.stringify({ aadhaar: "2345 6789 0124" }));
copyFileSync(path.join(engine, "demo/out/kyc.png"), path.join(ws, "docs/kyc.png"));
// a cached AI finding: shows without network, provider or consent
mkdirSync(path.join(ws, ".shield/cache"), { recursive: true });
writeFileSync(path.join(ws, ".shield/cache/cognitive.json"), JSON.stringify({ "docs/kyc.png": {
  sha: createHash("sha256").update(readFileSync(path.join(ws, "docs/kyc.png"))).digest("hex"), model: "groq/test",
  findings: [{ id: "aitest", engine: "cognitive", rule: "AI_SENSITIVE", severity: "high", file: "docs/kyc.png", line: 0, col: 0, end_line: 0, end_col: 0,
    message: "HEALTH visible in image at x=1 y=2 w=3 h=4", masked: "•••", fixes: ["redact_image", "ignore"], confidence: 0.6, bbox: [1, 2, 3, 4], rationale: "medical condition" }],
} }));
// SHIELD_IT_BUNDLED=1: no Python settings at all, so the extension must use vscode/engine/shield-engine
const bundled = process.env.SHIELD_IT_BUNDLED === "1";
writeFileSync(path.join(ws, ".vscode/settings.json"), JSON.stringify(bundled ? {} : { "shieldCode.pythonPath": python, "shieldCode.enginePath": engine }));
execFileSync("git", ["init", "-q"], { cwd: ws });

await runTests({
  extensionDevelopmentPath: ext,
  extensionTestsPath: path.join(here, "suite.cjs"),
  launchArgs: [ws, "--disable-extensions", "--skip-welcome", "--skip-release-notes"],
  extensionTestsEnv: { SHIELD_TEST_KEY: key },
});
