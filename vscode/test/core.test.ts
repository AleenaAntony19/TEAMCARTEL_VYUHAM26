import { test } from "node:test";
import assert from "node:assert/strict";
import { applyEdits, atLeast, debounce, findingRange, parseScan, scanArgs, type Finding } from "../src/core.ts";

const base: Finding = {
  id: "x", engine: "secrets", rule: "OpenAI Token", severity: "critical", file: "a.py", line: 2, col: 5, end_line: 2, end_col: 20,
  message: "", masked: "sk-p…ab", fixes: [], in_history: false, confidence: 0.9, evidence: "", recommendation: "", bbox: null,
};

test("findingRange converts 1-based scanner columns and handles whole-file findings", () => {
  assert.deepEqual(findingRange(base), { startLine: 1, startCol: 4, endLine: 1, endCol: 19 });
  assert.deepEqual(findingRange({ ...base, line: 0, col: 0, end_line: 0, end_col: 0 }), { startLine: 0, startCol: 0, endLine: 0, endCol: 0 });
});

test("applyEdits matches the Python edit model (insert + replace, bottom-up)", () => {
  const out = applyEdits("a = 1\nb = 2\n", [
    { file: "f", line: 1, col: 0, end_line: 1, end_col: 0, new_text: "import os\n" },
    { file: "f", line: 2, col: 4, end_line: 2, end_col: 5, new_text: "X" },
  ]);
  assert.equal(out, "import os\na = 1\nb = X\n");
});

test("severity filter and arg building", () => {
  assert.ok(atLeast("critical", "high") && !atLeast("low", "medium"));
  const args = scanArgs("/w", { engines: ["secrets"], ocr: false, maxFileMB: 2, exclude: ["dist/*"], concurrency: 3, timeout: 60, files: ["a.py"] });
  assert.deepEqual(args.slice(-5), ["--no-ocr", "--exclude", "dist/*", "--files", "a.py"]);
  assert.equal(args[args.indexOf("--workers") + 1], "3");
});

test("parseScan rejects unexpected output", () => {
  assert.throws(() => parseScan('{"nope": 1}'));
  assert.equal(parseScan('{"version":2,"root":"/","findings":[],"stats":{}}').findings.length, 0);
});

test("debounce collapses bursts", async () => {
  let n = 0;
  const d = debounce(() => { n++; }, 20);
  for (let i = 0; i < 5; i++) d();
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(n, 1);
});
