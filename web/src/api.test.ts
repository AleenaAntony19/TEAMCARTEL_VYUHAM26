import { test } from "node:test";
import assert from "node:assert/strict";
import { defaultSelection, type Finding } from "./api.ts";

const f = (id: string, severity: Finding["severity"], actions: Finding["actions"]): Finding => ({
  id, severity, actions, type: "X", confidence: 1, layer: "visible", location: { layer: "visible" },
  masked: "", evidence: "", analyzer: "", checks: [], recommendation: "",
});

test("default selection picks medium+ with an action, preferring token", () => {
  const sel = defaultSelection([f("a", "critical", ["token", "mask", "remove"]), f("b", "low", ["token"]), f("c", "high", ["remove"]), f("d", "high", [])]);
  assert.deepEqual(sel, { a: "token", c: "remove" });
});
