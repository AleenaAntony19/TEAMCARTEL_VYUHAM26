"""Dialectic agent swarm over the Shield·Scout MCP tools (binding, bounded, token-aware).

Run (document or code workspace session):
  MetaPlanner      plans and spawns specialists (real child agents with scoped MCP tools)
  Round 1          PrivacyHawk claims · PragmaticDev challenges · StatutoryAuditor proves (validate_checksum)
  Round 2          FormatGuard (documents, measure_layout) / RefactorBot (code) propose non-destructive fixes
                   SwarmAdjudicator issues the binding plan
  Execute          plan -> execute_destructive_redaction / refactor_code_secret
  Red team         adversarial_penetration_test / rescan_workspace; MetaPlanner replans (max 3 cycles)

Not delegated to the LLM: the tool-side safety floor (verified IDs, PAN, bank, passport, UPI, GSTIN,
coordinates, faces are always redacted) and the "clean" verdict, which is the attack tool's real result.
The deterministic persona ring (review.py) runs first and is the swarm's grounding: its checks are
included as evidence, and dismissed placeholders never reach the swarm.
"""
from __future__ import annotations

import asyncio
import time
from typing import Callable

from . import llm
from .agent_runtime import AgentResult, AutonomousAgent
from .mcp.tools import (
    SESSIONS,
    adversarial_penetration_test,
    execute_destructive_redaction,
    list_code_findings,
    list_findings,
    refactor_code_secret,
    rescan_workspace,
)

MAX_CYCLES = 3
JSON_ONLY = " Values are masked; never guess them. Ground every claim in a tool observation or the given findings. Finish with JSON only."
OPINIONS = ' {"opinions":[{"id":str,"stance":"redact"|"keep","reason":str}]}'
DOC_ACTIONS = {"token", "mask", "remove", "keep"}
CODE_ACTIONS = {"move_to_env", "redact_pii", "fake_pii", "yaml_safe_load", "requests_verify", "keep"}


CHECKSUM_TYPES = {"IN_AADHAAR", "CREDIT_CARD", "IN_BANK_ACCOUNT", "POTENTIAL_LEAK"}


def _compact(findings: list[dict]) -> list[dict]:
    """What agents need, nothing more: every later LLM step re-sends it, so it dominates token use."""
    keys = ("id", "type", "rule", "layer", "masked", "file", "line", "fixes")
    out = []
    for f in findings:
        c = {k: f[k] for k in keys if f.get(k) not in (None, "", [])}
        ctx = f.get("context") or f.get("evidence") or ""
        if ctx:
            c["ctx"] = ctx[:70]
        out.append(c)
    return out


def _personas(kind: str) -> dict[str, tuple[str, list[str]]]:
    look = "list_findings" if kind == "document" else "list_code_findings"
    return {
        "PrivacyHawk": ("🦅 Zero-trust DPDP Act 2023 advocate: argue to redact anything that can identify a person or grant access.", []),
        "PragmaticDev": ("💻 Challenge false positives with context: placeholders, RFC 2606 test e-mails, sample/test data, invoice/order numbers, public org names.", [look]),
        "StatutoryAuditor": ("⚖️ Prove identifiers before ruling: call validate_checksum on every Aadhaar/card/12-digit finding; cite the law that applies.",
                             ["validate_checksum"] if kind == "document" else [look]),
    }


async def run_agentic(session_id: str, cfg: llm.LLMConfig, on_event: Callable[[dict], None] | None = None, transport=None) -> dict:
    s = SESSIONS[session_id]
    kind = s.kind
    findings = list_findings(session_id)["findings"] if kind == "document" else list_code_findings(session_id)["findings"]
    agents: list[AgentResult] = []

    def agent(name, prompt, tools):
        return AutonomousAgent(name, prompt, tools, cfg, session_id, on_event, 0, transport)

    def emit(**ev):
        if on_event:
            on_event({"ts": time.time(), **ev})

    if not findings:
        return {"clean": True, "cycles": 0, "decisions": [], "agents": [], "tokens": 0, "llm_calls": 0, "tool_calls": 0, "kind": kind}

    # ---- MetaPlanner: dynamic specialists
    if kind == "document":
        menu = ("SovereignPIIAgent [validate_checksum] for Indian IDs/cards; DocumentForensicAgent [extract_ocr_region] for scans "
                "or images; VisualLikenessAgent [compute_perceptual_pdq, compute_pca_projection] for photos")
    else:
        menu = "SecretsAuditor [list_code_findings] for credentials; PiiFixtureAuditor [list_code_findings] for personal data in code"
    plan = await agent("MetaPlanner",
                       f"You plan a privacy run over a {kind}. Spawn ONLY the specialists these findings need, all in ONE turn "
                       f"(parallel spawn_specialist_agent calls): {menu}. Spawn none if nothing needs them." + JSON_ONLY +
                       ' {"plan":str,"spawned":[str]}',
                       ["spawn_specialist_agent"]).execute({"kind": kind, "format": s.src.suffix.lstrip(".") or "dir",
                                                            "finding_types": sorted({f.get("type") or f.get("rule") for f in findings}),
                                                            "count": len(findings)}, max_steps=4)
    agents.append(plan)
    if kind == "document":
        findings = list_findings(session_id)["findings"]  # OCR specialists may have added findings
    briefs = [{"agent": c.name, "summary": str((c.verdict or {}).get("summary", ""))[:200]} for c in plan.children]
    compact = _compact(findings)

    # ---- Round 1: claim / challenge / proof (parallel; the auditor only when something has a checksum)
    personas = _personas(kind)
    eligible = [f for f in compact if f.get("type") in CHECKSUM_TYPES]
    if kind == "document" and not eligible:
        personas.pop("StatutoryAuditor")
    r1 = await asyncio.gather(*[
        agent(n, f"You are {n}. {brief}" + JSON_ONLY + OPINIONS, tools).execute(
            {"findings": eligible if n == "StatutoryAuditor" and kind == "document" else compact, "specialists": briefs}, max_steps=3)
        for n, (brief, tools) in personas.items()])
    agents.extend(r1)
    debate = {r.name: (r.verdict or {}).get("opinions", []) for r in r1}
    emit(agent="swarm", event="round", round=1, opinions={k: len(v) for k, v in debate.items()})

    # ---- Round 2: optimizer + binding adjudication
    if kind == "document":
        opt = await agent("FormatGuard",
                          "You optimize document redactions for layout: call measure_layout, then pick per finding the action that "
                          "removes the value while keeping table/line widths (mask keeps length; PDFs/images always fill boxes)."
                          + JSON_ONLY + ' {"proposals":[{"id":str,"action":"token"|"mask"|"remove","reason":str}]}',
                          ["measure_layout"]).execute({"finding_ids": [f["id"] for f in findings]}, max_steps=3)
        actions, act_desc = DOC_ACTIONS, '"token"|"mask"|"remove"|"keep"'
    else:
        opt = await agent("RefactorBot",
                          "You optimize code fixes so nothing breaks: choose per finding the safest fix from its `fixes` list "
                          "(move_to_env for secrets keeps the code running via os.environ/process.env; fake_pii keeps tests valid)."
                          + JSON_ONLY + ' {"proposals":[{"id":str,"action":str,"reason":str}]}',
                          []).execute({"findings": compact}, max_steps=2)
        actions, act_desc = CODE_ACTIONS, '"move_to_env"|"redact_pii"|"fake_pii"|"yaml_safe_load"|"requests_verify"|"keep"'
    agents.append(opt)
    debate[opt.name] = (opt.verdict or {}).get("proposals", [])

    # compact stance table: {id: {"type":..., "PrivacyHawk": "redact: reason", ...}}
    table: dict[str, dict] = {f["id"]: {"type": f.get("type") or f.get("rule")} for f in findings}
    for who, items in debate.items():
        for o in items if isinstance(items, list) else []:
            if isinstance(o, dict) and o.get("id") in table:
                table[o["id"]][who] = f"{o.get('stance') or o.get('action')}: {str(o.get('reason', ''))[:60]}"
    adj = await agent("SwarmAdjudicator",
                      "🧠 Synthesize the debate into ONE binding plan. Everything is redacted by default with the optimizer's action. "
                      "List as keep ONLY findings PragmaticDev showed to be placeholders/test/non-personal; a valid checksum always means "
                      "redact (Rule of Mathematical Superiority). You may override an action." + JSON_ONLY +
                      ' {"keep":[{"finding_id":str,"reason":str}],"actions":[{"finding_id":str,"action":' + act_desc + "}]}",
                      []).execute({"debate": table}, max_steps=2)
    agents.append(adj)

    # ---- binding plan (code-enforced grounding: a keep must be backed by PragmaticDev's challenge)
    known = {f["id"]: f for f in findings}
    verdict = adj.verdict or {}
    proposed = {o["id"]: o.get("action") for o in debate.get(opt.name, []) if isinstance(o, dict) and o.get("id") in known}
    override = {a["finding_id"]: a["action"] for a in verdict.get("actions", []) if isinstance(a, dict) and a.get("finding_id") in known and a.get("action") in actions}
    challenged = {o["id"] for o in debate.get("PragmaticDev", []) if isinstance(o, dict) and o.get("stance") == "keep"}
    keeps, rejected = {}, []
    for k in verdict.get("keep", []):
        if isinstance(k, dict) and k.get("finding_id") in known:
            (keeps.__setitem__(k["finding_id"], str(k.get("reason", ""))[:120]) if k["finding_id"] in challenged else rejected.append(k["finding_id"]))
    default = "token" if kind == "document" else "move_to_env"
    decisions = []
    for fid, f in known.items():
        if fid in keeps:
            decisions.append({"finding_id": fid, "action": "keep", "reason": keeps[fid]})
            continue
        act = override.get(fid) or proposed.get(fid) or default
        if kind == "workspace" and act not in (f.get("fixes") or []):
            act = next((x for x in ("move_to_env", "fake_pii", "redact_pii", "yaml_safe_load", "requests_verify") if x in (f.get("fixes") or [])), "keep")
        if act not in actions or act == "keep":
            act = default if kind == "document" else act
        why = "keep rejected: no PragmaticDev challenge" if fid in rejected else ("adjudicator" if fid in override else "optimizer/default")
        decisions.append({"finding_id": fid, "action": act, "reason": why})
    missing = [] if adj.verdict else list(known)
    emit(agent="SwarmAdjudicator", event="binding_plan", decisions=len(decisions), fail_safe=len(missing), keeps=len(keeps), rejected_keeps=len(rejected))

    # ---- Execute binding plan + red team / replan
    for cycle in range(1, MAX_CYCLES + 1):
        strategy = "standard" if cycle == 1 else "aggressive"
        if kind == "document":
            if cycle == 1 or s.cycles < cycle:
                res = execute_destructive_redaction(session_id, [{"finding_id": d["finding_id"], "action": d["action"]} for d in decisions], strategy)
                emit(agent="executor", event="redaction", observation=res)
            team = agent("AdversarialRedTeamAgent", "Attack the sanitized output with adversarial_penetration_test and report leaks." + JSON_ONLY +
                         ' {"clean":bool,"failed_attacks":[str]}', ["adversarial_penetration_test"])
        else:
            if cycle == 1:
                for d in decisions:
                    if d["action"] != "keep":
                        res = refactor_code_secret(session_id, d["finding_id"], d["action"])
                        emit(agent="executor", event="refactor", finding=d["finding_id"], observation=res)
                s.cycles = 1
            team = agent("AdversarialRedTeamAgent", "Re-scan the workspace with rescan_workspace and report what survived." + JSON_ONLY +
                         ' {"clean":bool,"remaining":[str]}', ["rescan_workspace"])
        agents.append(await team.execute({"cycle": cycle}, max_steps=3))
        if s.last_attack is None or s.last_attack.get("cycle") != s.cycles:
            (adversarial_penetration_test if kind == "document" else rescan_workspace)(session_id)  # never skip verification
        if s.last_attack["clean"] or cycle == MAX_CYCLES:
            break
        if kind == "document":
            replan = await agent("MetaPlanner", "The red team recovered data. Re-run execute_destructive_redaction with strategy "
                                 '"aggressive" and the same or wider decisions.' + JSON_ONLY + ' {"strategy":str,"reason":str}',
                                 ["execute_destructive_redaction"]).execute(
                {"failed_attacks": [a for a in s.last_attack["attacks"] if not a["passed"]], "decisions": decisions}, max_steps=3)
        else:
            replan = await agent("MetaPlanner", "Fixes left findings behind. Call refactor_code_secret for each remaining finding with a "
                                 "fix from its fixes list." + JSON_ONLY + ' {"fixed":[str]}',
                                 ["list_code_findings", "refactor_code_secret"]).execute({"remaining": s.last_attack["remaining"]}, max_steps=4)
            s.cycles += 1
        agents.append(replan)

    every = [a for a in agents] + [c for a in agents for c in a.children]
    return {
        "kind": kind,
        "clean": bool(s.last_attack and s.last_attack["clean"]),
        "cycles": s.cycles,
        "attacks": (s.last_attack or {}).get("attacks", []),
        "remaining": (s.last_attack or {}).get("remaining", []),
        "decisions": decisions,
        "fail_safe_defaults": len(missing) if kind == "document" else 0,
        "agents": [a.summary() for a in agents],
        "llm_calls": sum(a.steps_taken for a in every),
        "tool_calls": sum(len(a.tool_calls) for a in every),
        "tokens": sum(a.tokens for a in every),
        "output": str(s.output) if s.output else None,
    }
