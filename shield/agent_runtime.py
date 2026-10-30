"""ReAct runtime: LLM agents that act through the Shield·Scout MCP server with native tool calling.

Each step: the model sees its task plus prior tool observations, may call tools (executed for real via
`server.call_tool`), and finishes with a JSON verdict. Bounded by max_steps, spawn depth and child count.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Callable

from . import llm
from .llm import parse_json
from .mcp.tools import SESSIONS, server

MAX_CHILDREN = 4
MAX_DEPTH = 1  # the root may spawn specialists; specialists may not spawn further

SPAWN_TOOL = {
    "name": "spawn_specialist_agent",
    "description": "Spawn a specialist sub-agent with a scoped tool list and a goal; it runs its own ReAct loop and returns its JSON verdict.",
    "input_schema": {
        "type": "object",
        "properties": {
            "role": {"type": "string", "description": "e.g. SovereignPIIAgent, DocumentForensicAgent, VisualLikenessAgent"},
            "goal": {"type": "string"},
            "allowed_tools": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["role", "goal", "allowed_tools"],
    },
}


@dataclass
class AgentResult:
    name: str
    steps_taken: int = 0
    tool_calls: list[dict] = field(default_factory=list)
    verdict: dict | None = None
    text: str = ""
    error: str = ""
    tokens: int = 0
    children: list["AgentResult"] = field(default_factory=list)

    def summary(self) -> dict:
        return {"name": self.name, "steps": self.steps_taken, "tokens": self.tokens, "tools": [c["name"] for c in self.tool_calls],
                "verdict": self.verdict, "error": self.error, "children": [c.summary() for c in self.children]}


async def mcp_tools(names: list[str]) -> list[dict]:
    """MCP tool schemas for `names`, with session_id removed (the runtime injects it)."""
    out = []
    for t in await server.list_tools():
        if t.name in names:
            schema = json.loads(json.dumps(t.input_schema))
            schema.get("properties", {}).pop("session_id", None)
            schema["required"] = [r for r in schema.get("required", []) if r != "session_id"]
            out.append({"name": t.name, "description": t.description or "", "input_schema": schema})
    return out


class AutonomousAgent:
    def __init__(self, name: str, system_prompt: str, tools: list[str], cfg: llm.LLMConfig, session_id: str,
                 on_event: Callable[[dict], None] | None = None, depth: int = 0, transport=None):
        self.name, self.system_prompt, self.tool_names = name, system_prompt, tools
        self.cfg, self.session_id, self.on_event, self.depth, self.transport = cfg, session_id, on_event, depth, transport
        self.scratchpad: list[dict] = []
        self.children: list[AgentResult] = []

    def _emit(self, **ev):
        if self.on_event:
            self.on_event({"agent": self.name, "depth": self.depth, "ts": time.time(), **ev})

    async def _call(self, name: str, args: dict) -> dict:
        if name == "spawn_specialist_agent":
            return await self._spawn(args)
        if name not in self.tool_names:
            return {"error": f"tool '{name}' is not permitted for {self.name}"}
        try:
            res = await server.call_tool(name, {**args, "session_id": self.session_id})
        except Exception as exc:  # bad arguments or tool failure: the model sees the error and can correct itself
            return {"error": str(exc).split("\n")[0][:300]}
        text = res.content[0].text if res.content else "{}"
        try:
            return json.loads(text)
        except ValueError:
            return {"error": text[:300]}

    async def _spawn(self, args: dict) -> dict:
        if self.depth >= MAX_DEPTH or len(self.children) >= MAX_CHILDREN:
            return {"error": "spawn limit reached"}
        allowed = [t for t in args.get("allowed_tools", []) if t != "spawn_specialist_agent"]
        role = re.sub(r"[^A-Za-z0-9_]", "", str(args.get("role", "Specialist")))[:40] or "Specialist"
        child = AutonomousAgent(
            role,
            f"You are {role}, a specialist privacy-forensics agent. Goal: {args.get('goal', '')}. "
            "Use your tools on the session (values are masked; never guess them). "
            'Finish with JSON only: {"findings": [{"id": str, "assessment": str}], "summary": str}.',
            allowed, self.cfg, self.session_id, self.on_event, self.depth + 1, self.transport,
        )
        self._emit(event="spawn", child=role, tools=allowed)
        sess = SESSIONS.get(self.session_id)
        brief = [{"id": fid, "type": e.type, "masked": "•" * max(0, len(e.value) - 4) + e.value[-4:]} for fid, e in (sess.findings.items() if sess else [])][:40]
        result = await child.execute({"goal": args.get("goal", ""), "findings": brief}, max_steps=4)
        self.children.append(result)
        return {"agent": role, "steps": result.steps_taken, "verdict": result.verdict, "error": result.error}

    async def execute(self, task_input: dict, max_steps: int = 5) -> AgentResult:
        result = AgentResult(self.name)
        tools = await mcp_tools(self.tool_names)
        if self.depth < MAX_DEPTH and "spawn_specialist_agent" in self.tool_names:
            tools.append(SPAWN_TOOL)
        self.scratchpad = [{"role": "user", "content": json.dumps(task_input, separators=(",", ":"))}]
        for step in range(1, max_steps + 1):
            result.steps_taken = step
            try:
                turn = await asyncio.to_thread(llm.chat_tools, self.cfg, self.system_prompt, self.scratchpad, tools, self.transport)
            except llm.LLMError as exc:
                result.error = str(exc)
                self._emit(event="error", error=result.error)
                break
            result.tokens += turn.get("tokens", 0)
            self.scratchpad.append({"role": "assistant", "text": turn["text"], "tool_calls": turn["tool_calls"]})
            if not turn["tool_calls"]:
                result.text, result.verdict = turn["text"], parse_json(turn["text"])
                self._emit(event="final", verdict=result.verdict)
                break
            async def run_call(call):
                t = time.monotonic()
                obs = await self._call(call["name"], call["args"] if isinstance(call["args"], dict) else {})
                return call, obs, int((time.monotonic() - t) * 1000)

            # several tool calls in one turn (e.g. spawning 3 specialists) run concurrently
            for call, obs, ms in await asyncio.gather(*[run_call(c) for c in turn["tool_calls"]]):
                result.tool_calls.append({"name": call["name"], "args": call["args"], "ms": ms, "ok": "error" not in obs})
                self._emit(event="tool", action=call["name"], args=call["args"], observation=obs, ms=ms)
                # compact observations: they are re-sent every later step, so they dominate token use
                self.scratchpad.append({"role": "tool", "id": call["id"], "name": call["name"], "content": json.dumps(obs, separators=(",", ":"))[:2500]})
        else:
            result.error = result.error or f"no final answer within {max_steps} steps"
        result.children = self.children
        return result


def session_findings(session_id: str) -> list[dict]:
    from .mcp.tools import list_findings

    return list_findings(session_id)["findings"] if session_id in SESSIONS else []
