#!/usr/bin/env bash
# Every automated check: Python tests + lint, web typecheck/test/build, extension typecheck/test/build, mock-web scout run.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
# local dev: activate a venv if SHIELD_VENV points at one; CI already has the right python on PATH
if [ -n "${SHIELD_VENV:-}" ] && [ -f "$SHIELD_VENV/bin/activate" ]; then source "$SHIELD_VENV/bin/activate"; fi
export PYTHONPATH="$ROOT_DIR" SHIELD_ALLOW_LOCAL=1

echo "==> fixtures + mock web"
python demo/make_fixtures.py demo/out > /dev/null
python demo/make_mockweb.py > /dev/null

echo "==> pytest"
pytest -q

echo "==> ruff (errors only)"
ruff check shield tests --select F,E9

echo "==> web"
(cd web && npm ci --no-audit --no-fund >/dev/null && npm run typecheck && npm test && npm run build >/dev/null)

echo "==> vscode extension"
(cd vscode && npm ci --no-audit --no-fund >/dev/null && npm run typecheck && npm test && npm run build >/dev/null)

echo "==> codescan CLI emits valid JSON"
python -m shield.codescan scan shield --no-ocr --format json | python -m json.tool > /dev/null || [ "${PIPESTATUS[0]}" = 1 ]

echo "==> mock leak web scout run"
python demo/serve.py &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
sleep 1
python - <<'PY'
import asyncio
from shield import pdq
from shield.ledger import Ledger
from shield.models import BASE
from shield.pipeline import run_scout

async def main():
    led = Ledger()
    bank = pdq.HashBank.load(BASE / "demo/leak_bank.json")
    events = [ev async for ev in run_scout([], bank, BASE / "registry/seeds.yaml", "Acme Corp", ["IN_AADHAAR"], "acme.in", led)]
    rep = next(e for e in events if e["kind"] == "done")["report"]["scout"]
    assert led.verify() is None, "ledger broken"
    assert rep["matches"], "expected PDQ matches on the mock web"
    print(f"scout: {len(rep['matches'])} matches, {rep['counters']}")

asyncio.run(main())
PY
echo "==> all checks passed"
