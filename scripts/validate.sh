#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

source /Users/aaronr/py311/bin/activate
export PYTHONPATH="$ROOT_DIR"
export SHIELD_ALLOW_LOCAL=1

echo "==> Running pytest..."
pytest -q

echo "==> Generating demo fixtures and mock web..."
python demo/make_fixtures.py demo/out > /dev/null
python demo/make_mockweb.py > /dev/null

echo "==> Testing Shield·Code scanner CLI..."
python -m shield.codescan scan shield --format json | python -m json.tool > /dev/null || true
echo "Shield·Code scan JSON generation OK"

echo "==> Starting mock leak server..."
python demo/serve.py &
SERVER_PID=$!
sleep 1

cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Testing leak scout crawler against mock web..."
python - <<'PY'
import asyncio, json
from pathlib import Path
from shield.ledger import Ledger
from shield.pipeline import run_scout
from shield import pdq
from shield.models import BASE

bank = pdq.HashBank.load(BASE / "demo/leak_bank.json")

async def main():
    led = Ledger()
    events = []
    async for ev in run_scout([], bank, BASE / "registry/seeds.yaml", "Acme Corp", ["IN_AADHAAR"], "acme.in", led):
        events.append(ev)
    done_evs = [e for e in events if e.get("kind") == "done"]
    assert done_evs, "No done event found"
    rep = done_evs[0]["report"]["scout"]
    matches = rep["matches"]
    counters = rep["counters"]
    bad_block = led.verify()
    print(f"Scout run complete: {len(matches)} matches, pages: {counters.get('pages')}, images: {counters.get('images')}, blocked: {counters.get('blocked')}")
    print(f"Ledger verification: {'OK' if bad_block is None else f'FAILED at {bad_block}'}")
    assert bad_block is None, "Ledger integrity check failed"
    assert len(matches) > 0, "Expected matches against mock web"

asyncio.run(main())
PY

echo "==> All validation checks passed successfully! 🛡️"
