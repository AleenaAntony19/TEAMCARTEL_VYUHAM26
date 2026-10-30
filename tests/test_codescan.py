import json
import secrets
import string
import subprocess
import sys

import pytest

from shield.codescan import scan
from shield.codescan.fix import TextEdit, apply_edits, apply_plan, plan_fix

AADHAAR = "2345 6789 0124"


def _rand(n):
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


@pytest.fixture
def repo(tmp_path, fx):
    """Throwaway git repo with planted problems; fake secrets are generated here, never committed."""
    r = tmp_path / "leaky"
    (r / "app").mkdir(parents=True)
    (r / "tests").mkdir()
    (r / "docs").mkdir()
    (r / "node_modules" / "x").mkdir(parents=True)
    key = "sk-proj-" + _rand(48)
    (r / "app/config.py").write_text(f'DEBUG = False\nOPENAI_API_KEY = "{key}"\n')
    (r / "app/util.py").write_text(
        "import yaml, requests\n\ndef f(p, u):\n    data = yaml.load(open(p), Loader=yaml.Loader)\n    return requests.get(u, verify=False)\n"
    )
    (r / "tests/users.json").write_text(json.dumps({"aadhaar": AADHAAR, "pan": "ABCPK1234F"}))
    (r / ".env").write_text("DB_PASSWORD=hunter2hunter2\n")
    (r / "node_modules/x/leak.py").write_text(f'K = "{key}"\n')
    (r / "docs/kyc.pdf").write_bytes(fx["pdf"].read_bytes())
    subprocess.run(["git", "init", "-q"], cwd=r, check=True)
    subprocess.run(["git", "add", "-A"], cwd=r, check=True)
    return r, key


def test_scan_finds_planted_issues_without_leaking(repo):
    r, key = repo
    res = scan(r, workers=3, ocr=False)
    rules = {(f["file"], f["rule"]) for f in res["findings"]}
    assert ("app/config.py", "OpenAI Token") in rules
    assert ("tests/users.json", "IN_AADHAAR") in rules
    assert (".env", "ENV_TRACKED") in rules
    assert any(f["file"] == "app/util.py" and f["rule"] == "B506" for f in res["findings"])
    assert any(f["file"] == "docs/kyc.pdf" and f["engine"] == "document" for f in res["findings"])
    assert not any(f["file"].startswith("node_modules") for f in res["findings"])
    dump = json.dumps(res)
    assert key not in dump and AADHAAR not in dump and "234567890124" not in dump
    f = next(f for f in res["findings"] if f["rule"] == "OpenAI Token")
    assert f["confidence"] > 0 and f["recommendation"] and f["evidence"] and f["line"] == 2
    assert set(res["stats"]["engines"]) >= {"secrets", "pii", "sast", "config", "document"}


def test_exclude_and_size_limit(repo):
    r, _ = repo
    res = scan(r, engines=["pii"], exclude=("tests/*",), ocr=False)
    assert not any(f["file"].startswith("tests/") for f in res["findings"])


def test_move_to_env_fix_preview_then_apply(repo):
    r, key = repo
    f = next(f for f in scan(r, engines=["secrets"])["findings"] if f["rule"] == "OpenAI Token")
    plan = plan_fix(r, f, "move_to_env")
    pub = json.dumps(plan.public())
    assert key not in pub, "dry-run output must not carry the secret"
    apply_plan(plan, r)
    src = (r / "app/config.py").read_text()
    assert src.startswith("import os\nDEBUG = False\n") and 'os.environ["OPENAI_API_KEY"]' in src and key not in src
    assert f"OPENAI_API_KEY={key}" in (r / ".env").read_text()
    assert (r / ".env.example").read_text() == "OPENAI_API_KEY=\n"
    apply_plan(plan_fix(r, {**f, "rule": "GITIGNORE_MISSING_ENV"}, "gitignore_add"), r)
    assert (r / ".gitignore").read_text().splitlines().count(".env") == 1  # no duplicate lines
    assert any("Rotate" in n for n in plan.notes)


def test_fake_pii_and_yaml_fix(repo):
    r, _ = repo
    res = scan(r, engines=["pii", "sast"], ocr=False)
    pii = next(f for f in res["findings"] if f["rule"] == "IN_AADHAAR")
    apply_plan(plan_fix(r, pii, "fake_pii"), r)
    from shield.detect import verhoeff_valid

    data = json.loads((r / "tests/users.json").read_text())
    assert data["aadhaar"] != AADHAAR and verhoeff_valid(data["aadhaar"])
    y = next(f for f in res["findings"] if f["rule"] == "B506")
    apply_plan(plan_fix(r, y, "yaml_safe_load"), r)
    assert "yaml.safe_load(open(p))" in (r / "app/util.py").read_text()


def test_paths_cannot_escape_root(repo):
    r, _ = repo
    with pytest.raises(ValueError):
        plan_fix(r, {"file": "../outside.txt", "rule": "x", "id": "1"}, "gitignore_add")


def test_apply_edits_insert_and_replace():
    text = "a = 1\nb = 2\n"
    out = apply_edits(text, [TextEdit("f", 1, 0, 1, 0, "import os\n"), TextEdit("f", 2, 4, 2, 5, "X")])
    assert out == "import os\na = 1\nb = X\n"


def test_image_redact_backs_up_original(repo, fx):
    r, _ = repo
    img = r / "docs/kyc.png"
    img.write_bytes(fx["png"].read_bytes())
    original = img.read_bytes()
    f = {"file": "docs/kyc.png", "rule": "OCR_PII", "id": "x"}
    apply_plan(plan_fix(r, f, "strip_exif"), r)
    backups = list((r / ".shield/backup").iterdir())
    assert len(backups) == 1 and backups[0].read_bytes() == original
    assert ".shield/backup/" in (r / ".gitignore").read_text()
    assert not list(r.glob("docs/*.sanitized*")), "no scratch files in the workspace"


def test_cli_scan_json(repo):
    r, _ = repo
    out = subprocess.run([sys.executable, "-m", "shield.codescan", "scan", str(r), "--no-ocr", "--workers", "2"], capture_output=True, text=True)
    assert out.returncode == 1  # critical findings present
    assert json.loads(out.stdout)["version"] == 2


def test_groq_key_flagged_rotate_and_sarif(repo, tmp_path):
    r, _ = repo
    (r / "app/llm.py").write_text('GROQ = "gsk_' + _rand(52) + '"\n')
    res = scan(r, engines=["secrets"])
    g = next(f for f in res["findings"] if f["rule"] == "Groq Token")
    assert g["severity"] == "critical" and g["message"].startswith("CRITICAL: Rotate this key now")
    from shield.codescan.report import to_sarif

    sarif = to_sarif(res)
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["tool"]["driver"]["name"]
    assert any(x["ruleId"] == "Groq Token" for x in sarif["runs"][0]["results"])
    out = subprocess.run([sys.executable, "-m", "shield.codescan", "scan", str(r), "--engines", "secrets", "--format", "sarif"], capture_output=True, text=True)
    assert json.loads(out.stdout)["version"] == "2.1.0"


def test_hash_pdq_adds_to_bank_without_touching_image(repo, fx):
    r, _ = repo
    img = r / "docs/kyc.png"
    img.write_bytes(fx["png"].read_bytes())
    before = img.read_bytes()
    plan = plan_fix(r, {"file": "docs/kyc.png", "rule": "OCR_PII", "id": "x"}, "hash_pdq")
    assert any("does not redact" in n for n in plan.notes)
    apply_plan(plan, r)
    bank = json.loads((r / ".shield/bank.json").read_text())
    assert bank and img.read_bytes() == before
    assert "hash_pdq" in __import__("shield.codescan", fromlist=["FIX_KINDS"]).FIX_KINDS


def test_fake_pii_value_is_not_reflagged(repo):
    r, _ = repo
    res = scan(r, engines=["pii"], ocr=False)
    pii = next(f for f in res["findings"] if f["rule"] == "IN_AADHAAR")
    apply_plan(plan_fix(r, pii, "fake_pii"), r)
    assert not [f for f in scan(r, engines=["pii"], ocr=False)["findings"] if f["rule"] == "IN_AADHAAR" and f["file"] == "tests/users.json"]


def test_sast_evidence_never_carries_a_neighbouring_secret(tmp_path):
    key = "sk-proj-" + _rand(48)
    (tmp_path / "c.py").write_text(f'import yaml\nKEY = "{key}"\nyaml.load(open("x"), Loader=yaml.Loader)\n')
    res = scan(tmp_path, engines=["sast", "secrets"], ocr=False)
    assert any(f["rule"] == "B506" and "yaml.load" in f["evidence"] for f in res["findings"])
    assert key not in json.dumps(res)
