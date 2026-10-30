from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import scan
from .fix import apply_plan, plan_fix
from .report import to_markdown, to_sarif


def main(argv=None):
    parser = argparse.ArgumentParser(prog="shield.codescan")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan")
    p.add_argument("root", nargs="?", default=".")
    p.add_argument("--files", nargs="*")
    p.add_argument("--engines")
    p.add_argument("--history", action="store_true")
    p.add_argument("--format", choices=["json", "sarif", "md"], default="json")
    p.add_argument("--out")

    f = sub.add_parser("fix")
    f.add_argument("root")
    f.add_argument("--id", required=True)
    f.add_argument("--kind", required=True)
    f.add_argument("--dry-run", action="store_true")

    b = sub.add_parser("bank")
    b.add_argument("action", choices=["add", "list", "rm"])
    b.add_argument("path", nargs="?")
    b.add_argument("--label", default="sensitive")

    args = parser.parse_args(argv)

    if args.cmd == "scan":
        engines = args.engines.split(",") if args.engines else None
        result = scan(Path(args.root), [Path(x) for x in args.files] if args.files else None, engines, args.history)
        if args.format == "json":
            text = json.dumps(result, indent=2)
        elif args.format == "sarif":
            text = json.dumps(to_sarif(result), indent=2)
        else:
            text = to_markdown(result)
        if args.out:
            Path(args.out).write_text(text)
        else:
            print(text)
        return 0 if not any(f["severity"] in {"critical", "high"} for f in result["findings"]) else 1

    if args.cmd == "fix":
        root = Path(args.root)
        result = scan(root)
        finding = next((x for x in result["findings"] if x["id"] == args.id), None)
        if not finding:
            print("finding not found", file=sys.stderr)
            return 2
        plan = plan_fix(root, finding, args.kind)
        if args.dry_run:
            print(json.dumps({"edits": [vars(e) for e in plan.edits], "notes": plan.notes}, indent=2))
        else:
            apply_plan(plan)
            print("applied")
        return 0

    if args.cmd == "bank":
        from .media import bank_add, bank_list, bank_rm

        if args.action == "add":
            bank_add(Path(args.path), args.label)
        elif args.action == "list":
            print(json.dumps(bank_list(), indent=2))
        else:
            bank_rm(args.path)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

