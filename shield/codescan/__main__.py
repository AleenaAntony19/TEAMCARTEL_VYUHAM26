from __future__ import annotations

import argparse
import json
import os
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
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--timeout", type=float, default=300, help="overall seconds; unfinished engines report 'timeout'")
    p.add_argument("--no-ocr", action="store_true")
    p.add_argument("--cognitive", action="store_true", help="send OCR and document text to the configured AI provider; known values are blanked first")
    p.add_argument("--max-file-mb", type=float, default=2)
    p.add_argument("--exclude", action="append", default=[], help="glob on repo-relative paths; repeatable")

    f = sub.add_parser("fix")
    f.add_argument("root")
    f.add_argument("--id", required=True)
    f.add_argument("--kind", required=True)
    f.add_argument("--file", help="limit the re-scan to this file (faster)")
    f.add_argument("--dry-run", action="store_true")

    b = sub.add_parser("bank")
    b.add_argument("action", choices=["add", "list", "rm"])
    b.add_argument("path", nargs="?")
    b.add_argument("--label", default="sensitive")

    args = parser.parse_args(argv)

    if args.cmd == "scan":
        engines = args.engines.split(",") if args.engines else None
        result = scan(
            Path(args.root), [Path(x) for x in args.files] if args.files else None, engines, args.history,
            workers=args.workers, timeout=args.timeout, ocr=not args.no_ocr, max_file_mb=args.max_file_mb, exclude=tuple(args.exclude),
            cognitive=args.cognitive,
        )
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
        code = 0 if not any(f["severity"] in {"critical", "high"} for f in result["findings"]) else 1
        if result["stats"].get("timed_out"):
            sys.stdout.flush()
            os._exit(code)  # engine threads still running cannot be joined; exit without waiting
        return code

    if args.cmd == "fix":
        root = Path(args.root).resolve()
        result = scan(root, [Path(args.file)] if args.file else None)
        finding = next((x for x in result["findings"] if x["id"] == args.id), None)
        if not finding:
            print(json.dumps({"error": "finding not found; the file may have changed - re-scan"}))
            return 2
        try:
            plan = plan_fix(root, finding, args.kind)
        except (ValueError, OSError, IndexError) as exc:
            print(json.dumps({"error": f"cannot plan fix: {type(exc).__name__}"}))
            return 2
        if args.dry_run:
            print(json.dumps(plan.public()))
        else:
            apply_plan(plan, root)
            print(json.dumps({"applied": True, **plan.public()}))
        return 0

    if args.cmd == "bank":
        from .media import bank_add, bank_list, bank_rm

        if args.action == "add":
            bank_add(Path(args.path), args.label, Path.cwd())
        elif args.action == "list":
            print(json.dumps(bank_list(Path.cwd()), indent=2))
        else:
            bank_rm(args.path, Path.cwd())
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

