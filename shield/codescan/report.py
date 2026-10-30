from __future__ import annotations

from collections import Counter


def to_sarif(scan: dict) -> dict:
    rules = {}
    results = []
    for f in scan["findings"]:
        rules.setdefault(f["rule"], {"id": f["rule"], "name": f["rule"], "shortDescription": {"text": f["rule"]}})
        results.append(
            {
                "ruleId": f["rule"],
                "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(f["severity"], "warning"),
                "message": {"text": f["message"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"]},
                            "region": {
                                "startLine": max(1, f["line"]),
                                "startColumn": max(1, f["col"]),
                                "endLine": max(1, f["end_line"] or f["line"]),
                                "endColumn": max(1, f["end_col"] or f["col"]),
                            },
                        }
                    }
                ],
                "partialFingerprints": {"shieldId": f["id"]},
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Shield·Code", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }


def to_markdown(scan: dict) -> str:
    counts = Counter((f["engine"], f["severity"]) for f in scan["findings"])
    lines = ["# Shield·Code report", "", "| Engine | Critical | High | Medium | Low |", "|---|---:|---:|---:|---:|"]
    for engine in sorted({e for e, _ in counts}):
        lines.append(
            f"| {engine} | {counts[(engine,'critical')]} | {counts[(engine,'high')]} | "
            f"{counts[(engine,'medium')]} | {counts[(engine,'low')]} |"
        )
    lines += ["", "## Rotate now", ""]
    for f in scan["findings"]:
        if f["severity"] in {"critical", "high"} and f["engine"] == "secrets":
            lines.append(f"- `{f['file']}:{f['line']}` {f['rule']} — {f['masked']} — **rotate this key**")
    lines += ["", "## Top findings", "", "| Severity | Rule | File | Masked |", "|---|---|---|---|"]
    for f in scan["findings"][:20]:
        lines.append(f"| {f['severity']} | {f['rule']} | {f['file']}:{f['line']} | {f['masked']} |")
    return "\n".join(lines)

