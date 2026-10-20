"""CLI: python -m sentinel.cli audit --rules rules [--format json|text]"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checks import Ctx
from .engine import load_rules, run_audit
from .platform_detect import detect
from .scoring import summarize


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit", help="read-only audit")
    a.add_argument("--rules", type=Path, default=Path("rules"))
    a.add_argument("--save", action="store_true", help="store scan in SENTINEL_DATA_DIR/sentinel.db (for scheduled runs)")
    a.add_argument("--format", choices=["json", "text"], default="text")
    args = ap.parse_args(argv)

    info = detect()
    rules, errs = load_rules(args.rules)
    results = run_audit(rules, Ctx(os_family=info["os_family"] or "", distro=info["distro"]))
    summary = summarize(results)
    if args.save:
        import os
        from .storage import Store
        sid = Store(Path(os.environ.get("SENTINEL_DATA_DIR", "./data")) / "sentinel.db").save(info, summary, [r.model_dump(mode="json") for r in results], "local")
        print(f"saved scan #{sid}", file=sys.stderr)
    if args.format == "json":
        print(json.dumps({"system": info, "summary": summary, "results": [r.model_dump(mode="json") for r in results],
                          "rule_load_errors": [e.model_dump() for e in errs]}, indent=2))
    else:
        print(f"Host: {info['hostname']}  OS: {info['os_family']} {info['distro'] or ''} {info['version'] or ''}")
        for r in results:
            print(f"[{r.outcome.value:<14}] {r.severity:<8} {r.rule_id}  {r.title}" + (f"  ({r.message})" if r.message else ""))
        for e in errs:
            print(f"[LOAD_ERROR   ] {e.path}: {e.error}", file=sys.stderr)
        print(f"\nScore: {summary['score_percent']}%  Coverage: {summary['coverage_percent']}%  Counts: {summary['counts']}")
        print(summary["note"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
