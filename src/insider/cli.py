"""CLI: feed an event log, then assess users. Every event is
{user, group, features:{...}}; assessment reports elevated users with the
mandatory explanation. Exit codes: 0 none elevated, 2 elevated (review required),
1 error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .engine import Engine

EXIT_OK, EXIT_ERROR, EXIT_ELEVATED = 0, 1, 2


def _load(path: str) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text())
    if not isinstance(data, list):
        raise ValueError("event log must be a JSON array")
    return data


def cmd_assess(a: argparse.Namespace) -> int:
    events = _load(a.events)
    engine = Engine(warmup=a.warmup)
    # baseline on all but the last event per user; assess the last one
    per_user_last: dict[str, dict[str, Any]] = {}
    for e in events:
        u = e["user"]
        if u in per_user_last:
            prev = per_user_last[u]
            engine.observe(prev["user"], prev.get("group", ""),
                           prev.get("features", {}))
        per_user_last[u] = e

    assessments = []
    for u, e in per_user_last.items():
        assessments.append(engine.assess(u, e.get("features", {})))

    elevated = [a for a in assessments if a.elevated]
    if a.json:
        print(json.dumps([{
            "user": x.user, "status": x.status, "score": x.score,
            "elevated": x.elevated, "review_required": x.review_required,
            "explanation": x.explanation} for x in assessments], indent=2))
    else:
        print("Insider-risk assessment (review-required; NOT an accusation):\n")
        for x in sorted(assessments, key=lambda a: a.score, reverse=True):
            tag = "⚠ REVIEW" if x.elevated else ("· " + x.status)
            print(f"  {tag}  {x.user}  score={x.score}")
            print(f"       {x.explanation}")
    return EXIT_ELEVATED if elevated else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="insider", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assess", help="baseline an event log and assess users")
    a.add_argument("events", help="JSON array of {user, group, features}")
    a.add_argument("--warmup", type=int, default=14)
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_assess)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rc: int = args.func(args)
        return rc
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
