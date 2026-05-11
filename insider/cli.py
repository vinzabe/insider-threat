"""insider CLI."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from .analyst import LLMInsiderAnalyst
from .detector import DetectorConfig, InsiderThreatDetector
from .pipeline import InsiderPipeline
from .synth import SyntheticActivityGenerator


def _cmd_train(args):
    gen = SyntheticActivityGenerator(seed=args.seed)
    corpus = gen.generate_baseline(n_days=args.days, n_per_profile_per_day=1)
    cfg = DetectorConfig(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=args.seed,
        suspicious_threshold=args.threshold,
        per_role=not args.no_per_role,
    )
    det = InsiderThreatDetector(cfg).fit(corpus)
    det.save(args.out)
    print(f"trained on {len(corpus)} user-days -> {args.out}")
    return 0


def _cmd_scan(args):
    det = InsiderThreatDetector.load(args.model)
    analyst = LLMInsiderAnalyst() if args.llm else None
    pipeline = InsiderPipeline(detector=det, analyst=analyst, enable_llm=args.llm)
    if args.input == "-":
        result = pipeline.from_lines(sys.stdin.readlines())
    else:
        result = pipeline.from_file(args.input)
    print(json.dumps(result.to_dict(), indent=2, default=str))
    return 0


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="insider")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_t = sub.add_parser("train", help="train detector on synthetic baseline")
    p_t.add_argument("--out", default="insider.joblib")
    p_t.add_argument("--seed", type=int, default=1337)
    p_t.add_argument("--days", type=int, default=21)
    p_t.add_argument("--n-estimators", type=int, default=200)
    p_t.add_argument("--contamination", type=float, default=0.05)
    p_t.add_argument("--threshold", type=float, default=0.55)
    p_t.add_argument("--no-per-role", action="store_true")
    p_t.set_defaults(func=_cmd_train)

    p_s = sub.add_parser("scan", help="score activity JSONL against a detector")
    p_s.add_argument("--model", required=True)
    p_s.add_argument("--input", required=True)
    p_s.add_argument("--llm", action="store_true")
    p_s.set_defaults(func=_cmd_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
