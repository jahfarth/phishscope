"""Command line interface.

    phishscope analyze mail.eml [more.eml ...] [--json] [--no-ml]
    phishscope scan samples/                 # directory of .eml files
    phishscope train [--out PATH]            # retrain + save model JSON
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import parse_eml
from .model import DEFAULT_MODEL_PATH, PhishModel
from .report import analyze, render_text


def _load_model(no_ml: bool) -> PhishModel:
    return None if no_ml else PhishModel.load_or_train()


def _cmd_analyze(paths, as_json: bool, no_ml: bool) -> int:
    model = _load_model(no_ml)
    reports = [analyze(parse_eml(p), model) for p in paths]
    if as_json:
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2))
    else:
        print("\n\n".join(render_text(r) for r in reports))
    return 1 if any(r["verdict"] == "phishing" for r in reports) else 0


def _cmd_scan(directory, as_json: bool, no_ml: bool) -> int:
    paths = sorted(Path(directory).glob("*.eml"))
    if not paths:
        print(f"no .eml files in {directory}", file=sys.stderr)
        return 2
    return _cmd_analyze(paths, as_json, no_ml)


def _cmd_train(out, n: int, seed: int) -> int:
    model = PhishModel.train(n=n, seed=seed)
    path = model.save(out or DEFAULT_MODEL_PATH)
    m = model.metrics
    print(f"trained on {m['train_samples']} synthetic samples, "
          f"tested on {m['test_samples']}: "
          f"accuracy={m['accuracy']:.2%} precision={m['precision']:.2%} "
          f"recall={m['recall']:.2%} f1={m['f1']:.2%}")
    print(f"model written to {path}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="phishscope",
        description="Static phishing triage for .eml files: auth checks, IOC "
                    "extraction, weighted red-flag rules and an explainable ML score.")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument("--json", action="store_true", help="machine-readable output")
        p.add_argument("--no-ml", action="store_true", help="rule engine only")

    p = sub.add_parser("analyze", help="analyse one or more .eml files")
    p.add_argument("files", nargs="+")
    add_common(p)

    p = sub.add_parser("scan", help="analyse every .eml in a directory")
    p.add_argument("directory")
    add_common(p)

    p = sub.add_parser("train", help="retrain the bundled model on synthetic data")
    p.add_argument("--out", default=None)
    p.add_argument("--samples", type=int, default=4000)
    p.add_argument("--seed", type=int, default=42)

    args = parser.parse_args(argv)
    if args.command == "analyze":
        return _cmd_analyze(args.files, args.json, args.no_ml)
    if args.command == "scan":
        return _cmd_scan(args.directory, args.json, args.no_ml)
    if args.command == "train":
        return _cmd_train(args.out, args.samples, args.seed)
    return 2
