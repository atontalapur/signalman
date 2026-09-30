#!/usr/bin/env python3
"""Sum the per-worker counters a differential fuzz run leaves behind.

Fuzzing runs the target in worker processes, so the only number the
coordinator reports is executions. That count includes every input the
fuzz target skipped before either engine: empty values, invalid UTF-8, and
regex patterns reSafe declines. The gate cares about comparisons, not
executions, so each worker writes its counters to
SIGNALMAN_FUZZ_STATS/<pid>-<start>.json and this sums them.

A run that compares nothing is the failure this script exists to catch: the
first version of the fuzzer reached 684,594 executions with zero comparisons
because every generated rule was rejected by both engines, and nothing in a
green CI run said so. Pass --min-compared to make that a failure instead of a
number somebody has to notice.

A floor on comparisons is not enough on its own. A suppression that
matches too much moves real mismatches into the suppressed bucket, and a
run stays green as long as enough other cases still agree. So the share of
suppressed cases and of oracle timeouts can be capped too.

Usage: scripts/fuzz_stats.py <dir> [--min-compared N]
       [--max-suppressed-ratio R] [--max-timeout-ratio R]
"""

import argparse
import json
import pathlib
import sys

KEYS = ["compared", "rejected_by_both", "suppressed", "oracle_timeout", "skipped"]


def parse(argv):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("dir", type=pathlib.Path)
    p.add_argument("--min-compared", type=int, default=0)
    p.add_argument("--max-suppressed-ratio", type=float, default=None)
    p.add_argument("--max-timeout-ratio", type=float, default=None)
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse(argv)
    files = sorted(args.dir.glob("*.json"))
    if not files:
        print(f"no worker stats in {args.dir}", file=sys.stderr)
        return 1

    total = dict.fromkeys(KEYS, 0)
    for f in files:
        # Workers write to a temporary name and rename, so a file that does
        # not parse was not left by a killed worker. Something else is wrong,
        # and summing around it would hide how much.
        try:
            counts = json.loads(f.read_text())
        except json.JSONDecodeError as exc:
            print(f"unreadable worker stats {f.name}: {exc}", file=sys.stderr)
            return 1
        for k in KEYS:
            total[k] += counts.get(k, 0)

    # Suppressed cases reached both engines too: every suppression check in
    # the fuzz target runs after both EvalOnce and the oracle have answered.
    evaluated = total["compared"] + total["rejected_by_both"] + total["suppressed"]
    print(f"workers: {len(files)}")
    for k in KEYS:
        print(f"{k}: {total[k]}")
    print(f"reached both engines: {evaluated}")

    failed = False
    if total["compared"] < args.min_compared:
        print(
            f"FAIL: {total['compared']} verdict comparisons, below the "
            f"minimum of {args.min_compared}. The fuzzer ran without checking "
            f"much: look at what is being skipped before trusting this run.",
            file=sys.stderr,
        )
        failed = True
    failed |= over(
        "suppressed", total["suppressed"], evaluated, args.max_suppressed_ratio
    )
    failed |= over(
        "oracle timeout",
        total["oracle_timeout"],
        evaluated + total["oracle_timeout"],
        args.max_timeout_ratio,
    )
    return 1 if failed else 0


def over(name, part, whole, limit) -> bool:
    """Report whether part/whole exceeds limit. No limit, no check."""
    if limit is None:
        return False
    if whole == 0:
        print(f"FAIL: no cases reached both engines, so the {name} share is undefined.", file=sys.stderr)
        return True
    ratio = part / whole
    print(f"{name} share: {ratio:.3f}")
    if ratio > limit:
        print(
            f"FAIL: {name} share {ratio:.3f} is over the limit of {limit}. "
            f"A suppression or refusal is matching more than it used to: "
            f"find which before trusting this run.",
            file=sys.stderr,
        )
        return True
    return False


if __name__ == "__main__":
    sys.exit(main())
