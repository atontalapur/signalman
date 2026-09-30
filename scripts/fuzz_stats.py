#!/usr/bin/env python3
"""Sum the per-worker counters a differential fuzz run leaves behind.

Fuzzing runs the target in worker processes, so the only number the
coordinator reports is executions. That count includes every input the
fuzz target skipped before either engine: empty values, invalid UTF-8, and
regex patterns reSafe declines.
The gate cares about comparisons, not executions, so each worker writes its
counters to SIGNALMAN_FUZZ_STATS/<pid>.json and this sums them.

A run that compares nothing is the failure this script exists to catch: the
first version of the fuzzer reached 684,594 executions with zero comparisons
because every generated rule was rejected by both engines, and nothing in a
green CI run said so. Pass --min-compared to make that a failure instead of a
number somebody has to notice.

Usage: scripts/fuzz_stats.py <dir> [--min-compared N]
"""

import json
import pathlib
import sys

KEYS = ["compared", "rejected_by_both", "suppressed", "oracle_timeout", "skipped"]


def main() -> int:
    args = sys.argv[1:]
    min_compared = 0
    if "--min-compared" in args:
        i = args.index("--min-compared")
        try:
            min_compared = int(args[i + 1])
        except (IndexError, ValueError):
            print("--min-compared needs an integer", file=sys.stderr)
            return 2
        del args[i : i + 2]
    if len(args) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    d = pathlib.Path(args[0])
    files = sorted(d.glob("*.json"))
    if not files:
        print(f"no worker stats in {d}", file=sys.stderr)
        return 1

    total = dict.fromkeys(KEYS, 0)
    for f in files:
        try:
            counts = json.loads(f.read_text())
        except json.JSONDecodeError:
            # A worker killed mid-write leaves a truncated file. One lost
            # flush is at most statsFlushEvery cases.
            continue
        for k in KEYS:
            total[k] += counts.get(k, 0)

    # Suppressed cases reached both engines too: every suppression check in
    # the fuzz target runs after both EvalOnce and the oracle have answered.
    # Leaving them out understated this by the whole suppressed bucket.
    evaluated = total["compared"] + total["rejected_by_both"] + total["suppressed"]
    print(f"workers: {len(files)}")
    for k in KEYS:
        print(f"{k}: {total[k]}")
    print(f"reached both engines: {evaluated}")

    if total["compared"] < min_compared:
        print(
            f"FAIL: {total['compared']} verdict comparisons, below the "
            f"minimum of {min_compared}. The fuzzer ran without checking "
            f"much: look at what is being skipped before trusting this run.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
