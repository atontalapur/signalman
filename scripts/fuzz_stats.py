#!/usr/bin/env python3
"""Sum the per-worker counters a differential fuzz run leaves behind.

Fuzzing runs the target in worker processes, so the only number the
coordinator reports is executions. That count includes every input the
mutator produced that was not valid YAML and never reached either engine.
The gate cares about comparisons, not executions, so each worker writes its
counters to SIGNALMAN_FUZZ_STATS/<pid>.json and this sums them.

Usage: scripts/fuzz_stats.py <dir>
"""

import json
import pathlib
import sys

KEYS = ["compared", "rejected_by_both", "suppressed", "oracle_timeout", "skipped"]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    d = pathlib.Path(sys.argv[1])
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

    evaluated = total["compared"] + total["rejected_by_both"]
    print(f"workers: {len(files)}")
    for k in KEYS:
        print(f"{k}: {total[k]}")
    print(f"reached both engines: {evaluated}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
