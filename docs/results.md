# Results

Measured numbers, one place, each with where it came from and how to
reproduce it. A number goes here only after it has been measured. Targets
from the spec are listed separately and stay there until a run replaces them.

## Differential fuzzer (Plan A gate)

Three runs, all on an Apple M1 Pro, all with zero verdict mismatches. The
2026-09-21 runs are recorded in `docs/corpus-acceptance.md` with pySigma
1.5.1 and pySigma-backend-sqlite 1.2.4.

```bash
make fuzz-differential FUZZTIME=10m FUZZMINCOMPARED=100000
```

| | 2026-09-21, 20 min, 2 workers | 2026-09-21, 30 min, 4 workers | 2026-09-30, 10 min, 4 workers |
|---|---|---|---|
| Executions | 1,989,112 | 5,670,565 | 1,819,797 |
| Verdict comparisons | 755,860 | 2,193,509 | 696,202 |
| Rejected by both engines | 100,150 | 296,839 | 97,968 |
| Suppressed (documented divergence) | 241,997 | 628,122 | 225,532 |
| Skipped before either engine | 885,197 | 2,559,675 | 801,025 |
| Oracle timeouts | 0 | 0 | 0 |
| Verdict mismatches | 0 | 0 | 0 |

Total: 9,479,474 executions and 3,645,571 verdict comparisons with no
mismatch. The 30 minute run was killed by the host at 29m29s for memory
(each worker holds a Python interpreter with pySigma loaded); its counters
are what the workers had flushed by then. The 2026-09-30 run is on commit
`365ed2d`, after the oracle timeout fix; the earlier runs had no timeouts,
so the response desync that fix closes could not have affected them.

Skipped cases never reached either engine: empty values, invalid UTF-8,
and regex patterns `reSafe` declines. The gate counts comparisons, not executions: the first version of the
fuzzer ran 684,594 executions with zero comparisons and still passed CI.
`--min-compared` exists because of that run.

Every suppression has a section in `test/fuzz/KNOWN_DIVERGENCES.md`; there
are 25.

### Defects found in the oracle

Every divergence the fuzzer surfaced was on pySigma's side. Two were bugs,
not dialect differences:

- `pySigma-backend-sqlite` renders a negated multi-variant selection as
  `NOT a LIKE x OR a LIKE y` with no parentheses, so the query asks
  `(NOT a) OR b`.
- pySigma indexes the `base64offset` trim table by character count instead
  of byte count, so it is wrong on any non-ASCII plaintext.

## SigmaHQ corpus acceptance

Run of 2026-09-21, corpus commit `2e8fd89`. Full table and per-code
commentary in `docs/corpus-acceptance.md`.

| Figure | Value |
|---|---|
| Live rules (`rules`, `rules-emerging-threats`, `rules-threat-hunting`, `rules-compliance`) | 3,760 |
| Accepted in the `rules` tree | 1,236 of 3,144 (39.3%) |
| Accepted across live trees | 1,478 |
| Live rules the engine cannot express | 3 |
| Rules loaded or rejected with a code | 100% (asserted by a test) |

Nearly every rejection is `no-taxonomy`: `config/taxonomy/` maps three
logsources, and mapping more is configuration, not engine work.

## v1 evaluator baseline

Apple M1 Pro, `go test -bench . -benchtime 3s ./internal/engine/v1/`, one
Sysmon process creation event. Details in `docs/evaluation.md`.

| Benchmark | Rules | ns/event | verdicts/s | allocs/event |
|---|---|---|---|---|
| Fixtures | 3 | 1,108 | 2,708,682 | 7 |
| Accepted corpus | 1,236 | 3,553,219 | 347,854 | 18,593 |

About 282 events per second single-threaded against the full corpus, and
about 2.9 microseconds and 15 allocations per rule per event. v1 is the
reference oracle and is never optimized, so this is the baseline v2 is
measured against, not a performance claim.

## Codebase

As of commit `365ed2d`: about 7,400 lines of Go, of which about 4,200 are
tests.

## Targets not yet measured

From the spec. These are goals, not results.

- 50,000 events/s against a 1,500 rule corpus on one 8-core node, p99
  end-to-end latency under 250ms. Measured in Plan F.
- v2 throughput relative to v1 with identical verdict digests. Measured in
  Plan G.

## Summary line

Built a Sigma detection engine in Go that loads, or rejects with a coded
reason, every rule in the 3,760-rule SigmaHQ corpus, and verified it
against pySigma with a differential fuzzer: 3.6M verdict comparisons, zero
mismatches, and two bugs found in pySigma's SQLite backend.
