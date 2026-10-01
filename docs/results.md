# Results

Measured numbers, one place, each with where it came from and how to
reproduce it. A number goes here only after it has been measured. Targets
from the spec are listed separately and stay there until a run replaces them.

## Differential fuzzer (Plan A gate)

### Gate run

Run of 2026-09-30 on commit `fa37b24`, after the suppression fixes below.
Apple M1 Pro, Go 1.27.1, Python 3.14.3, pySigma 1.5.1,
pySigma-backend-sqlite 1.2.4, `-parallel 4`.

```bash
make fuzz-differential FUZZTIME=20m FUZZMINCOMPARED=100000 \
  FUZZMAXSUPPRESSED=0.35 FUZZMAXTIMEOUT=0.01
```

| Counter | Value |
|---|---|
| Wall time | 20m28s |
| Executions | 1,798,175 |
| Verdict comparisons | 673,225 |
| Rejected by both engines | 92,867 |
| Suppressed (documented divergence) | 217,880 |
| Reached both engines | 983,972 |
| Suppressed share | 0.221 |
| Oracle timeouts | 0 |
| Skipped before either engine | 826,376 |
| Verdict mismatches | 0 |

Throughput was about half the earlier runs because a dependency audit ran
on the same machine for part of it; the counts are what matter, not the
rate.

Skipped cases never reached either engine: empty values, invalid UTF-8,
and regex patterns `reSafe` declines. The gate counts comparisons, not
executions: the first version of the fuzzer ran 684,594 executions with zero
comparisons and still passed CI. `--min-compared` exists because of that
run, and the suppressed-share cap exists because of the next section.

Every suppression has a section in `test/fuzz/KNOWN_DIVERGENCES.md`. The
oracle has 14 refusal codes and Signalman's side has 4 rejection kinds; each
is matched on a code or an error type, never on message text.

### Suppressions that matched too much

The pre-merge review of this fuzzer found that three oracle checks and the
Go suppression list matched on text a generated rule value could contain:

- the degenerate-query check matched `=''` anywhere in the SQL, including
  inside a quoted value such as `a='`, and suppressed any verdict mismatch
  on that case;
- the `NOT ... OR` defect check matched the words inside values;
- `known()` matched phrases anywhere in error messages, which quote values.

A mismatch on such a case was counted as suppressed instead of failing.
The fixes key every suppression on a code and blank SQL literals before any
structural check. The suppressed share barely moved (0.221 before, 0.221
after), so the holes were real but rarely hit.

### Earlier runs

Recorded in `docs/corpus-acceptance.md`, all before the suppression fixes.
Their verdict comparisons are real agreements; a mismatch hidden by the
holes above would have been counted as suppressed, not compared.

| | 2026-09-21, 20 min, 2 workers | 2026-09-21, 30 min, 4 workers | 2026-09-30, 10 min, 4 workers |
|---|---|---|---|
| Executions | 1,989,112 | 5,670,565 | 1,819,797 |
| Verdict comparisons | 755,860 | 2,193,509 | 696,202 |
| Rejected by both engines | 100,150 | 296,839 | 97,968 |
| Suppressed | 241,997 | 628,122 | 225,532 |
| Skipped before either engine | 885,197 | 2,559,675 | 801,025 |
| Oracle timeouts | 0 | 0 | 0 |
| Verdict mismatches | 0 | 0 | 0 |

The 30 minute run was killed by the host at 29m29s for memory (each worker
holds a Python interpreter with pySigma loaded); its counters are what the
workers had flushed by then.

Across all four runs: 11,277,649 executions and 4,318,796 verdict
comparisons that agreed.

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
against pySigma with a differential fuzzer: 4.3M agreeing verdict
comparisons, zero mismatches, and two bugs found in pySigma.
