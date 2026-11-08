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

### Typed-value run

Run of 2026-10-01 on commit `d2a20e4`, after the fuzzer started sending
integer and null event values. Same machine and versions, nightly's caps
(`FUZZMAXSUPPRESSED=0.40`).

| Counter | Value |
|---|---|
| Wall time | 20m2s |
| Executions | 2,898,084 |
| Verdict comparisons | 1,043,565 |
| Rejected by both engines | 142,712 |
| Suppressed (documented divergence) | 359,916 |
| Reached both engines | 1,546,193 |
| Suppressed share | 0.233 |
| Oracle timeouts | 2 |
| Skipped before either engine | 1,352,765 |
| Verdict mismatches | 0 |

The first single run past a million verdict comparisons.

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

Across all five runs: 14,175,733 executions and 5,362,361 verdict
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

## v2 compiled engine

Run of 2026-10-21 on branch `feat/SIG-38-v2-engine`. Apple M1 Pro, 8
cores, 16 GB, Go 1.27.1. This is a laptop, not the spec's 8-core reference
machine, and every number is in-process: no pipeline, no Kafka, no sink.
v1 was re-measured in the same session so the two columns share a machine.

### Equivalence with v1

Every verdict is compared field by field, then each partition's digest.
Events come from `genEvents` in `internal/engine/v2/harness_test.go`: for
each rule, an event built to satisfy its condition, sometimes perturbed or
mixed with another rule's fields, plus a few null and list edge cases.
Aimed events are what make true verdicts common enough for a disagreement
to show; they are not real traffic.

| Rule set | Rules | Events | Verdicts | Matched | Digests equal |
|---|---|---|---|---|---|
| `internal/sigma/testdata` | 2 | 83 | 166 | 42 | 4 of 4 partitions |
| `internal/engine/v1/testdata` | 3 | 123 | 369 | 78 | 4 of 4 |
| shipped `rules/` | 20 | 803 | 16,060 | 405 | 4 of 4 |
| SigmaHQ `rules` tree | 1,236 | 1,239 | 1,531,404 | 1,163 | 4 of 4 |
| SigmaHQ `rules`, `SIGNALMAN_EQUIV_PER_RULE=20` | 1,236 | 24,723 | 30,557,628 | 22,952 | 4 of 4 |
| All four live trees merged | 1,478 | 1,481 | 2,188,918 | 1,461 | 4 of 4 |

```bash
SIGNALMAN_CORPUS=/path/to/sigmahq SIGNALMAN_EQUIV_PER_RULE=20 \
  go test -run TestEquivalenceOnCorpus -v ./internal/engine/v2/
```

`FuzzPrefilterSound` compares v2 with v1 on generated rules (every
modifier chain the loader accepts, negated and disjunctive conditions,
string, int, null and list event values) and checks prefilter soundness
on each case: 761,304 executions in 120 s, no failure.

### Prefilter and gating on the corpus

Over the 1,236-rule set: 1,226 rules are keyed on a literal from their
condition, 10 only on their logsource literal, and `Always` is empty;
7,927 distinct literals. On the 1,239-event stream the prefilter rejected
1,513,077 of 1,531,404 (rule, event) pairs, and presence gating settled
801,541 pairs on a stream of the same size. Neither rejected a pair v1
matched.

### Speed

`go test -bench . -benchtime 3s -benchmem`, v1 in `./internal/engine/v1/`,
v2 in `./internal/engine/v2/`. "Single event" is the Sysmon process
creation event both benchmarks use; "stream" cycles the 1,239-event
generated stream.

| Benchmark | Rules | v1 ns/event | v1 allocs/event | v2 ns/event | v2 allocs/event |
|---|---|---|---|---|---|
| Fixtures, single event | 3 | 1,017 | 7 | 936 | 0 |
| Corpus, single event | 1,236 | 3,469,928 | 18,593 | 27,845 | 0 |
| Corpus, stream | 1,236 | 938,733 | 4,192 | 17,633 | 0 |

The corpus stream benchmark reports 1 B/op for v2: averaged over 222,340
events, that is the scratch being rebuilt after a GC empties the
`sync.Pool`, not a per-event allocation. `TestEvaluateIntoDoesNotAllocate`
asserts zero with `testing.AllocsPerRun` on the fixtures and the corpus.

| v2 measure | Value | Spec target |
|---|---|---|
| Throughput, one goroutine, stream | 56,710 events/s | |
| Throughput, 8 goroutines sharing one evaluator | 413,337 events/s | 50k ev/s on 8 cores |
| Latency, one goroutine, 4,947 events | p50 16.0 µs, p90 24.4 µs, p99 39.3 µs, max 94 µs | p99 < 400 µs |
| v1 latency, same events | p50 767 µs, p90 2.14 ms, p99 4.34 ms, max 15.5 ms | |
| Compile, 1,478 rules (largest set) | 57.5 ms/op benchmark, 76.6 ms one-shot | < 2 s |

The 1,478-rule program has 8,562 leaves interned to 3,925 predicates over
29 fields, and 9,464 literals.

```bash
SIGNALMAN_CORPUS=/path/to/sigmahq go test -run '^$' -bench . -benchtime 3s -benchmem ./internal/engine/v2/
SIGNALMAN_CORPUS=/path/to/sigmahq SIGNALMAN_LATENCY=1 go test -run TestCorpusLatency -v ./internal/engine/v2/
```

The v1 benchmark looks for the corpus at `corpora/sigmahq` in the module
root only.

## Pipeline baseline (Plan F, S-60)

Run of 2026-10-21 on branch `feat/SIG-36-load-harness`. Apple M1 Pro, 8
cores, 16 GB, Go 1.27.1. In-process, in-memory broker: `pipe.Pipeline`
over `broker.Memory` behind the `internal/loadtest` tap, which accepts the
output topics instead of storing them and checks invariant 1 on every
batch. No Redpanda, no ClickHouse, no network, and the generator, the
pipeline, and the checker share the same eight cores. It is a floor on
per-node cost and a ceiling on throughput, not a deployment number.

Pipeline configuration is `signalmand`'s defaults: 8 partitions, max poll
500, 8 normalize and 8 match workers, queue 1024, 4 in-flight batches.
Engine v1. The corpus is generated from the rule set by
`loadtest.FromRules` (20 events per rule, seed 1, aimed at the rules the
way the v2 equivalence harness aims them) and cycled.

Capacity is a backlog drained from cold: the records are produced first,
then the pipeline starts, and the clock stops at the last commit.
Latency is from the `events.raw` produce to the moment the event's outputs
are accepted as durable, with the pipeline offered a fixed fraction of
capacity for 30 s, first 5 s left out.

| Rule set | Rules | Capacity (events/s) | Backlog | Stage that fills | Offered | p50 | p90 | p99 | max |
|---|---|---|---|---|---|---|---|---|---|
| SigmaHQ `rules` tree | 1,236 | 2,465 | 40,000 in 16.2 s | match (normalize and batches behind it) | 0.5x, 1,232/s | 43 ms | 97 ms | 284 ms | 346 ms |
| | | | | | 0.8x, 1,972/s | 624 ms | 1.48 s | 1.69 s | 2.04 s |
| `rules/` | 20 | 121,287 | 1,000,000 in 8.2 s | sink and match together | 0.5x, 60,644/s | 1.1 ms | 6.7 ms | 87 ms | 184 ms |
| | | | | | 0.8x, 97,030/s | 25 ms | 542 ms | 640 ms | 706 ms |

Every run accounted for every event: one verdict record per event with
one verdict per rule, zero drops, zero straddled batches.

What the numbers say:

- The SigmaHQ baseline is 2,465 events/s. v1 costs about 0.94 ms per
  event on this rule set (the v1 stream benchmark above), so eight match
  workers alone could evaluate about 8,500 events/s; the pipeline gets 29%
  of that. The gap has not been profiled. The likely costs are v1's 4,192
  allocations per event under eight workers (GC), the normalizer, and the
  single sink goroutine marshalling a 1,236-verdict record per event. The
  spec's 50,000 events/s is 20 times this baseline; v1 is the oracle and is
  not expected to reach it.
- p99 under 250 ms holds at neither load on the SigmaHQ set. At 0.8x the
  pipeline is close enough to saturation that the bounded queues fill and
  latency is their drain time: up to `(inflight + 2) x max-poll` = 3,000
  admitted records at about 2,500/s is 1.2 s, plus the stage channels.
- With 20 rules the match stage is no longer the limit; the single sink
  goroutine, which builds and writes every output record, fills first.

```bash
SIGNALMAN_LOAD=1 SIGNALMAN_CORPUS=/path/to/sigmahq SIGNALMAN_LOAD_OUT=out \
  go test -run TestLoadBaseline -v -timeout 1h ./internal/loadtest/
# without SIGNALMAN_CORPUS (or corpora/sigmahq) it uses rules/
```

`cmd/loadgen -measure-baseline N` runs the same capacity measurement before
replaying into Kafka, and `-baseline R -multiple X` replays at a stated
multiple without measuring.

## Gate runs on the compose stack (Plans C, D, E)

Run on 2026-11-08 on a laptop against `deploy/docker-compose.yml`
(Redpanda 24.2.7, ClickHouse 24.8, Prometheus 3.5), with the real binaries:
`signalmand -rules rules`, `signalman-sink`, `signalman-sink -lane events`,
and `loadgen -rules rules -baseline 1000`. 21 rules.

**Plan C, one-hour soak.** `loadgen` offered 1,000 events/s for 62 minutes,
00:32 to 01:34 UTC: 3,720,000 records, 0 retries, at most 4.5 s behind
schedule. signalmand ingested 3,721,008 (the rest are canary events),
closed 2,992 audit windows, and `signalman_audit_violations_total` stayed 0
on every partition; Prometheus agrees (`increase` over 65 minutes is 0).
Consumer lag on `events.raw` ended at 0. Three `SIGHUP` reloads landed
mid-run. No ERROR or WARN line in any of the three logs. Gate passed.

**Plan D, live.** After the soak drained, `signalman hunt` over the whole
event-time range up to the end of the soak returned, for each of the 21
rules, exactly the `(partition, seq)` set the pipeline had stored in the
`alerts` table: 1,905,293 rows each way, none on one side only. Rows
written to `signalman.alerts` by the integration tests (negative
partitions) are excluded.

**Plan E, consumer kill.** Under 1,000 events/s, `kill -9` of signalmand:
`SignalmanCanaryAbsent` went pending at +21 s and fired at +51 s. With
signalmand alive and Redpanda paused (`docker compose pause redpanda`), so
the canary age climbs instead of vanishing: `SignalmanCanaryStalled` went
pending at +66 s and fired at +95 s. Both inside two minutes. Gate passed.

**The kill, for Plan F.** After the `kill -9` and a restart on the same
group, the audit closed 163 more windows with 0 violations, the events
table held 4,021,128 rows with no duplicate key, and the hunt still equaled
the stored alerts row for row (2,058,990). After Redpanda was unpaused,
the canary ages fell back under 10 s and no process had exited.

**G0, attempted.** `cutover check -gate G0` with `-rules
corpora/sigmahq/rules` (1,236 rules) and 200,000 events exported from the
soak's `events.norm` as the corpus: the v1 and v2 digests match on all 8
partitions (247.2 million verdicts), and the property and equivalence tests
pass. The gate fails on `fuzz-compared` alone: the latest differential run
made 232,324 comparisons against the 1e8 floor. At about 1,900 a second on
this laptop, the floor is roughly 15 hours of fuzzing, a nightly-scale run
rather than a session. G0 is not dated in `docs/cutover.md`.

## Codebase

As of commit `365ed2d`: about 7,400 lines of Go, of which about 4,200 are
tests.

## Targets not yet measured

From the spec. These are goals, not results.

- 50,000 events/s against a 1,500 rule corpus on one 8-core node, p99
  end-to-end latency under 250ms. The in-process v1 baseline above is
  2,465 events/s on 1,236 rules; the target belongs to v2 through the
  pipeline against Redpanda, which has not been run.
- v2 throughput on the reference machine and end to end through the
  pipeline. The in-process numbers above are from a laptop.

## Summary line

Built a Sigma detection engine in Go that loads, or rejects with a coded
reason, every rule in the 3,760-rule SigmaHQ corpus, and verified it
against pySigma with a differential fuzzer: 5.4M agreeing verdict
comparisons, zero mismatches, and two bugs found in pySigma.
