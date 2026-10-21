# Equivalence and cutover

How v2 replaces v1 as the serving engine, what has to be true before each
step, and the record of every disagreement found on the way. The spec is
phases 08 and 09 of `docs/spec/signalman-v1.html`.

No gate has been passed. The dates column below is empty on purpose and is
filled in only when a gate's criteria are met and checked.

## The four arguments

Each argument is stronger than the one before it. Each runs in CI once
built.

1. **Differential fuzzing against pySigma.** Random valid rules and events
   are evaluated by Signalman and by pySigma, and the two must agree. This
   is the only argument that tests the frontend against the Sigma
   specification instead of against v1. `test/fuzz`; run counts are in
   `docs/results.md`.
2. **Property tests.** Determinism (shuffled rule set, same digest), rule
   independence (rules evaluated together equal rules evaluated alone),
   prefilter soundness (prefilter rejects implies v1 is false), and
   idempotence (re-ingesting a batch changes no alert row after merge).
   The first three are in `internal/engine/v1` and `internal/engine/v2`.
   Idempotence needs the ClickHouse alert table, which is Plan D and not
   built.
3. **Corpus replay.** The full event corpus through both engines offline,
   compared by per-partition verdict digest. Exhaustive over a fixed input.
   `internal/engine/v2` harness tests; numbers in `docs/results.md`.
4. **Shadow mode.** v2 evaluates live traffic beside v1 and writes
   `verdicts.v2`; `cmd/differ` joins the two streams on
   `(partition, seq, rule_id)` and classifies every disagreement. This is the
   only argument made on real traffic.

## Shadow lane

`signalmand -shadow` hands every normalized event to v2 as well as v1, and
writes v2's verdicts to `verdicts.v2`. In shadow mode v2 emits no alerts and
nothing consumes its verdicts except the differ.

The spec draws v2 as a separate consumer of `events.norm`. Here v2 evaluates
the same normalized event in the same batch, right after v1, and its
verdicts are written in the same produce as v1's. v2 sees exactly what is
written to `events.norm`; the difference is where it reads it from. The
reasons:

- The slot stores v1 and v2 as one value, so a reload swaps both between
  batches and the two engines never evaluate one event under different
  RuleSetV. Version skew should be empty at steady state, which is the
  spec's own test for an atomic reload.
- The rollout in phase 09 needs one decision per event about which engine
  serves each rule. Two lanes reading at different offsets would each make
  that decision at a different moment, and an event could alert twice or
  not at all during a percentage change.
- A v1 record names the shadow it was evaluated beside, so the differ knows
  a v2 record is owed and can call its absence a missing verdict.

The cost is that v2's evaluation time is added to the match stage. v2 is
roughly 125 times faster than v1 on the benchmark event
(`docs/results.md`), so the added time is small next to v1's, but it is not
zero, and a v2 that became slow would slow the production lane.

A v2 panic, or a v2 verdict list that is not one verdict per rule in rule
set order stamped with the event and the primary's versions, does not stop
the pipeline. v1's outputs for the event are written as usual, no v2 record
is written, `signalman_shadow_failures_total{engine="v2"}` goes up, and the
differ reports every rule of that event as a missing v2 verdict.

## The differ

`cmd/differ` reads `verdicts.v1` and `verdicts.v2` partition by partition.
Within a partition each topic is in Seq order apart from redelivered
repeats, which the differ passes over, so the join is a merge of two sorted
streams:

- same seq on both sides: compare rule by rule;
- one side's head is behind the other's: the side that moved past it will
  never write it, so it is a missing verdict;
- one side has nothing to read: wait. Lag, never loss.

Each side's channel holds `-queue` records, so one side can run at most that
far (plus one poll) ahead before its reader stops. Output depends only on
the two streams, not on when records arrive. Divergences are produced before
the offsets covering them are committed under `-group`, so a restart repeats
work and never skips it.

### Divergence classes

| Class | `class` value | Budget | Handling |
|---|---|---|---|
| v2 false negative | `v2_false_negative` | zero | Missed detection. Halts the cutover. |
| v2 false positive | `v2_false_positive` | zero | Noise for the SOC. Halts the cutover. |
| Missing verdict, either engine | `missing_verdict` | zero | Violates invariant 1. Halts the cutover. |
| Version skew during reload | `version_skew` | transient | Written with `excluded: true` and left out of the count. Decided by RuleSetV alone: a TaxonomyV difference under one RuleSetV is counted in its normal class. Not empty at steady state means the reload is not atomic. |
| Ordering | `ordering` | n/a | Never emitted. The join is on Seq, so arrival order cannot cause a divergence. |

`signalman_divergences_counted_total` is the sum of the three zero-budget
classes. `signalman_divergences_total{class}` has all five.

### Divergence record

One JSON record per `(partition, seq, rule_id)` on the `divergences` topic,
pinned to the event's partition, and the same fields as one JSON log line on
the differ's stderr (`"msg":"divergence"`, or `"divergence excluded"` for
skew):

```json
{"partition": 3, "seq": 81723, "rule_id": "1f1a...", "class": "v2_false_negative",
 "excluded": false,
 "v1": {"matched": true,  "ruleset_v": "9c1d...", "taxonomy_v": "41aa..."},
 "v2": {"matched": false, "ruleset_v": "9c1d...", "taxonomy_v": "41aa..."}}
```

`missing` names the engine with no verdict when there is one. `seq` is the
event's offset in its `events.raw` partition, so the raw record is one
fetch away.

## Gate ladder

| Gate | Criteria | Date passed |
|---|---|---|
| G0 Offline equivalence | Full corpus replay digests match on every partition. Differential fuzzer clean for 1e8 executions. All property tests green. | |
| G1 Shadow at full traffic | v2 shadows 100% of rules for 7 days with 0 divergences in the three zero-budget classes. v2 p99 within target under production load. | |
| G2 1% of rules served by v2 | Hold 48 h. v1 still shadowing. Alert volume per rule unchanged within noise. Rollback is a config flag, measured to take effect in under 30 s. | |
| G3 10%, then 50% | 48 h at each step, same conditions. Any divergence at any step returns to the previous step, not to zero. | |
| G4 100% served by v2 | v1 keeps shadowing and keeps consuming. No configuration change other than the flag. Rollback still exercised. | |
| G5 Rollback game day | Deliberately roll back to v1 at full traffic, during business hours, and roll forward again. Measure both. | |
| G6 Retirement | 14 days at 100% with zero divergence, plus a successful game day. v1 is removed from the serving path and the shadow lane is torn down. | |

## Retirement criteria

Written before G4, as the spec requires, so that "safe enough" is decided
before anyone is looking at a green dashboard. v1 is retired from serving
only when every item holds:

1. G0 through G5 each have a date in the table above, and each date is
   backed by the run or dashboard that showed the criteria met.
2. 14 consecutive days at 100% served by v2, with v1 shadowing every rule
   for the whole period.
3. Over those 14 days, `signalman_divergences_counted_total` does not
   increase. One v2 false negative, v2 false positive, or missing verdict
   restarts the 14 days and returns the rollout to the previous step.
4. Over those 14 days, every `version_skew` record falls inside a reload,
   and the count is zero outside one. Skew at steady state means the reload
   is not atomic, and that is fixed before retirement.
5. Over those 14 days, `signalman_shadow_failures_total` and
   `signalman_audit_violations_total` do not increase.
6. v2 p99 match latency is within the spec target (under 400 µs) under
   production load for the whole period.
7. Alert volume per rule while v2 serves matches the volume while v1 served,
   within the noise measured during G2.
8. The G5 game day rolled back and rolled forward at full traffic, and both
   took effect in under 30 s, measured.
9. Every entry in the divergence log below has a root cause and a fix, and
   none is open.

Retirement removes v1 from the serving path and tears down the shadow lane
and the differ. It does not delete `internal/engine/v1`: v1 stays as the
test oracle, and the differential, property, and replay tests keep running
against it.

## Divergence log

Every disagreement found in shadow mode, from the first day, with the rule,
the event, the root cause, and the fix. The differ's structured log and the
`divergences` topic are the source; each distinct root cause gets one row,
with the event that first showed it.

| # | Found | Class | Rule | Event (partition/seq) | Root cause | Fix | Status |
|---|---|---|---|---|---|---|---|

No entries. Shadow mode has not run against production traffic.
