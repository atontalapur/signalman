# Equivalence and cutover

How v2 replaces v1 as the serving engine, what has to be true before each
step, and the record of every disagreement found on the way. The spec is
phases 08 and 09 of `docs/spec/signalman-v1.html`.

No gate has been passed. The dates column below is empty on purpose and is
filled in only when a gate's criteria are met and checked, by
`cutover check -record` (see "Checking the gates").

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
   Idempotence is in `internal/pipe/chsink`, against a model of
   ReplacingMergeTree in CI and a real ClickHouse under `make integration`.
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

A v1 record with no `shadow` owes no v2 record and is passed over. On v1 a
shadowed record is a repeat only of an earlier shadowed one, so when
signalmand restarts with `-shadow` and redelivers events it first wrote
without it, the shadowed copies are compared. A v2 record for a seq v1 has
already moved past without a shadowed record is not counted: v1 wrote that
event unshadowed (typically v2's record landed and v1's did not before a
restart without `-shadow`), so v1 has its verdict. A shadowed v1 head whose
v2 record never comes would otherwise hold the partition: once a later
unshadowed v1 record shows signalmand moved on without the shadow, the
differ reads v2 up to its end offset at that moment, and if the record is
not there it is a missing verdict. v2 records are written in the same
produce as their v1 record, before any later batch, so nothing below that
offset is still to come.

Each side's channel holds `-queue` records, so one side can run at most that
far (plus one poll) ahead before its reader stops. Output depends only on
the two streams, not on when records arrive. Divergences are produced before
the offsets covering them are committed under `-group`, so a restart repeats
work and never skips it. Each committed offset carries that side's
repeat-dropping state (highest seq handled, and on v1 highest shadowed seq)
as its commit metadata, so a restart that lands inside a redelivered run on
one side drops the same repeats a running differ would. Offsets committed
by an older differ have no metadata and start with empty state.

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
`signalman_differ_events_total` counts events resolved and
`signalman_differ_records_read_total{engine}` records read per side. All
four are served by `cmd/differ` on `-metrics-addr` (default `:9466`).

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

## Rollout and rollback

A rule's alerts are served by v2 when `fnv(rule_id) mod 100 < percent`
(FNV-1a 32 over the rule id bytes; `pipe.RolloutBucket`). The bucket depends
on nothing but the id, so routing is the same after a restart and on every
node, and raising the percentage only adds rules: a rule served by v2 stays
served by v2 as the rollout advances. `TestRolloutBucketIsPinned` fixes the
hash, so a change to it fails a test instead of quietly moving rules.

Both engines evaluate every rule at every percentage. v1 keeps writing
`verdicts.v1` with `shadow: "v2"` on every record, so the differ stays armed
on exactly the rules v2 is serving. Only the alerts change hands.

The rollout is read from the slot once per batch, with the engines, so each
event's alerts come from one routing decision. Each matched rule is served
by exactly one engine for that event, so there is one alert per
`(partition, seq, rule_id)` that the serving engine matched, never one from
each. If v2 fails on an event, v1 serves that event's v2 rules, so a v2
failure costs a v2 verdict (which the differ reports as missing) and never
an alert. Every alert carries `engine`, the engine that served it.

Rollback is a config change. `signalmand -rollout <file>` reads one integer,
0 to 100, from the file at startup, every `-rollout-poll` (default 5 s), and
on `SIGHUP`. A changed value applies from the next batch formed; batches
already in flight finish under the old one. A file that does not parse is
refused and the current rollout stays. Write the file with a rename, not in
place, so the poller never reads half of it.

Measured in `TestRollbackTakesEffectWithin30Seconds`
(`cmd/signalmand`), in memory, with the default poll interval and no
`SIGHUP`: from rewriting the file from 100 to 0 until the first alert served
by v1, 5.2 to 5.4 s over four runs on an Apple M1 Pro, and every later
alert came from v1. Most of that is the poll interval. This is the
in-memory test, not the G2 measurement, which has to be taken against
Redpanda under production load.

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
   `signalman_audit_violations_total` do not increase, and
   `signalman_audit_windows_total` rises at every 5m step: a flat
   violations counter is also what an audit that never ran exports.
6. v2 p99 match latency is within the spec target (under 400 µs) under
   production load for the whole period.
7. Alert volume per rule while v2 serves matches the volume while v1 served,
   within the noise measured during G2.
8. The G5 game day rolled back and rolled forward at full traffic, and both
   took effect in under 30 s, measured.
9. Every entry in the divergence log below has a root cause and a fix, and
   none is open.

Retirement removes v1 from the serving path and tears down the shadow lane
and the differ (see "After G6: v2 serves"). It does not delete
`internal/engine/v1`: v1 stays as the test oracle, and the differential,
property, and replay tests keep running against it.

## After G6: v2 serves

Switching the serving engine is the last step of the ladder, taken only
once G6 is recorded below. Until then nothing changes: `-serve` defaults to
v1.

`signalmand -serve v2` makes v2 the primary engine. Its verdicts go to
`verdicts.v2`, which the invariant 1 audit then checks, and every alert
carries `engine: v2`. `signalman_rollout_percent` reads 100. `-rollout` is
refused, and so is any rollout above zero in the slot, because a rollout
would hand the rules inside it back to v1. A v2 failure on an event is now
the primary's failure and stops the process, as a v1 failure did before:
lag, not a short verdict list.

The shadow lane is torn down by running without `-shadow` and stopping the
differ. `-serve v2 -shadow` keeps v1 evaluating every event as the oracle
and writing `verdicts.v1` with no alerts, for `differ -primary v2`, whose
divergence classes stay relative to v1. A failing v1 costs a v1 record,
which the differ reports as a missing verdict, and never an alert. Both
engines still evaluate in the same batch, so this mode runs at v1's speed;
it is for checking the switch, not for serving full rate.

v1 stays in the repository as the test oracle and is not changed by the
switch. The fixture runner and `signalman test`, `signalman explain`, the
pySigma differential fuzzer, the v1 and v2 property tests, the equivalence
and digest harness, and the G0 corpus replay keep running against it.

Going back to v1 after the switch is a restart with `-serve v1 -rollout`
and a file holding 100, then lowering the file. That is a restart, not the
30 s flag; the flag rollback ends at G6 by design.

## Checking the gates

`cmd/cutover` checks one gate at a time and prints every criterion with its
status and the evidence behind it. It exits 0 only when every criterion
passed or was attested.

```sh
go run ./cmd/cutover check -gate G2 -prom http://localhost:9090 -drill g2-rollback.json
```

Nothing is written unless `-record` is given, and `-record` writes only for
a gate that passed: it puts the date of `-at` (default now) in the table
above and appends the checks and their evidence under "Gate evidence" at
the end of this document. It refuses a gate that already has a date. G3 is
recorded in two steps, `-percent 10` and then `-percent 50`; only the second
dates the row. `-at` after now is refused: a window that has not ended
cannot be checked, and its date cannot go in the table.

Every gate with a window (G1 to G4, G6) first checks the window was
observed. Sums and extremes over a window see only the samples that exist,
so a hold scraped for one day of seven would otherwise pass on that day.
`coverage-signalmand` and `coverage-differ` need at least 95% of the
samples a `-scrape-interval` (15 s) scrape would give, counted with
`min(count_over_time(...))` over `signalman_rollout_percent` and
`signalman_differ_events_total`, which each process exports from start-up.
`coverage-baseline` checks the same for the window alert volume is compared
against. `engines-continuous` counts the 5m steps at which each engine's
verdict rate was above zero and needs every one of them; a minimum over the
steps would not see a step with no data.

Where each criterion comes from:

| Gate | Checked from | Not machine-checkable here |
|---|---|---|
| G0 | `-corpus` replayed through v1 and v2 with `-rules`, digests compared per partition (`internal/verdict`); `-fuzz-stats` summed, at least `-fuzz-min` (1e8) comparisons; `-go-test` runs `go test` over `internal/engine`, `internal/verdict`, `internal/pipe/chsink` | `fuzz-clean`: the counters do not record the fuzz run's exit status |
| G1 | Over 7 days, covered: rollout at 0, both engines' verdict rates above zero at every 5m step and their counts within `-verdict-tolerance`, differ resolving events, `signalman_divergences_counted_total` and `signalman_shadow_failures_total` flat | `v2-p99`: no per-engine match latency metric is exported; it comes from the load harness |
| G2, G3 | Over 48 h: rollout held at 1, 10 or 50 on every instance, the G1 checks, alert volume per rule against the 48 h before within `-noise-sigma` (Poisson, default 3), and a rollback in `-drill` under 30 s | |
| G4 | The G2 checks at 100 apart from alert volume, `signalman_alerts_total{engine="v1"}` flat, and a rollback from 100 in `-drill` | `flag-only`: no configuration change other than the rollout file |
| G5 | `-drill` from `cutover gameday`: 100 to 0 and 0 to 100, each under 30 s; started on a weekday inside `-business-hours` in `-tz`; ingest rate at the rollback at least `-full-traffic` (0.8) of the 7 day mean | |
| G6 | Over 14 days: rollout at 100, the G1 checks, the audit closing windows at every 5m step and its violations flat, zero `version_skew`, alert volume against `-baseline-at` (a window when v1 served everything), the G5 drill, G0 to G5 dated here, no open divergence log entry | `v2-p99`; `skew-in-reloads` when there was any skew |

A criterion nothing here can check is `unchecked` until an operator states
the evidence with `-attest key=evidence`, which is recorded as `attested`
next to the machine checks. A failed check cannot be attested. A query that
fails, or a metric with no series where one must exist (an unscraped
differ), is `unchecked`, never zero. `deploy/prometheus/prometheus.yml`
scrapes the differ on `:9466` for this.

## Game day

G5 is a rollback at full traffic during business hours and a roll-forward,
both measured. `cutover gameday` is the one subcommand that changes
production: it rewrites signalmand's `-rollout` file.

Before: G4 holds, the rollout file reads 100 and so does
`signalman_rollout_percent` on every instance, the SOC knows the window,
and someone is watching the canary and divergence panels.

```sh
go run ./cmd/cutover gameday -prom http://localhost:9090 \
  -rollout-file /etc/signalman/rollout -out docs/gameday/$(date +%F).json
```

1. Preflight: the file and every instance's gauge must read `-from` (100).
   Anything else stops the drill before it writes.
2. Rollback: the file is replaced with 0 by a rename, and the write time is
   kept.
3. After `-observe` (90 s) the change is measured from Prometheus. It took
   effect at the later of two samples: the first with
   `max(signalman_rollout_percent)` at 0, and the last at which
   `signalman_alerts_total{engine="v2"}` rose for a moved rule. A moved rule
   is one whose `RolloutBucket` lies between the two percentages, so a
   partial rollback is timed on the rules that actually changed hands. v1
   must also have served at least one moved rule, and v2 must have been
   quiet for `-quiet` (20 s) before the window ends.
4. If the rollback is not measured the drill stops with the rollout at 0,
   which is v1 serving: investigate before rolling forward by hand.
5. After `-hold` (5 min from the rollback) the file is set back to 100,
   and the roll-forward is measured the same way with the engines swapped.

The result is a JSON file holding both steps; pass it to
`cutover check -gate G5 -drill` (and later to G6). `-rollback-only` runs
the rollback alone, for the measured rollback G2 to G4 need, with `-from`
set to the current step. `cutover measure` times a change an operator made
by hand from its write time, without touching the file.

Each time is the first sample that showed it, so a measured duration is an
upper bound, never shorter than the real one, and its error is at most one
scrape interval (15 s in `deploy/prometheus`). A duration near the 30 s
budget should be re-run with a shorter scrape interval before it is
believed either way.

### Measured durations

| Date | From | To | Took effect | Measured by | Result file |
|---|---|---|---|---|---|

No game day has been run. There is no production traffic to run one
against, and no number goes here until one is.

## Divergence log

Every disagreement found in shadow mode, from the first day, with the rule,
the event, the root cause, and the fix. The differ's structured log and the
`divergences` topic are the source; each distinct root cause gets one row,
with the event that first showed it.

| # | Found | Class | Rule | Event (partition/seq) | Root cause | Fix | Status |
|---|---|---|---|---|---|---|---|

No entries. Shadow mode has not run against production traffic.

## Gate evidence

What `cutover check -record` appended for each gate it recorded, newest
last. Each entry names the command, the window, and every check.

Nothing recorded. No gate has been checked against production traffic.
