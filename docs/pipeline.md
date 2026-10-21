# The pipeline

How `signalmand` moves an event from `events.raw` to verdicts, alerts, or
the drop ledger, and how it proves none went missing. Code lives in
`internal/pipe`, `internal/broker`, and `internal/obs`; the ClickHouse alert
sink is `internal/pipe/chsink`.

```
events.raw -> ingest -> normalize -> match (Slot: v1 [+ v2 shadow]) -> sink -> events.norm, verdicts.v1, [verdicts.v2,] alerts, drops
                  bounded      bounded          bounded                  |
                                                                       commit offsets after the batch is durable

verdicts.v1 + verdicts.v2 -> cmd/differ -> divergences
```

## Topics and records

All record bodies are JSON. Types are in `internal/pipe/wire.go` and
`internal/pipe/drop.go`.

| Topic | Key | Body |
|---|---|---|
| `events.raw` | host_id | the untouched source record; header `source` names the source |
| `events.norm` | host_id | `NormEvent`: seq, partition, host_id, source, event_time, ingest_at, typed fields, raw |
| `verdicts.v1` | partition, pinned to the event's partition | `EventVerdicts`: one record per event with every rule's verdict and both versions; `shadow` names the shadow engine when there is one |
| `verdicts.v2` | partition, pinned | `EventVerdicts` from the shadow engine, written only with `-shadow` |
| `divergences` | partition, pinned | `differ.Divergence`: one per `(partition, seq, rule_id)` the engines disagree on (`docs/cutover.md`) |
| `alerts` | rule_id | `Alert`: one per match by the engine serving the rule, shaped like the spec's ClickHouse alert table plus `engine` |
| `drops` | host_id | `DropEntry`: identity, reason, detail, and the raw bytes (base64) |
| `alerts.dead` | the alert's key | an `alerts` record the ClickHouse table cannot hold, written by `signalman-sink`; not in the spec |

`verdicts.v1` holds one record per event rather than one per verdict, so the
topic grows with events, not events times rules, and an event's verdicts are
written or redelivered together. `EventVerdicts.Expand` turns it back into
data contract verdicts for the digest and the differ.

## Seq

Seq is the record's offset in its `events.raw` partition. The offset is
already per-partition, monotonic, and durable, so Seq survives a restart with
nothing extra stored. A redelivered record gets the Seq it had the first time,
which is what lets the alert table deduplicate on `(partition, seq, rule_id)`
and lets the digest stay stable across a crash. A persisted counter would give
a redelivered record a new Seq and turn every redelivery into a duplicate
alert.

## Normalization

The raw record is a JSON object. Nested objects flatten to dotted names. A
field whose name matches a taxonomy name ignoring case (a `match` key or the
event side of a field mapping, from `Taxonomy.FieldNames`) is renamed to the
taxonomy's spelling, because a bound rule reads fields by exact name. An
integer number becomes an int value; any other number keeps its literal text
as a string, since `Value` has no float kind. The event time comes from the
`event_time` field (RFC 3339 or epoch milliseconds), never the wall clock.

### Drop reasons

The only way an admitted event leaves without verdicts. Every reason is a
property of the record's bytes; overload never drops.

| Reason | Meaning |
|---|---|
| `parse` | not JSON, not an object, or trailing data |
| `invalid-utf8` | the record is not valid UTF-8 (checked before decoding, so nothing is silently replaced) |
| `value-too-long` | a string over 64 KiB |
| `nested-value` | a list holding a list or object, or objects nested deeper than 8 |
| `duplicate-field` | a key appears twice, literally or after taxonomy renaming |
| `missing-source` | no `source` header |
| `event-time` | event time absent or unparseable |
| `panic` | the normalizer panicked on this record; the partition moves on |
| `record-too-large` | key, value, and headers together over 128 KiB; the entry keeps a 16 KiB prefix of the raw bytes (`truncated: true`, `raw_bytes` is the full length) |
| `output-too-large` | the record fit, but its `events.norm` or an alert record would be over the output limit (long flattened names can do this); decided in the sink before anything for the event is written |

### Size limits

A broker refuses a record over `max.message.bytes` on every retry, so one
oversized output would hold its partition forever, and again after a
restart. The limits make every output fit:

| Limit | Value | Where |
|---|---|---|
| `max.message.bytes` on every topic | 1 MiB | `deploy/docker-compose.yml`, `signalmand -create-topics` |
| producer batch limit | 1 MiB, the same | `broker.MaxMessageBytes`, `kgo.ProducerBatchMaxBytes` |
| largest output record (key, value, headers) | 1 MiB minus 16 KiB for framing | `pipe.MaxOutputRecordBytes` |
| largest admitted record | 128 KiB | `pipe.DefaultMaxRecordBytes` |

JSON escapes one byte to at most six, and a drop entry carries the host id
twice (field and key), the source, a detail cut to 1 KiB, and the raw bytes
in base64, so the entry for a record under 128 KiB stays under seven times
that, inside the output limit. A verdict record grows with the rule count
(about 60 bytes a rule), so a rule set of more than roughly 16,000 rules
stops the pipeline with an error naming the rule set.

Topics that already exist keep their configuration: neither the compose
setup nor `-create-topics` alters them. On a Redpanda volume created before
this limit, set it by hand with
`rpk topic alter-config <topic> --set max.message.bytes=1048576`.

## Delivery: at-least-once

A batch is one poll. The sink waits for every item in the batch, writes all of
its outputs, waits for the broker to ack them (all in-sync replicas), and only
then commits the batch's offsets. Batches commit in poll order. A crash before
the commit redelivers the batch with the same Seqs; the duplicates are exact
copies and the alert table's ReplacingMergeTree collapses them.

The alternative, committing before the outputs are durable, makes a crash
into silent loss. A delayed detection can be reported on afterwards; a lost
one cannot, so at-least-once with an idempotent sink was chosen.

A failed produce is retried with backoff until it succeeds or the process
stops, unless the error is permanent (`broker.ErrPermanent`: message too
large, unknown topic or partition, a pinned partition the topic lacks, an
authorization failure). Retrying those cannot succeed and would hold every
partition behind the batch, so the pipeline stops with the batch
uncommitted and an error naming its offsets. At startup it also refuses a
missing output topic, or a `verdicts.v1` (and, with `-shadow`, a
`verdicts.v2`) with fewer partitions than `events.raw`, since verdicts are
pinned to the event's partition. The output size limit covers the
`verdicts.v2` record the same way. A failed commit is logged and not retried: the next batch's commit
supersedes it, and the worst case is redelivery.

A batch still in flight when a rebalance takes its partition away does not
commit for that partition: the Redpanda consumer drops commits for
partitions this member no longer owns, for a reassigned partition until a
record is polled from it again, and any commit that would move a
partition's offset backwards. The new owner redelivers from its own
position.

Within a partition, outputs are written in Seq order, so alerts for a
partition are emitted in Seq order. Ordering across partitions, and so across
hosts, is not guaranteed.

## Backpressure: lag over loss

Ingest, normalize, match, and the sink are joined by bounded channels
(`-queue`), with fixed worker pools (`-normalize-workers`, `-match-workers`)
that are stated by the operator, never derived from the machine. At most
`-inflight` polled batches wait for the sink. When the sink cannot write, its
input fills, the workers block, the batch queue fills, and ingest stops
polling. Consumer lag grows; nothing is dropped. The number of records
admitted but not yet committed is bounded by `(inflight + 2) x max-poll`.

## Alert sink: alerts to ClickHouse

`signalman-sink` (`internal/pipe/chsink`) consumes `alerts` as its own
consumer group and inserts into the `alerts` table from the spec, defined in
`deploy/clickhouse/001_alerts.sql`. The table has one column the spec does
not: `engine LowCardinality(String)`, the engine that served the alert, so
alert volume per rule can be compared across engines during the rollout.
`002_alerts_engine.sql` adds it to a table created before it existed; on an
existing volume, run it by hand. The sink runs as a separate process from
`signalmand` so a ClickHouse outage stops alert storage and nothing else:
detection keeps writing to Redpanda, and the backlog waits in the topic.

- **Batches.** Rows are buffered until `-batch-rows` (5000) or until
  `-flush-interval` (1s) after the first one, then sent as one INSERT.
  ClickHouse writes a part per insert, so few large inserts beat many small
  ones. The buffer never holds more than `batch-rows + max-poll` rows.
- **Commit after insert.** Offsets are committed only after the INSERT
  returns. A crash between the two redelivers the batch. A redelivered alert
  is an exact copy (same partition, seq, rule_id, and ingest_time, so the
  same PARTITION BY day), and the ReplacingMergeTree collapses the copies
  when parts merge. Until a merge runs the copies are visible: read with
  `FINAL`, or `OPTIMIZE TABLE alerts FINAL`, to see the collapsed table. A
  failed commit is logged, not retried, as in the pipeline. Every insert
  sets `fsync_after_insert=1`, so ClickHouse acknowledges only after the part
  is on disk; without it a host crash after the ack could lose rows whose
  offsets are committed. The cost is one fsync per part, small at the
  sink's batch sizes.
- **Partitioning and TTL on ingest_time.** The spec partitions and expires
  the table on `event_time`. Here both read `ingest_time` instead, the
  `events.raw` record timestamp, which a replay reproduces. `event_time`
  comes from the source: an alert for an event older than 90 days would be
  TTL-deleted on insert, after its offset was committed, which is loss; and
  a batch with skewed times could touch more than the 100 partitions one
  INSERT may. Queries still filter on `event_time`. A record whose
  `event_time` or `ingest_time` is outside the DateTime64(3) range
  (1900-01-01 to 2299-12-31) is refused by the sink, since the normalizer
  has no drop reason for it at this layer.
- **Outage.** A failed insert is retried with the same rows, backing off
  from 100ms to 5s, and nothing is polled meanwhile. The outage surfaces as
  `signalman_consumer_lag_records{topic="alerts"}` on the sink's `/metrics`
  (`:9465`), growing until ClickHouse returns, bounded by the topic's
  retention. Nothing is dropped. signalmand itself is not slowed: the
  acceptance line "the sink backpressures the pipeline" holds for the
  alerts consumer, whose lag is the backpressure, not for detection.
- **Records the table cannot hold.** The table's `rule_id` is a UUID,
  `severity` is an Enum8 of the five Sigma levels, the times are
  DateTime64(3), and `engine` must be `v1` or `v2`. The rule loader now rejects a non-UUID id and a missing or
  unknown level (codes `invalid-id` and `level`), so these come from a
  hand-written record, an older rule set, or a bug, but a record that would
  fail every insert of its batch would still stop the sink for every
  partition. `Decode` checks each record, and one it refuses goes to the
  `alerts.dead` topic: same key and value, with headers naming its topic,
  partition, offset, and the reason (capped at 1 KiB; a value too large to
  fit beside the headers is cut, and `signalman-dead-truncated` records its
  length). Its offset is committed with the batch around it, only after the
  dead-letter write returned, so a crash redelivers it and it may be
  dead-lettered twice. Each one increments
  `signalman_sink_dead_letters_total`; any increase is an alert stored
  nowhere queryable and needs an operator. `alerts.dead` keeps 30 days and
  has the same 1 MiB record limit as the other topics. The sink refuses to
  start without it. A transient dead-letter write failure is retried like
  an insert; a permanent one stops the sink with the record's position.
- **Permanent insert errors.** ClickHouse exceptions an identical insert
  hits again (parse and type errors, a missing table or column, refused
  auth, too many partitions in one block) and client-side append errors
  wrap `chsink.ErrPermanent`. The sink then stops at once, naming the
  offsets it holds per partition, and commits nothing. Everything else,
  including "too many parts" while merges catch up, is retried as an
  outage.

Idempotence is checked twice, once against a model and once for real.
`TestModelReingestChangesNoRow` runs over `replacingTable`, a model of the
merge written for the test (last insert wins per sorting key, within a day
partition), and checks over 500 random histories that inserting a batch
again, whole or as a prefix, changes no row of `FINAL` or of the merged
table. That shows the sink's redelivery pattern is safe if ClickHouse merges
the way the model does; it proves nothing about ClickHouse.
`TestReingestCollapsesInClickHouse` (build tag `integration`, needs
`SIGNALMAN_CLICKHOUSE_DSN`, fails instead of skipping under `CI=true`) is
the proof: the same check against a real ClickHouse with `SELECT ... FINAL`
and `OPTIMIZE TABLE ... FINAL`. It has not been run yet: there is no Docker
on the development machine.

**Reset Redpanda and ClickHouse together.** `seq` is the `events.raw`
offset, and `(partition, seq, rule_id)` is the table's dedup key. Recreating
`events.raw` (or wiping the Redpanda volume) restarts offsets at 0, so new
alerts reuse keys already in the table, and the ReplacingMergeTree collapses
distinct alerts into one, silently. Wipe both volumes at once
(`docker compose -f deploy/docker-compose.yml down -v`), or drop the
`alerts` table when the topic is recreated.

## Rule set reload

The engine sits in a `Slot`. Ingest reads the slot once per batch, when it
forms the batch, and every item in that batch is evaluated with that engine.
`SIGHUP` reloads the rule directory into the slot; the new rule set applies
from the next batch. No batch straddles two RuleSetV values, by construction
rather than by locking. A taxonomy change needs a restart, because the
normalizer is built from it.

The slot holds anything implementing `pipe.Engine` (`Name`, `RuleSet`,
`EvaluateInto`), which is the seam v2 drops into.

## Shadow lane

With `-shadow` the slot holds v1 and v2 as one value
(`Slot.StoreWithShadow`), both built from the same rule set, and a reload
swaps the pair between batches. Each normalized item is evaluated by v1 and
then v2 in the same match worker, and both verdict records go out in the
batch's produce. v2 writes `verdicts.v2` and no alerts. A v2 panic or a
malformed v2 verdict list leaves v1's outputs alone, writes no v2 record for
that event, and counts in `signalman_shadow_failures_total`. Why the shadow
reads the batch instead of consuming `events.norm`, and how `cmd/differ`
compares the two streams, is in `docs/cutover.md`.

`-rollout <file>` routes alerts per rule: v2 serves a rule when
`fnv(rule_id) mod 100` is below the file's percentage, v1 serves the rest,
and both keep writing verdicts for every rule. The percentage lives in the
slot beside the engines, so a change lands between batches like a reload.
The file is reread every `-rollout-poll` and on `SIGHUP`; see
`docs/cutover.md` for the rollback measurement.

## Invariant 1 audit

`pipe.Auditor` reads `verdicts.v1` and `drops` and checks, for every
`events.raw` offset the group has committed, that the event has a verdict
record with one verdict per rule of its RuleSetV, or a drop entry, and not
both. Because commits follow durable writes, the arithmetic
`ingested = evaluated + dropped` must close exactly for every committed
offset. Windows slide forward with the committed offset, at most
`-audit-window` seqs at a time. A failing window is logged at error level,
names the partition and seqs, and increments
`signalman_audit_violations_total{partition}`; any increase is a P1.

Each partition's audit starts at the later of the group's committed offset
and the log start of `events.raw`, so offsets retention removed before the
group ever committed are not reported missing. A committed offset below the
log start is logged as a warning: those records were removed before the
pipeline read them.

It assumes `events.raw` is a plain topic with dense offsets, and that it
starts in the same `signalmand` process before the pipeline produces. Two
instances on one group would break the second assumption.

### Status of the Plan C gate

The gate is "green for an hour under load". That has not been run: there is
no Docker on the development machine. What has run is
`TestEndToEndUnderGeneratedLoad` in `internal/pipe`, which pushes generated
load (including malformed records and rule set reloads every half second)
through the in-memory broker for 3 seconds with the audit stepping
throughout, and requires every window green. `SIGNALMAN_SOAK_DURATION=1h`
lengthens it, but the in-memory broker keeps every record, so the real hour
belongs on Redpanda.

## Metrics

Names from the spec's core metrics table, in `internal/obs`.
`internal/obs/metrics_test.go` parses that table out of the spec and fails if
the registered set, types, or labels differ from it, apart from an
allowlist of extras, each with its reason. The differ's own metrics are
registered by `cmd/differ`, not here; they are listed in `docs/cutover.md`.

| Metric | Type | Labels | Set by |
|---|---|---|---|
| `signalman_events_ingested_total` | counter | source, partition | ingest, per admitted record |
| `signalman_events_dropped_total` | counter | reason, source | normalizer, per drop |
| `signalman_verdicts_total` | counter | engine, matched | sink, once durable |
| `signalman_rule_matches_total` | counter | rule_id | sink, per durable alert, from whichever engine serves the rule |
| `signalman_rule_eval_seconds` | histogram | rule_id | match workers, sampled (`-rule-eval-every`) |
| `signalman_stage_queue_depth` | gauge | stage (normalize, match, sink, batches) | sampled every second |
| `signalman_consumer_lag_records` | gauge | topic, partition | log end offset minus committed offset |
| `signalman_event_staleness_seconds` | gauge | partition | now minus the newest durable event time, at scrape |
| `signalman_canary_age_seconds` | gauge | partition | seconds since the last canary alert was durable, at scrape |
| `signalman_ruleset_version_info` | gauge | ruleset_v, taxonomy_v | the slot, on every reload |
| `signalman_audit_violations_total` | counter | partition | the audit; not in the spec table |
| `signalman_canary_injected_total` | counter | partition | the canary generator, per record written; not in the spec table |
| `signalman_shadow_failures_total` | counter | engine | sink, per event the shadow failed on; not in the spec table |
| `signalman_alerts_total` | counter | engine, rule_id | sink, per durable alert, by the serving engine; not in the spec table |
| `signalman_rollout_percent` | gauge | | the slot, on every rollout change; not in the spec table |
| `signalman_event_time_future_total` | counter | partition | sink, per durable event whose event time is ahead of the clock; not in the spec table |
| `signalman_sink_dead_letters_total` | counter | none | signalman-sink, per record written to `alerts.dead`; not in the spec table |

`signalman_rule_eval_seconds` is sampled: on events whose Seq is a multiple
of `-rule-eval-every` (default 100, 0 turns it off), a match worker times
each rule's logsource test and condition walk, the same work v1 does per
rule, and throws the result away. The verdicts come from the engine as
always, so sampling costs time and cannot change one. Buckets run from
100ns to about 26ms by factors of four; exemplars are off.

Lag and staleness are separate. Lag is records in `events.raw` not yet
committed. Staleness is `now() - max(event_time)` over events whose batch is
durable, per partition, computed when Prometheus scrapes, so it keeps rising
while nothing arrives. An upstream that stops producing leaves lag at zero
and staleness climbing; only staleness sees it. Canary events are left out
of staleness, or the canary would keep it fresh. An event time ahead of
the clock counts as now and increments `signalman_event_time_future_total`:
taken as is, one event from a host whose clock runs a day fast would hold
staleness at zero for that day. The event and its verdicts keep the time
it carried. The wall clock is read only by the metric, never by anything a
verdict depends on.

## Canary

`pipe.Canary` writes one synthetic event to every `events.raw` partition
every `-canary-interval` (default 30s; 0 turns it off), pinned to the
partition, keyed `signalman-canary`, source `sysmon`. The event matches one
rule, `rules/signalman_canary.yml`, and nothing else in `rules/`. The rule
loads and is evaluated like any other, so the canary takes the same path as
a real detection: normalize, the engine slot, the sink. When a batch holding
a canary alert is durable, the sink resets that partition's
`signalman_canary_age_seconds`. The alert is the one served: under a rollout
that hands the canary rule to v2, a v2 that wrongly says false for it writes
no canary alert, and the age climbs and pages. When no alert arrives, the gauge climbs,
because it is computed at scrape time from the last reset.

The generator starts a partition's age the first time it injects there, so
a consumer that never comes up pages too. signalmand refuses to start, or
to reload, a rule directory without the canary rule while the canary is
on, since that would page for a healthy pipeline.

The canary event carries the generator's clock as its `event_time`. That
is data in the event, like any event time, not a clock the engine reads, so
verdicts stay a pure function of the event and the rule set. The generator
only produces; it buffers nothing, and a failed injection is logged and
left for the next tick.

`deploy/prometheus/alerts/absence.yml` pages on two conditions.
`SignalmanCanaryStalled` fires when a partition's age is over 50s for 30s.
The spec writes it as `> 120` for `2m`, which pages three to four and a
half minutes after a consumer dies and misses the two-minute target; the
file has the budget (50s + one scrape + one evaluation + 30s = 110s worst
case). `SignalmanCanaryAbsent` covers the case the age cannot: when
signalmand itself is gone, the gauge goes with it.
`TestCanaryStallPagesWithinTwoMinutes` runs the pipeline and the generator
on the in-memory broker with a fake clock, kills the consumer, and evaluates
the rule as written in the file against the gauge every scrape interval.

`deploy/prometheus/` holds the scrape config and alert rules, with promtool
unit tests in `alerts_test.yml` (`make check-alerts`). CI runs that target
in the `alerts` job with promtool 3.5.0, the compose Prometheus version,
taken from the official release tarball after a sha256 check against a
value pinned in `ci.yml`. A version bump changes both the compose image and
that pin.
`deploy/grafana/dashboards/signalman.json` is the dashboard, provisioned
into the compose stack's Grafana at `localhost:3000`.

## Silent rules

`SignalmanRuleWentSilent`, in `absence.yml` as the spec writes it, files a
ticket (never a page) for a rule whose `signalman_rule_matches_total` rose in
the last 30 days and not in the last 24 hours. The failure it is for: a
taxonomy edit renames a field, every rule reading that field stops
matching, and nothing errors.

It only works because the slot exports every loaded rule's series at zero.
A taxonomy change needs a restart, and in the new process a silenced rule
never matches, so without the zero its series would end at the restart,
leave the 24h window a day later, and the alert would compare nothing. A
reload that drops a rule deletes its series, so a rule removed on purpose
does not ticket. `TestTaxonomyRenameSilencesTheAffectedRule` runs the
shipped rules for three simulated days, restarts on a taxonomy with
`CommandLine` renamed in the sysmon binding, runs two more, and evaluates
the alert's expression over the hourly scrapes: every rule reading
`CommandLine` that went quiet fires, and no other rule does. Remove the
zero series and it fails. `deploy/prometheus/alerts_silence_test.yml` is the
promtool version.
