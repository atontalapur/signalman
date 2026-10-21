# The pipeline

How `signalmand` moves an event from `events.raw` to verdicts, alerts, or
the drop ledger, and how it proves none went missing. Code lives in
`internal/pipe`, `internal/broker`, and `internal/obs`; the ClickHouse alert
sink is `internal/pipe/chsink`.

```
events.raw -> ingest -> normalize -> match (Slot: v1) -> sink -> events.norm, verdicts.v1, alerts, drops
                  bounded      bounded          bounded      |
                                                           commit offsets after the batch is durable
```

## Topics and records

All record bodies are JSON. Types are in `internal/pipe/wire.go` and
`internal/pipe/drop.go`.

| Topic | Key | Body |
|---|---|---|
| `events.raw` | host_id | the untouched source record; header `source` names the source |
| `events.norm` | host_id | `NormEvent`: seq, partition, host_id, source, event_time, ingest_at, typed fields, raw |
| `verdicts.v1` | partition, pinned to the event's partition | `EventVerdicts`: one record per event with every rule's verdict and both versions |
| `alerts` | rule_id | `Alert`: one per match, shaped like the spec's ClickHouse alert table |
| `drops` | host_id | `DropEntry`: identity, reason, detail, and the raw bytes (base64) |

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
missing output topic, or a `verdicts.v1` with fewer partitions than
`events.raw`, since verdicts are pinned to the event's partition. A failed commit is logged and not retried: the next batch's commit
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
`deploy/clickhouse/001_alerts.sql`. It runs as a separate process from
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
  failed commit is logged, not retried, as in the pipeline.
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
- **Records the table cannot hold.** The rule loader accepts any rule id
  and any level, but the table's `rule_id` is a UUID and `severity` is an
  Enum8 of the five Sigma levels. A record that would fail every insert of
  its batch stops the sink with its topic, partition, and offset, and
  nothing in that batch is committed. Skipping it would be silent loss;
  stopping is lag an operator can see and fix.

Idempotence is tested twice. `TestReingestingABatchChangesNoRow` models the
merge (last insert wins per sorting key, within a day partition) and checks
over 500 random histories that inserting a batch again, whole or as a
prefix, changes no row of `FINAL` or of the merged table.
`TestReingestCollapsesInClickHouse` (build tag `integration`, needs
`SIGNALMAN_CLICKHOUSE_DSN`) does the same against a real ClickHouse with
`SELECT ... FINAL` and `OPTIMIZE TABLE ... FINAL`. It has not been run yet:
there is no Docker on the development machine.

## Rule set reload

The engine sits in a `Slot`. Ingest reads the slot once per batch, when it
forms the batch, and every item in that batch is evaluated with that engine.
`SIGHUP` reloads the rule directory into the slot; the new rule set applies
from the next batch. No batch straddles two RuleSetV values, by construction
rather than by locking. A taxonomy change needs a restart, because the
normalizer is built from it.

The slot holds anything implementing `pipe.Engine` (`Name`, `RuleSet`,
`EvaluateInto`), which is the seam v2 drops into.

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

| Metric | Labels | Set by |
|---|---|---|
| `signalman_events_ingested_total` | source, partition | ingest, per admitted record |
| `signalman_events_dropped_total` | reason, source | normalizer, per drop |
| `signalman_verdicts_total` | engine, matched | sink, once durable |
| `signalman_rule_matches_total` | rule_id | sink, once durable |
| `signalman_stage_queue_depth` | stage (normalize, match, sink, batches) | sampled every second |
| `signalman_consumer_lag_records` | topic, partition | log end offset minus committed offset |
| `signalman_ruleset_version_info` | ruleset_v, taxonomy_v | the slot, on every reload |
| `signalman_audit_violations_total` | partition | the audit; not in the spec table |

Not yet exported: `signalman_rule_eval_seconds`,
`signalman_event_staleness_seconds`, `signalman_canary_age_seconds`. Those are
Plan E.
