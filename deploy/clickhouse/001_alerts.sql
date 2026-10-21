-- The alert table from the spec (phase 04). The clickhouse service in
-- deploy/docker-compose.yml runs this on its first start, when its data
-- volume is empty; `docker compose down -v` to apply a change.
--
-- ReplacingMergeTree collapses rows with equal ORDER BY keys when parts
-- merge. The pipeline is at-least-once, and a redelivered alert is an exact
-- copy with the same (partition, seq, rule_id), so a redelivered batch
-- collapses into the rows already there. Until a merge runs the copies are
-- visible; read with FINAL to see the collapsed table. Collapsing happens
-- within a PARTITION BY partition only; a copy has the same ingest_time
-- (the events.raw record timestamp, which a replay reproduces), so it lands
-- in the same one.
--
-- PARTITION BY and TTL read ingest_time, not event_time as the spec has it.
-- event_time comes from the source: an old one would be TTL-deleted on
-- insert, after the offset is committed, and a batch with skewed times
-- would span more than the 100 partitions one insert may touch.
-- docs/pipeline.md records the deviation.
CREATE DATABASE IF NOT EXISTS signalman;

CREATE TABLE IF NOT EXISTS signalman.alerts (
  partition   Int32,
  seq         UInt64,
  rule_id     UUID,
  rule_title  LowCardinality(String),
  severity    Enum8('informational'=1,'low'=2,'medium'=3,'high'=4,'critical'=5),
  event_time  DateTime64(3),
  ingest_time DateTime64(3),
  host_id     LowCardinality(String),
  source      LowCardinality(String),
  fields      Map(String, String),
  raw         String CODEC(ZSTD(3))
) ENGINE = ReplacingMergeTree
ORDER BY (partition, seq, rule_id)
PARTITION BY toYYYYMMDD(ingest_time)
TTL toDateTime(ingest_time) + INTERVAL 90 DAY;
