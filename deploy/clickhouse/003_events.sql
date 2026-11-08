-- The events table: every normalized event, stored for retro-hunting.
-- signalman-sink -lane events writes it from events.norm, and
-- signalman hunt reads it. The columns are internal/backend/ch's
-- CreateTableSQL, which TestEventsDDLIsTheBackendSchema holds this file to.
-- Each column holds a value v1 computes at match time, computed once in Go
-- at write time, so the SQL only compares. See docs/backend-ch.md.
--
-- Runs on first start (empty volume). On an existing volume apply it by hand:
--
--   docker compose exec clickhouse clickhouse-client -u signalman --password signalman \
--     --queries-file /docker-entrypoint-initdb.d/003_events.sql
CREATE TABLE IF NOT EXISTS signalman.events (
  partition   Int32,
  seq         UInt64,
  event_time  DateTime64(3, 'UTC'),
  ingest_time DateTime64(3, 'UTC'),
  source      LowCardinality(String),
  f_present   Array(String),
  f_text      Map(String, Array(String)),
  f_folded    Map(String, Array(String)),
  f_eqfold    Map(String, Array(String)),
  f_ints      Map(String, Array(Int64)),
  f_ips       Map(String, Array(String)),
  raw         String CODEC(ZSTD(3))
) ENGINE = ReplacingMergeTree
ORDER BY (partition, seq)
PARTITION BY toYYYYMMDD(ingest_time)
TTL toDateTime(ingest_time) + INTERVAL 90 DAY;
