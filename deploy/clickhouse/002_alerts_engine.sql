-- Adds the engine column to an alerts table created by 001_alerts.sql
-- before the column existed. On a fresh volume 001 already has it and this
-- is a no-op. On an existing volume the init scripts do not run again, so
-- apply it by hand:
--
--   docker compose exec clickhouse clickhouse-client -u signalman --password signalman \
--     --queries-file /docker-entrypoint-initdb.d/002_alerts_engine.sql
--
-- Rows written before it read engine as the empty string.
ALTER TABLE signalman.alerts ADD COLUMN IF NOT EXISTS engine LowCardinality(String) AFTER raw;
