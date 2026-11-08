package chsink

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/atontalapur/signalman/internal/backend/ch"
	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/pipe"
)

// The events lane stores events.norm in the ClickHouse events table
// (deploy/clickhouse/003_events.sql), the table internal/backend/ch
// retro-hunts over. Each record is stored as the row ch.Encode computes, so
// the SQL compares the values v1 would compute at match time. Delivery and
// backpressure are the alert lane's; a redelivered event collapses on
// (partition, seq).

func eventsLane() laneSpec[ch.Row] {
	return laneSpec[ch.Row]{topic: pipe.TopicEventsNorm, dead: pipe.TopicEventsDead, decode: DecodeEvent}
}

// NewEvents builds the events lane. m and log may be nil.
func NewEvents(cfg Config, b broker.Broker, ins RowInserter[ch.Row], m *obs.Metrics, log *slog.Logger) (*Lane[ch.Row], error) {
	return newLane(cfg, eventsLane(), b, ins, m, log)
}

// DecodeEvent reads an events.norm record into the row the events table
// stores. A record that is not a NormEvent, or whose times the table cannot
// store exactly, is refused so the lane dead-letters it rather than failing
// its batch forever. The bounds are the alerts table's: both tables use
// DateTime64(3) and the same ingest_time TTL.
func DecodeEvent(r broker.Record) (ch.Row, error) {
	var n pipe.NormEvent
	if err := json.Unmarshal(r.Value, &n); err != nil {
		return ch.Row{}, fmt.Errorf("events.norm record is not a NormEvent: %w", err)
	}
	if err := checkTime("event_time", n.EventTime, minEventTime, maxEventTime); err != nil {
		return ch.Row{}, err
	}
	if err := checkTime("ingest_time", n.IngestAt, minIngestTime, endIngestTime.Add(-time.Nanosecond)); err != nil {
		return ch.Row{}, err
	}
	return ch.Encode(n.Event()), nil
}

// EventsTable inserts into the events table over clickhouse-go.
type EventsTable struct {
	conn  driver.Conn
	query string
}

var _ RowInserter[ch.Row] = (*EventsTable)(nil)

// OpenEvents connects with a clickhouse-go DSN and pings. table is normally
// "events"; it is checked as ch checks every table name.
func OpenEvents(ctx context.Context, dsn, table string) (*EventsTable, error) {
	if err := ch.CheckTable(table); err != nil {
		return nil, err
	}
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("clickhouse dsn: %w", err)
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}
	// Positional: Row.Values is in CreateTableSQL's column order, and
	// TestEventsDDLIsTheBackendSchema holds the deployed DDL to it.
	return &EventsTable{conn: conn, query: "INSERT INTO " + table}, nil
}

// Insert sends rows as one INSERT, like ClickHouse.Insert.
func (t *EventsTable) Insert(ctx context.Context, rows []ch.Row) error {
	batch, err := t.conn.PrepareBatch(ctx, t.query)
	if err != nil {
		return classify(err)
	}
	defer func() { _ = batch.Close() }()
	for _, r := range rows {
		if err := batch.Append(r.Values()...); err != nil {
			return fmt.Errorf("%w: append partition %d seq %d: %w", ErrPermanent, r.Partition, r.Seq, err)
		}
	}
	return classify(batch.Send())
}

// Close closes the connection.
func (t *EventsTable) Close() error { return t.conn.Close() }
