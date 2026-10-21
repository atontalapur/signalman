package chsink

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/google/uuid"
)

// Columns is the alerts table's columns in table order, which is the order
// Insert appends values in. schema_test.go holds it equal to the DDL.
//
// The first eleven are the spec's (phase 04). engine is an extension: the
// engine that served the alert, v1 or v2, so alert volume per rule can be
// compared across engines during the rollout.
var Columns = []string{
	"partition", "seq", "rule_id", "rule_title", "severity",
	"event_time", "ingest_time", "host_id", "source", "fields", "raw",
	"engine",
}

// severities are the Enum8 values of the severity column.
var severities = map[string]bool{"informational": true, "low": true, "medium": true, "high": true, "critical": true}

func validSeverity(s string) bool { return severities[s] }

// Decode reads an alerts topic record and checks it fits the table. A
// record that does not would fail every insert of its batch, so it is
// refused here, with a reason, rather than retried forever.
//
// The rule loader does not require a UUID id or a level, so a rule that
// lacks either loads, matches, and produces alerts the table cannot hold.
func Decode(r broker.Record) (pipe.Alert, error) {
	var a pipe.Alert
	if err := json.Unmarshal(r.Value, &a); err != nil {
		return a, fmt.Errorf("alert record is not an Alert: %w", err)
	}
	if _, err := uuid.Parse(a.RuleID); err != nil {
		return a, fmt.Errorf("rule_id %q is not a UUID, which the alerts table requires", a.RuleID)
	}
	if !validSeverity(a.Severity) {
		return a, fmt.Errorf("rule %s severity %q is not one of informational, low, medium, high, critical", a.RuleID, a.Severity)
	}
	return a, nil
}

// ClickHouse inserts into the alerts table over clickhouse-go.
type ClickHouse struct {
	conn  driver.Conn
	query string
}

var _ Inserter = (*ClickHouse)(nil)

// Open connects with a clickhouse-go DSN, such as
// clickhouse://user:pass@localhost:9000/signalman, and pings. table is the
// table to insert into, normally "alerts".
func Open(ctx context.Context, dsn, table string) (*ClickHouse, error) {
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
	return &ClickHouse{conn: conn, query: insertQuery(table)}, nil
}

func insertQuery(table string) string {
	return "INSERT INTO " + table + " (" + strings.Join(Columns, ", ") + ")"
}

// Conn is the underlying connection, for callers that need to run DDL or
// queries alongside the sink.
func (c *ClickHouse) Conn() driver.Conn { return c.conn }

// Insert sends rows as one INSERT. ClickHouse writes one block as one part,
// so the rows of a successful Insert are all stored.
func (c *ClickHouse) Insert(ctx context.Context, rows []pipe.Alert) error {
	batch, err := c.conn.PrepareBatch(ctx, c.query)
	if err != nil {
		return err
	}
	defer func() { _ = batch.Close() }()
	for _, a := range rows {
		if err := batch.Append(rowValues(a)...); err != nil {
			return fmt.Errorf("append partition %d seq %d rule %s: %w", a.Partition, a.Seq, a.RuleID, err)
		}
	}
	return batch.Send()
}

// rowValues is a's values in Columns order.
func rowValues(a pipe.Alert) []any {
	fields := a.Fields
	if fields == nil {
		fields = map[string]string{}
	}
	return []any{a.Partition, a.Seq, a.RuleID, a.RuleTitle, a.Severity,
		a.EventTime, a.IngestTime, a.HostID, a.Source, fields, a.Raw, a.Engine}
}

// Close closes the connection.
func (c *ClickHouse) Close() error { return c.conn.Close() }

// Statements splits a DDL file into statements, dropping -- comment lines
// and the terminating semicolons, for clients that take one statement per
// call.
func Statements(sql string) []string {
	var b strings.Builder
	for line := range strings.SplitSeq(sql, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	var out []string
	for s := range strings.SplitSeq(b.String(), ";") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
