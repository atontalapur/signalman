package chsink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/google/uuid"
)

// Columns is the alerts table's columns in table order, which is the order
// Insert appends values in. schema_test.go holds it equal to the DDL.
var Columns = []string{
	"partition", "seq", "rule_id", "rule_title", "severity",
	"event_time", "ingest_time", "host_id", "source", "fields", "raw",
}

// severities are the Enum8 values of the severity column.
var severities = map[string]bool{"informational": true, "low": true, "medium": true, "high": true, "critical": true}

func validSeverity(s string) bool { return severities[s] }

// DateTime64 holds 1900-01-01 00:00:00 through 2299-12-31 23:59:59.999. A
// time outside it is stored as a different time or refused.
var (
	minDateTime64 = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	maxDateTime64 = time.Date(2299, 12, 31, 23, 59, 59, 999e6, time.UTC)
)

func checkDateTime64(name string, t time.Time) error {
	if t.Before(minDateTime64) || t.After(maxDateTime64) {
		return fmt.Errorf("%s %s is outside the DateTime64(3) range 1900-01-01 to 2299-12-31", name, t.UTC().Format(time.RFC3339Nano))
	}
	return nil
}

// Decode reads an alerts topic record and checks it fits the table. A
// record that does not would fail every insert of its batch, so it is
// refused here, with a reason, rather than retried forever; the sink
// dead-letters it.
//
// The rule loader rejects a non-UUID id and a missing or unknown level
// (codes invalid-id and level), so a loaded rule cannot produce such an
// alert. These checks stay as a backstop for records from elsewhere: an
// older rule set, a hand-written record, or a bug.
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
	if err := checkDateTime64("event_time", a.EventTime); err != nil {
		return a, err
	}
	if err := checkDateTime64("ingest_time", a.IngestTime); err != nil {
		return a, err
	}
	return a, nil
}

// ErrPermanent is wrapped by an Insert error that will fail again on retry:
// a row the server refuses by type or value, a missing table or column, a
// refused login. Retrying it holds every partition behind the batch, so the
// sink stops instead. The same idea as broker.ErrPermanent on the produce
// side.
var ErrPermanent = errors.New("permanent insert error")

// permanentCodes are ClickHouse exception codes an identical insert hits
// again. Anything else (network, memory, timeouts, too many parts while
// merges catch up) is treated as an outage and retried.
var permanentCodes = map[int32]bool{
	6: true, 7: true, 8: true, 15: true, 16: true, 19: true, 20: true, // parse, column count, missing column
	25: true, 26: true, 27: true, 36: true, 38: true, 41: true, // parse, bad arguments
	43: true, 47: true, 53: true, 60: true, 62: true, 69: true, 70: true, 72: true, // types, unknown table, syntax
	81: true, 115: true, 117: true, 131: true, 164: true, // unknown database or setting, incorrect data, readonly
	192: true, 193: true, 321: true, 349: true, 376: true, 467: true, // auth, out of range, NULL, UUID, bool
	497: true, 516: true, 565: true, 691: true, // access denied, auth failed, too many partitions, enum element
}

// codeTooManyParts covers two cases. "Too many parts" while merges lag is
// an outage that clears; "too many partitions for single INSERT block" is
// the batch itself and fails every time, so only that message is permanent.
const codeTooManyParts = 252

// classify wraps err in ErrPermanent when retrying the same insert cannot
// succeed.
func classify(err error) error {
	var ex *clickhouse.Exception
	if !errors.As(err, &ex) {
		return err
	}
	if permanentCodes[ex.Code] ||
		(ex.Code == codeTooManyParts && strings.Contains(strings.ToLower(ex.Message), "partitions for single insert block")) {
		return fmt.Errorf("%w: %w", ErrPermanent, err)
	}
	return err
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
// so the rows of a successful Insert are all stored. An error that would
// recur on retry wraps ErrPermanent; a row the client cannot encode is one.
func (c *ClickHouse) Insert(ctx context.Context, rows []pipe.Alert) error {
	batch, err := c.conn.PrepareBatch(ctx, c.query)
	if err != nil {
		return classify(err)
	}
	defer func() { _ = batch.Close() }()
	for _, a := range rows {
		fields := a.Fields
		if fields == nil {
			fields = map[string]string{}
		}
		if err := batch.Append(a.Partition, a.Seq, a.RuleID, a.RuleTitle, a.Severity,
			a.EventTime, a.IngestTime, a.HostID, a.Source, fields, a.Raw); err != nil {
			return fmt.Errorf("%w: append partition %d seq %d rule %s: %w", ErrPermanent, a.Partition, a.Seq, a.RuleID, err)
		}
	}
	return classify(batch.Send())
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
