//go:build integration

package chsink

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/pipe"
)

// TestReingestCollapsesInClickHouse is the idempotence property against a
// real ReplacingMergeTree: insert a batch, insert it again, merge, and the
// rows are the rows a single insert left. It applies the DDL from
// deploy/clickhouse (idempotent) and writes under a partition number no
// pipeline produces, so it can share the table with other runs.
//
// SIGNALMAN_CLICKHOUSE_DSN is set by `make integration` and the CI
// integration job. Without it the test skips locally and fails under
// CI=true, where a skip would read green without running.
func TestReingestCollapsesInClickHouse(t *testing.T) {
	dsn := os.Getenv("SIGNALMAN_CLICKHOUSE_DSN")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("SIGNALMAN_CLICKHOUSE_DSN is not set")
		}
		t.Skip("SIGNALMAN_CLICKHOUSE_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ch, err := Open(ctx, dsn, "signalman.alerts")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ch.Close() }()
	ddl, err := os.ReadFile(ddlPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range Statements(string(ddl)) {
		if err := ch.Conn().Exec(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}

	// Negative partitions never come from Kafka. TTL reads ingest_time, so
	// a recent ingest_time keeps the rows; half the event times are two
	// years old, which an event_time TTL would delete on the merge below.
	part := -int32(time.Now().UnixNano()%1_000_000_000) - 1
	now := time.Now().UTC().Truncate(time.Millisecond)
	var batch []pipe.Alert
	for seq := range uint64(50) {
		a := genAlert(part, seq, int(seq)%len(ruleIDs))
		a.EventTime, a.IngestTime = now, now.Add(time.Second)
		if seq%2 == 0 {
			a.EventTime = now.AddDate(-2, 0, 0)
		}
		batch = append(batch, a)
	}

	if err := ch.Insert(ctx, batch); err != nil {
		t.Fatal(err)
	}
	once := selectFinal(ctx, t, ch, part)
	if len(once) != len(batch) {
		t.Fatalf("%d rows after one insert of %d", len(once), len(batch))
	}

	if err := ch.Insert(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if again := selectFinal(ctx, t, ch, part); !reflect.DeepEqual(once, again) {
		t.Fatalf("SELECT FINAL changed after reingest\nonce  %v\nagain %v", once, again)
	}
	if err := ch.Conn().Exec(ctx, "OPTIMIZE TABLE signalman.alerts FINAL"); err != nil {
		t.Fatal(err)
	}
	var n uint64
	if err := ch.Conn().QueryRow(ctx, "SELECT count() FROM signalman.alerts WHERE partition = ?", part).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != uint64(len(batch)) {
		t.Fatalf("%d stored rows after OPTIMIZE FINAL, want %d", n, len(batch))
	}
	if merged := selectFinal(ctx, t, ch, part); !reflect.DeepEqual(once, merged) {
		t.Fatal("rows changed after OPTIMIZE FINAL")
	}
}

type row struct {
	Partition  int32
	Seq        uint64
	RuleID     string
	RuleTitle  string
	Severity   string
	EventTime  int64
	IngestTime int64
	HostID     string
	Source     string
	Fields     map[string]string
	Raw        string
}

func selectFinal(ctx context.Context, t *testing.T, ch *ClickHouse, part int32) []row {
	t.Helper()
	rows, err := ch.Conn().Query(ctx, `SELECT partition, seq, toString(rule_id), rule_title, toString(severity),
		event_time, ingest_time, host_id, source, fields, raw
		FROM signalman.alerts FINAL WHERE partition = ? ORDER BY seq, rule_id`, part)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []row
	for rows.Next() {
		var r row
		var et, it time.Time
		if err := rows.Scan(&r.Partition, &r.Seq, &r.RuleID, &r.RuleTitle, &r.Severity,
			&et, &it, &r.HostID, &r.Source, &r.Fields, &r.Raw); err != nil {
			t.Fatal(err)
		}
		r.EventTime, r.IngestTime = et.UnixMilli(), it.UnixMilli()
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
