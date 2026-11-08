//go:build integration

package chsink

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
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
	// 002 adds the engine column to a table an older 001 created.
	for _, path := range []string{ddlPath, "../../../deploy/clickhouse/002_alerts_engine.sql"} {
		ddl, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range Statements(string(ddl)) {
			if err := ch.Conn().Exec(ctx, s); err != nil {
				t.Fatalf("%s: %v", s, err)
			}
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
	for i, r := range once {
		if r.Engine != batch[i].Engine {
			t.Fatalf("row %d engine %q, inserted %q", i, r.Engine, batch[i].Engine)
		}
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
	Engine     string
}

func selectFinal(ctx context.Context, t *testing.T, ch *ClickHouse, part int32) []row {
	t.Helper()
	rows, err := ch.Conn().Query(ctx, `SELECT partition, seq, toString(rule_id), rule_title, toString(severity),
		event_time, ingest_time, host_id, source, fields, raw, engine
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
			&et, &it, &r.HostID, &r.Source, &r.Fields, &r.Raw, &r.Engine); err != nil {
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

// On a volume created before the engine column existed, 001 does not run
// again and 002 adds the column. That path only happens on old volumes,
// which CI never has, so it is built here: 001 with the engine column cut,
// in a scratch table, then 002 against that table. Old rows must read
// engine as the empty string and new inserts must store it.
func TestEngineMigrationOnATableWithoutTheColumn(t *testing.T) {
	dsn := os.Getenv("SIGNALMAN_CLICKHOUSE_DSN")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("SIGNALMAN_CLICKHOUSE_DSN is not set")
		}
		t.Skip("SIGNALMAN_CLICKHOUSE_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	table := fmt.Sprintf("signalman_it.alerts_old_%d", time.Now().UnixNano())

	ddl, err := os.ReadFile(ddlPath)
	if err != nil {
		t.Fatal(err)
	}
	var create string
	for _, s := range Statements(string(ddl)) {
		if strings.HasPrefix(s, "CREATE TABLE") {
			create = s
		}
	}
	old := strings.Replace(create, "signalman.alerts", table, 1)
	old = strings.Replace(old, "raw         String CODEC(ZSTD(3)),\n  engine      LowCardinality(String)", "raw         String CODEC(ZSTD(3))", 1)
	if old == create || strings.Contains(old, "engine      LowCardinality") {
		t.Fatalf("could not build the pre-engine DDL from 001:\n%s", create)
	}
	mig, err := os.ReadFile("../../../deploy/clickhouse/002_alerts_engine.sql")
	if err != nil {
		t.Fatal(err)
	}
	stmts := Statements(string(mig))
	if len(stmts) != 1 || !strings.Contains(stmts[0], "signalman.alerts") {
		t.Fatalf("002 is not one ALTER on signalman.alerts: %v", stmts)
	}
	alter := strings.Replace(stmts[0], "signalman.alerts", table, 1)

	c, err := Open(ctx, dsn, table)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for _, q := range []string{"CREATE DATABASE IF NOT EXISTS signalman_it", old} {
		if err := c.Conn().Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	t.Cleanup(func() { _ = c.Conn().Exec(context.Background(), "DROP TABLE IF EXISTS "+table) })
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := c.Conn().Exec(ctx, "INSERT INTO "+table+
		" (partition, seq, rule_id, rule_title, severity, event_time, ingest_time, host_id, source, fields, raw)"+
		" VALUES (1, 1, ?, 't', 'low', ?, ?, 'h', 'sysmon', map(), '')", ruleIDs[0], now, now); err != nil {
		t.Fatal(err)
	}

	for range 2 { // IF NOT EXISTS: running it twice is safe
		if err := c.Conn().Exec(ctx, alter); err != nil {
			t.Fatalf("%s: %v", alter, err)
		}
	}
	a := genAlert(1, 2, 0)
	a.EventTime, a.IngestTime = now, now
	if err := c.Insert(ctx, []pipe.Alert{a}); err != nil {
		t.Fatalf("insert after the migration: %v", err)
	}
	rows, err := c.Conn().Query(ctx, "SELECT seq, engine FROM "+table+" ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	got := map[uint64]string{}
	for rows.Next() {
		var seq uint64
		var engine string
		if err := rows.Scan(&seq, &engine); err != nil {
			t.Fatal(err)
		}
		got[seq] = engine
	}
	if want := map[uint64]string{1: "", 2: a.Engine}; !reflect.DeepEqual(got, want) {
		t.Fatalf("engine by seq %v, want %v", got, want)
	}
}
