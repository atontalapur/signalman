//go:build integration

package ch

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2" // registers the "clickhouse" database/sql driver

	"github.com/atontalapur/signalman/internal/event"
)

// TestRetroHuntEqualsReplay loads a fixture of awkward events into a real
// ClickHouse, retro-hunts every rule below over a window, and requires the
// rows to equal a v1 replay of the same events over the same window.
//
// SIGNALMAN_CLICKHOUSE_DSN is a clickhouse-go DSN; `make integration` sets
// it to the compose server, clickhouse://signalman:signalman@localhost:9000/signalman.
// Without it the test skips locally and fails under CI=true. The test
// creates its own database, signalman_it, and never touches another.
func TestRetroHuntEqualsReplay(t *testing.T) {
	dsn, reason, fatal := integrationDSN(os.Getenv)
	if fatal {
		t.Fatal(reason)
	}
	if dsn == "" {
		t.Skip(reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	table := fmt.Sprintf("signalman_it.events_%d", time.Now().UnixNano())
	mustExec(t, ctx, db, "CREATE DATABASE IF NOT EXISTS signalman_it")
	ddl, err := CreateTableSQL(table)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, ctx, db, ddl)
	t.Cleanup(func() { _, _ = db.Exec("DROP TABLE IF EXISTS " + table) })

	evs := fixture()
	// The fixture's times are in 1970. Retention reads ingest_time, so stamp
	// it with now or the TTL could delete the rows before the hunt reads them.
	now := time.Now().UTC()
	for _, ev := range evs {
		ev.IngestAt = now
	}
	// Twice: a redelivered batch must not change the answer before or after
	// the ReplacingMergeTree merges.
	insert(t, ctx, db, table, evs)
	insert(t, ctx, db, table, evs)

	w := Window{From: msTime(1000), To: msTime(1000 + int64(len(evs)) - 2)}
	tax := testTaxonomy(t)
	check := func(when string) {
		for _, det := range huntRules {
			r := loadDetection(t, tax, det)
			want := replay(r, evs, w)
			got, err := RetroHunt(ctx, db, table, r, w)
			if err != nil {
				t.Fatalf("%s\n%v", det, err)
			}
			if len(got) == 0 && len(want) == 0 {
				got, want = nil, nil
			}
			if !reflect.DeepEqual(got, want) {
				q, _ := HuntQuery(table, r, w)
				t.Errorf("%s: rule\n%s\nretro-hunt %v\nreplay     %v\nquery %s", when, det, got, want, q)
			}
		}
	}
	check("before the merge")
	// FINAL forces the merge, so the duplicates are gone on disk rather
	// than folded by DISTINCT.
	mustExec(t, ctx, db, "OPTIMIZE TABLE "+table+" FINAL")
	check("after the merge")
}

func mustExec(t *testing.T, ctx context.Context, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.ExecContext(ctx, q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func insert(t *testing.T, ctx context.Context, db *sql.DB, table string, evs []*event.Event) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO "+table)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range evs {
		if _, err := stmt.ExecContext(ctx, Encode(ev).Values()...); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
