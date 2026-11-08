//go:build integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/backend/ch"
	"github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/fixture"
	"github.com/atontalapur/signalman/internal/pipe/chsink"
	"github.com/atontalapur/signalman/internal/sigma"
)

// TestHuntEqualsReplayOverTheRuleDirectory is the Plan D gate over real
// rules: every fixture event of every rule in rules/ is stored through the
// events lane's inserter into a real ClickHouse, `signalman hunt` runs the
// whole directory over a window that excludes some of them, and each rule's
// rows must equal a v1 replay of the same events over the same window,
// logsource test included.
//
// SIGNALMAN_CLICKHOUSE_DSN is set by `make integration`. Without it the test
// skips locally and fails under CI=true. It creates its own table in
// signalman_it and drops it.
func TestHuntEqualsReplayOverTheRuleDirectory(t *testing.T) {
	dsn := os.Getenv("SIGNALMAN_CLICKHOUSE_DSN")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("SIGNALMAN_CLICKHOUSE_DSN is not set")
		}
		t.Skip("SIGNALMAN_CLICKHOUSE_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	tax, err := sigma.LoadTaxonomy(testTaxonomy)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := sigma.RuleFiles("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	rs, loadErrs := sigma.LoadRuleFiles(paths, tax)
	if len(loadErrs) > 0 {
		t.Fatalf("rules/ does not load: %v", loadErrs)
	}

	// Every fixture event, one Seq each, spread over four partitions and
	// one millisecond apart in event time.
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()
	var evs []*event.Event
	for _, r := range rs.Rules {
		f, err := fixture.Load(strings.TrimSuffix(r.Path, ".yml") + ".test.yml")
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range f.Cases {
			ev := *c.Event
			i := len(evs)
			ev.Partition, ev.Seq = int32(i%4), uint64(i)
			ev.EventTime = base.Add(time.Duration(i) * time.Millisecond)
			ev.IngestAt = now
			evs = append(evs, &ev)
		}
	}
	if len(evs) < 40 {
		t.Fatalf("only %d fixture events; the gate needs both matches and misses", len(evs))
	}

	table := fmt.Sprintf("signalman_it.hunt_%d", time.Now().UnixNano())
	tbl, err := chsink.OpenEvents(ctx, dsn, table)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tbl.Close() }()
	ddl, err := ch.CreateTableSQL(table)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"CREATE DATABASE IF NOT EXISTS signalman_it", ddl} {
		if err := tblExec(ctx, dsn, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	t.Cleanup(func() { _ = tblExec(context.Background(), dsn, "DROP TABLE IF EXISTS "+table) })
	rows := make([]ch.Row, len(evs))
	for i, ev := range evs {
		rows[i] = ch.Encode(ev)
	}
	// Twice: a redelivered batch must not change the answer.
	for range 2 {
		if err := tbl.Insert(ctx, rows); err != nil {
			t.Fatal(err)
		}
	}

	// The window drops the first two events and the last three.
	w := ch.Window{From: evs[2].EventTime, To: evs[len(evs)-3].EventTime}
	code, stdout, stderr := cli(t, "hunt", "--taxonomy", testTaxonomy, "--json",
		"--clickhouse", dsn, "--table", table,
		"--from", w.From.Format(time.RFC3339Nano), "--to", w.To.Format(time.RFC3339Nano), "../../rules")
	if code != exitOK {
		t.Fatalf("hunt exit %d\n%s%s", code, stdout, stderr)
	}
	got := map[string][]huntHit{}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var rec huntRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		got[rec.RuleID] = rec.Hits
	}

	matched := 0
	for i := range rs.Rules {
		r := &rs.Rules[i]
		want := replayHits(r, evs, w)
		matched += len(want)
		if !reflect.DeepEqual(got[r.ID], want) {
			q, _ := ch.HuntQuery(table, r, w)
			t.Errorf("%s (%s)\nhunt   %v\nreplay %v\nquery %s", r.ID, r.Path, got[r.ID], want, q)
		}
	}
	if matched == 0 {
		t.Fatal("no rule matched any event in the window; the comparison proved nothing")
	}
	t.Logf("%d rules, %d events, %d matches in the window, hunt equal to replay", len(rs.Rules), len(evs), matched)
}

// replayHits is what v1 alerts on for r over the events inside w, in the
// order the hunt returns.
func replayHits(r *sigma.Rule, evs []*event.Event, w ch.Window) []huntHit {
	e := v1.New(&sigma.RuleSet{Rules: []sigma.Rule{*r}})
	out := []huntHit{}
	for _, ev := range evs {
		if !w.Contains(ev.EventTime) {
			continue
		}
		for _, vd := range e.Evaluate(ev) {
			if vd.Matched {
				out = append(out, huntHit{Partition: vd.Partition, Seq: vd.Seq})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Partition != out[j].Partition {
			return out[i].Partition < out[j].Partition
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

func tblExec(ctx context.Context, dsn, q string) error {
	h, err := openHunter(ctx, dsn)
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	_, err = h.(sqlHunter).db.ExecContext(ctx, q)
	return err
}
