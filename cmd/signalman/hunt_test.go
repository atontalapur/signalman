package main

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/backend/ch"
	"github.com/atontalapur/signalman/internal/sigma"
)

// stubHunter answers every rule from a fixed table and records the window
// and table it was asked about.
type stubHunter struct {
	hits   map[string][]ch.Hit
	fail   map[string]error
	window ch.Window
	table  string
	closed bool
}

func (s *stubHunter) Hunt(_ context.Context, table string, r *sigma.Rule, w ch.Window) ([]ch.Hit, error) {
	s.table, s.window = table, w
	if err := s.fail[r.ID]; err != nil {
		return nil, err
	}
	return s.hits[r.ID], nil
}

func (s *stubHunter) Close() error { s.closed = true; return nil }

// withHunter makes cmdHunt use h instead of dialing ClickHouse, and returns
// the DSN it was asked to dial.
func withHunter(t *testing.T, h *stubHunter) *string {
	t.Helper()
	var dsn string
	prev := openHunter
	openHunter = func(_ context.Context, d string) (hunter, error) {
		dsn = d
		return h, nil
	}
	t.Cleanup(func() { openHunter = prev })
	return &dsn
}

func procDumpRuleID(t *testing.T) string {
	t.Helper()
	tax, err := sigma.LoadTaxonomy(testTaxonomy)
	if err != nil {
		t.Fatal(err)
	}
	r, lerr := sigma.LoadRule("testdata/pass/proc_dump.yml", tax)
	if lerr != nil {
		t.Fatal(lerr)
	}
	return r.ID
}

func TestHuntFlagErrors(t *testing.T) {
	withHunter(t, &stubHunter{})
	cases := [][]string{
		{"hunt", "--taxonomy", testTaxonomy, "--to", "2026-11-02T00:00:00Z", "testdata/pass"},
		{"hunt", "--taxonomy", testTaxonomy, "--from", "2026-11-01T00:00:00Z", "testdata/pass"},
		{"hunt", "--taxonomy", testTaxonomy, "--from", "yesterday", "--to", "2026-11-02T00:00:00Z", "testdata/pass"},
		{"hunt", "--taxonomy", testTaxonomy, "--from", "2026-11-02T00:00:00Z", "--to", "2026-11-01T00:00:00Z", "testdata/pass"},
		{"hunt", "--taxonomy", testTaxonomy, "--from", "2026-11-01T00:00:00Z", "--to", "2026-11-02T00:00:00Z"},
		{"hunt", "--taxonomy", testTaxonomy, "--from", "2026-11-01T00:00:00Z", "--to", "2026-11-02T00:00:00Z", "--table", "events; DROP TABLE alerts", "testdata/pass"},
	}
	for _, args := range cases {
		if code, stdout, stderr := cli(t, args...); code != exitUsage {
			t.Errorf("%v: code %d, want %d\n%s%s", args, code, exitUsage, stdout, stderr)
		}
	}
}

func TestHuntPrintsEveryHitPerRule(t *testing.T) {
	id := procDumpRuleID(t)
	h := &stubHunter{hits: map[string][]ch.Hit{id: {{Partition: 0, Seq: 4}, {Partition: 3, Seq: 17}}}}
	dsn := withHunter(t, h)
	t.Setenv("SIGNALMAN_CLICKHOUSE_DSN", "clickhouse://from-env")
	code, stdout, stderr := cli(t, "hunt", "--taxonomy", testTaxonomy,
		"--from", "2026-11-01T00:00:00Z", "--to", "2026-11-02T00:00:00Z", "testdata/pass")
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
	for _, want := range []string{
		id + "  2 hits  testdata/pass/proc_dump.yml",
		"  partition 0 seq 4",
		"  partition 3 seq 17",
		"1 rules, 2 hits over [2026-11-01T00:00:00Z, 2026-11-02T00:00:00Z)",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if *dsn != "clickhouse://from-env" {
		t.Errorf("dialed %q, want the SIGNALMAN_CLICKHOUSE_DSN value", *dsn)
	}
	if h.table != ch.DefaultTable {
		t.Errorf("table %q, want %q", h.table, ch.DefaultTable)
	}
	want := ch.Window{From: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)}
	if !h.window.From.Equal(want.From) || !h.window.To.Equal(want.To) {
		t.Errorf("window %v, want %v", h.window, want)
	}
	if !h.closed {
		t.Error("the hunter was not closed")
	}
}

func TestHuntJSON(t *testing.T) {
	id := procDumpRuleID(t)
	withHunter(t, &stubHunter{hits: map[string][]ch.Hit{id: {{Partition: 1, Seq: 2}}}})
	code, stdout, stderr := cli(t, "hunt", "--taxonomy", testTaxonomy, "--json", "--table", "signalman.events_x",
		"--clickhouse", "clickhouse://flag", "--from", "2026-11-01T00:00:00Z", "--to", "2026-11-02T00:00:00Z", "testdata/pass")
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
	var rec huntRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &rec); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if rec.RuleID != id || len(rec.Hits) != 1 || rec.Hits[0] != (huntHit{Partition: 1, Seq: 2}) {
		t.Fatalf("record %+v", rec)
	}
}

// A rule that does not load, or that the backend cannot compile, fails the
// command, but every other rule is still hunted.
func TestHuntFailsOnARuleItCannotRun(t *testing.T) {
	id := procDumpRuleID(t)
	withHunter(t, &stubHunter{fail: map[string]error{id: errors.New("boom")}})
	code, stdout, _ := cli(t, "hunt", "--taxonomy", testTaxonomy,
		"--from", "2026-11-01T00:00:00Z", "--to", "2026-11-02T00:00:00Z", "testdata/pass")
	if code != exitFail || !strings.Contains(stdout, "FAIL  "+id) || !strings.Contains(stdout, "boom") {
		t.Fatalf("code %d\n%s", code, stdout)
	}
}

// With --json every line of stdout is one JSON object, failures included.
func TestHuntJSONReportsFailuresAsRecords(t *testing.T) {
	id := procDumpRuleID(t)
	withHunter(t, &stubHunter{fail: map[string]error{id: errors.New("boom")}})
	code, stdout, _ := cli(t, "hunt", "--taxonomy", testTaxonomy, "--json",
		"--from", "2026-11-01T00:00:00Z", "--to", "2026-11-02T00:00:00Z", "testdata/pass")
	if code != exitFail {
		t.Fatalf("code %d\n%s", code, stdout)
	}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var rec huntRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("not JSON: %q: %v", line, err)
		}
		if rec.RuleID != id || !strings.Contains(rec.Error, "boom") {
			t.Fatalf("record %+v, want rule %s with the error", rec, id)
		}
	}
}

// A rule that does not load is reported even when ClickHouse cannot be
// reached, and with nothing loaded the command never dials.
func TestHuntReportsLoadErrorsWithoutClickHouse(t *testing.T) {
	dialed := false
	prev := openHunter
	openHunter = func(context.Context, string) (hunter, error) {
		dialed = true
		return nil, errors.New("connection refused")
	}
	t.Cleanup(func() { openHunter = prev })
	code, stdout, _ := cli(t, "hunt", "--taxonomy", testTaxonomy,
		"--from", "2026-11-01T00:00:00Z", "--to", "2026-11-02T00:00:00Z", "testdata/gates/always")
	if code != exitFail || !strings.Contains(stdout, "FAIL") {
		t.Fatalf("code %d, want %d with the load error\n%s", code, exitFail, stdout)
	}
	if dialed {
		t.Fatal("dialed ClickHouse with no rule loaded")
	}
}

// concurrentHunter records how many hunts ran at once.
type concurrentHunter struct {
	mu        sync.Mutex
	cur, peak int
}

func (c *concurrentHunter) Hunt(context.Context, string, *sigma.Rule, ch.Window) ([]ch.Hit, error) {
	c.mu.Lock()
	c.cur++
	c.peak = max(c.peak, c.cur)
	c.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	c.mu.Lock()
	c.cur--
	c.mu.Unlock()
	return nil, nil
}

func (c *concurrentHunter) Close() error { return nil }

// --parallel runs that many queries at once, never more, and the output
// stays in rule order whatever order they finish in.
func TestHuntRunsRulesInParallelInRuleOrder(t *testing.T) {
	c := &concurrentHunter{}
	prev := openHunter
	openHunter = func(context.Context, string) (hunter, error) { return c, nil }
	t.Cleanup(func() { openHunter = prev })
	args := []string{"hunt", "--taxonomy", testTaxonomy, "--parallel", "3",
		"--from", "2026-11-01T00:00:00Z", "--to", "2026-11-02T00:00:00Z", "../../rules"}
	code, stdout, stderr := cli(t, args...)
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
	if c.peak != 3 {
		t.Fatalf("peak concurrency %d, want 3", c.peak)
	}
	_, again, _ := cli(t, args...)
	if again != stdout {
		t.Fatalf("output order changed between runs:\n%s\n---\n%s", stdout, again)
	}
	// The rule set is ordered by rule id; the output must be too.
	var ids []string
	for _, line := range strings.Split(stdout, "\n") {
		if f := strings.Fields(line); len(f) == 4 && f[2] == "hits" {
			ids = append(ids, f[0])
		}
	}
	if !sort.StringsAreSorted(ids) || len(ids) < 20 {
		t.Fatalf("rules not in rule set order: %v", ids)
	}
}

func TestHuntRejectsAZeroParallelism(t *testing.T) {
	withHunter(t, &stubHunter{})
	if code, _, _ := cli(t, "hunt", "--taxonomy", testTaxonomy, "--parallel", "0",
		"--from", "2026-11-01T00:00:00Z", "--to", "2026-11-02T00:00:00Z", "testdata/pass"); code != exitUsage {
		t.Fatalf("code %d, want %d", code, exitUsage)
	}
}
