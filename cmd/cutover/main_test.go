package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/cutover"
)

func cli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

// prom serves instant queries from a table; anything else is an empty
// vector, as Prometheus answers for a metric nobody exports.
func prom(t *testing.T, vals map[string]float64) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		res := "[]"
		if v, ok := vals[q]; ok {
			res = fmt.Sprintf(`[{"metric":{},"value":[%s,"%g"]}]`, r.URL.Query().Get("time"), v)
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":%s}}`, res)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

var tuesday = time.Date(2026, 11, 3, 14, 0, 0, 0, time.UTC)

// clock sets the command's clock to t for one test.
func clock(t *testing.T, at time.Time) {
	t.Helper()
	prev := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = prev })
}

func drillFile(t *testing.T, back, fwd float64) string {
	t.Helper()
	mk := func(from, to int, w time.Time, s float64) *cutover.Step {
		eff := w.Add(time.Duration(s * float64(time.Second)))
		return &cutover.Step{From: from, To: to, WrittenAt: w, TookEffectAt: &eff, FirstNewAlertAt: &eff, Seconds: &s,
			OldEngine: "v2", NewEngine: "v1", MovedRules: 40, ResolutionSeconds: 1}
	}
	d := cutover.Drill{StartedAt: tuesday, Rollback: mk(100, 0, tuesday, back), RollForward: mk(0, 100, tuesday.Add(5*time.Minute), fwd)}
	p := filepath.Join(t.TempDir(), "gameday.json")
	if err := writeDrill(p, d); err != nil {
		t.Fatal(err)
	}
	return p
}

func g5Prom(t *testing.T) string {
	return prom(t, map[string]float64{
		`sum(rate(signalman_events_ingested_total[5m]))`: 49000,
		`sum(rate(signalman_events_ingested_total[7d]))`: 50000,
	})
}

func docCopy(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../docs/cutover.md")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "cutover.md")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckPrintsEvidenceAndChangesNothing(t *testing.T) {
	clock(t, tuesday.Add(time.Hour))
	doc := docCopy(t)
	before, _ := os.ReadFile(doc)
	code, out, stderr := cli(t, "check", "-gate", "g5", "-prom", g5Prom(t), "-drill", drillFile(t, 8, 12), "-doc", doc)
	if code != exitOK {
		t.Fatalf("code %d\n%s\n%s", code, out, stderr)
	}
	for _, want := range []string{"G5 PASSED", "rollback", "roll-forward", "business-hours", "full-traffic", "took effect"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	after, _ := os.ReadFile(doc)
	if !bytes.Equal(before, after) {
		t.Fatal("check without -record changed the document")
	}
}

func TestCheckRecordWritesTheDateAndEvidence(t *testing.T) {
	clock(t, tuesday.Add(2*time.Hour))
	doc := docCopy(t)
	// G5 is recorded only once G0 to G4 have dates.
	b, _ := os.ReadFile(doc)
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		for _, g := range []string{"G0", "G1", "G2", "G3", "G4"} {
			if strings.HasPrefix(l, "| "+g+" ") && strings.HasSuffix(l, "| |") {
				lines[i] = strings.TrimSuffix(l, " |") + " 2026-10-01 |"
			}
		}
	}
	if err := os.WriteFile(doc, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := cli(t, "check", "-gate", "G5", "-at", "2026-11-03T15:00:00Z", "-prom", g5Prom(t), "-drill", drillFile(t, 8, 12), "-doc", doc, "-record")
	if code != exitOK {
		t.Fatalf("code %d\n%s\n%s", code, out, stderr)
	}
	b, _ = os.ReadFile(doc)
	if d := cutover.LadderDates(string(b)); d["G5"] != "2026-11-03" {
		t.Fatalf("G5 dated %q", d["G5"])
	}
	if !strings.Contains(string(b), "### G5 passed 2026-11-03") || !strings.Contains(string(b), "-record`.") {
		t.Fatalf("no evidence block:\n%s", b)
	}
}

func TestCheckRecordRefusesAFailedGate(t *testing.T) {
	clock(t, tuesday.Add(time.Hour))
	doc := docCopy(t)
	before, _ := os.ReadFile(doc)
	code, out, stderr := cli(t, "check", "-gate", "G5", "-prom", g5Prom(t), "-drill", drillFile(t, 8, 45), "-doc", doc, "-record")
	if code != exitFail || !strings.Contains(stderr, "nothing recorded") || !strings.Contains(out, "NOT PASSED") {
		t.Fatalf("code %d\n%s\n%s", code, out, stderr)
	}
	after, _ := os.ReadFile(doc)
	if !bytes.Equal(before, after) {
		t.Fatal("a failed gate changed the document")
	}
}

func TestCheckJSON(t *testing.T) {
	code, out, _ := cli(t, "check", "-gate", "G1", "-prom", prom(t, nil), "-json")
	if code != exitFail {
		t.Fatalf("G1 against an empty Prometheus exited %d", code)
	}
	var r cutover.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if r.Gate != "G1" || r.Passed() || len(r.Checks) == 0 {
		t.Fatalf("report %+v", r)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"nope"},
		{"check"},
		{"check", "-gate", "G9", "-prom", "http://x"},
		{"check", "-gate", "G2"},
		{"check", "-gate", "G5", "-business-hours", "17-9", "-prom", "http://x"},
		{"check", "-gate", "G1", "-prom", "http://x", "-attest", "novalue"},
		{"gameday", "-prom", "http://x"},
		{"measure", "-prom", "http://x", "-out", "x.json"},
		{"measure", "-prom", "http://x", "-from", "0", "-to", "100", "-written-at", "2026-11-03T14:00:00Z", "-forward-at", "2026-11-03T14:05:00Z", "-out", "x.json"},
	} {
		if code, _, _ := cli(t, args...); code != exitUsage {
			t.Errorf("%q exited %d, want %d", args, code, exitUsage)
		}
	}
}

func TestParseHours(t *testing.T) {
	if lo, hi, err := parseHours("8-18"); err != nil || lo != 8 || hi != 18 {
		t.Fatalf("%d %d %v", lo, hi, err)
	}
	for _, bad := range []string{"9", "a-b", "-1-5", "9-25", "12-12"} {
		if _, _, err := parseHours(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// -at after now is a window that has not ended: refused before any query,
// and nothing is recorded.
func TestCheckRefusesAnAtInTheFuture(t *testing.T) {
	clock(t, tuesday)
	doc := docCopy(t)
	before, _ := os.ReadFile(doc)
	code, out, stderr := cli(t, "check", "-gate", "G5", "-at", "2026-11-03T15:00:00Z", "-prom", g5Prom(t), "-drill", drillFile(t, 8, 12), "-doc", doc, "-record")
	if code != exitUsage || !strings.Contains(stderr, "after now") {
		t.Fatalf("code %d\n%s\n%s", code, out, stderr)
	}
	after, _ := os.ReadFile(doc)
	if !bytes.Equal(before, after) {
		t.Fatal("a future -at changed the document")
	}
}
