package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLintPassesTheShippedRules(t *testing.T) {
	code, stdout, stderr := cli(t, "lint", "--taxonomy", testTaxonomy, "../../rules")
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "21 rules, 21 loaded, 0 rejected") {
		t.Fatalf("stdout:\n%s", stdout)
	}
}

func TestLintPrintsEveryLoadErrorStructured(t *testing.T) {
	code, stdout, _ := cli(t, "lint", "--taxonomy", testTaxonomy, "../../internal/sigma/testdata/rules_bad")
	if code != exitFail {
		t.Fatalf("code %d\n%s", code, stdout)
	}
	for _, want := range []string{
		"rules_bad/no_id.yml:1 [missing-id] rule : rule has no id",
		"[modifier]",
		"[yaml]",
		"[condition]",
		"[invalid-id]",
		"[level]",
		"8 rules, 0 loaded, 8 rejected",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

func TestLintReportsDuplicateIDsAcrossArguments(t *testing.T) {
	code, stdout, _ := cli(t, "lint", "--taxonomy", "../../internal/sigma/testdata/taxonomy",
		"../../internal/sigma/testdata/rules_dup/second.yml", "../../internal/sigma/testdata/rules_dup/first.yml")
	if code != exitFail || !strings.Contains(stdout, "[duplicate-id]") {
		t.Fatalf("code %d\n%s", code, stdout)
	}
}

func TestLintJSONIsOneObjectPerError(t *testing.T) {
	code, stdout, _ := cli(t, "lint", "--json", "--taxonomy", testTaxonomy, "../../internal/sigma/testdata/rules_bad")
	if code != exitFail {
		t.Fatalf("code %d", code)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 8 {
		t.Fatalf("want 8 lines, got:\n%s", stdout)
	}
	var e struct {
		Path, RuleID, Code, Reason string
		Line                       int
	}
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatal(err)
	}
	if e.Code == "" || e.Path == "" || e.Line == 0 {
		t.Fatalf("decoded %+v from %s", e, lines[0])
	}
}

func TestBenchReportsP99PerRule(t *testing.T) {
	code, stdout, stderr := cli(t, "bench", "--taxonomy", testTaxonomy, "--samples", "50", "--threshold", "1h", "../../rules")
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "p99") || !strings.Contains(stdout, "rules/proc_dump.yml") {
		t.Fatalf("stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "21 rules, 0 over the 1h0m0s p99 budget, 60 events") {
		t.Fatalf("stdout:\n%s", stdout)
	}
}

func TestBenchFlagsARuleOverBudget(t *testing.T) {
	code, stdout, _ := cli(t, "bench", "--taxonomy", testTaxonomy, "--samples", "20", "--threshold", "1ns", "../../rules/proc_dump.yml")
	if code != exitFail {
		t.Fatalf("code %d\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "SLOW") || !strings.Contains(stdout, "1 rules, 1 over the 1ns p99 budget") {
		t.Fatalf("stdout:\n%s", stdout)
	}
}

func TestBenchDefaultsToFiftyMicroseconds(t *testing.T) {
	_, stdout, _ := cli(t, "bench", "--taxonomy", testTaxonomy, "--samples", "20", "../../rules/proc_dump.yml")
	if !strings.Contains(stdout, "50µs p99 budget") {
		t.Fatalf("stdout:\n%s", stdout)
	}
}

func TestBenchTakesACorpus(t *testing.T) {
	code, stdout, stderr := cli(t, "bench", "--taxonomy", testTaxonomy, "--samples", "20", "--threshold", "1h",
		"--corpus", "testdata/corpus", "../../rules/proc_dump.yml")
	if code != exitOK || !strings.Contains(stdout, "6 events") {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
}

func TestBenchWithNoEventsIsAUsageError(t *testing.T) {
	code, _, stderr := cli(t, "bench", "--taxonomy", testTaxonomy, "testdata/nofixture")
	if code != exitUsage || !strings.Contains(stderr, "no events") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestReadCorpusIsOrderedAndSkipsBlankLines(t *testing.T) {
	evs, err := readCorpus("testdata/corpus")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 6 {
		t.Fatalf("got %d events", len(evs))
	}
	if evs[0].File != filepath.Join("testdata/corpus", "a.ndjson") || evs[0].Line != 1 {
		t.Fatalf("first = %s:%d", evs[0].File, evs[0].Line)
	}
	if evs[2].Line != 4 {
		t.Fatalf("the blank line still counts toward line numbers, got %d", evs[2].Line)
	}
	if evs[4].File != filepath.Join("testdata/corpus", "sub", "b.jsonl") {
		t.Fatalf("fifth = %s", evs[4].File)
	}
	for i, e := range evs {
		if e.Event.Seq != uint64(i) {
			t.Fatalf("seq %d at %d", e.Event.Seq, i)
		}
	}
}

func TestReadCorpusRejectsABadLine(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.ndjson"), []byte("{\"a\":1}\nnot json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readCorpus(dir)
	if err == nil || !strings.Contains(err.Error(), "x.ndjson:2") {
		t.Fatalf("err = %v", err)
	}
}

func TestReadCorpusMissingOrEmptyIsAnError(t *testing.T) {
	if _, err := readCorpus("testdata/missing"); err == nil {
		t.Fatal("missing dir")
	}
	if _, err := readCorpus(t.TempDir()); err == nil {
		t.Fatal("a corpus with no events is an error, not a zero rate")
	}
}

func TestQuantileIsNearestRank(t *testing.T) {
	d := make([]time.Duration, 100)
	for i := range d {
		d[i] = time.Duration(i + 1)
	}
	if quantile(d, 0.99) != 99 || quantile(d, 0.50) != 50 || quantile(d[:1], 0.99) != 1 {
		t.Fatalf("p99 %v p50 %v", quantile(d, 0.99), quantile(d, 0.50))
	}
}
