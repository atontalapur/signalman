package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// writeRule copies the shipped proc_dump rule with extra lines appended.
func writeRule(t *testing.T, extra string) string {
	t.Helper()
	src, err := os.ReadFile("../../rules/proc_dump.yml")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "proc_dump.yml")
	if err := os.WriteFile(p, append(src, []byte(extra)...), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNoiseReportsRateAndSamples(t *testing.T) {
	code, stdout, stderr := cli(t, "noise", "--taxonomy", testTaxonomy,
		"../../rules/proc_dump.yml", "--corpus", "testdata/corpus")
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
	for _, want := range []string{
		"events    6",
		"matches   2",
		"per 100k  33333.3",
		"budget    none declared",
		filepath.Join("testdata/corpus", "a.ndjson") + ":1",
		filepath.Join("testdata/corpus", "sub", "b.jsonl") + ":1",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "a.ndjson:2") {
		t.Errorf("a non-matching event is not a sample:\n%s", stdout)
	}
}

func TestNoiseWithinBudgetPasses(t *testing.T) {
	rule := writeRule(t, "budget: 40000\n")
	code, stdout, _ := cli(t, "noise", "--taxonomy", testTaxonomy, "--corpus", "testdata/corpus", rule)
	if code != exitOK || !strings.Contains(stdout, "budget    40000 per 100k, within") {
		t.Fatalf("code %d\n%s", code, stdout)
	}
}

func TestNoiseOverBudgetFails(t *testing.T) {
	rule := writeRule(t, "budget: 5\n")
	code, stdout, _ := cli(t, "noise", "--taxonomy", testTaxonomy, "--corpus", "testdata/corpus", rule)
	if code != exitFail || !strings.Contains(stdout, "budget    5 per 100k, EXCEEDED") {
		t.Fatalf("code %d\n%s", code, stdout)
	}
}

func TestNoisePrintsAtMostTenSamples(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < 15; i++ {
		fmt.Fprintf(&b, `{"channel":"Microsoft-Windows-Sysmon/Operational","event_id":1,"Image":"C:\\rundll32.exe","CommandLine":"comsvcs.dll MiniDump %d"}`+"\n", i)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.ndjson"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := cli(t, "noise", "--taxonomy", testTaxonomy, "--corpus", dir, "../../rules/proc_dump.yml")
	if code != exitOK {
		t.Fatalf("code %d\n%s", code, stdout)
	}
	if n := strings.Count(stdout, "x.ndjson:"); n != 10 {
		t.Fatalf("%d samples:\n%s", n, stdout)
	}
	if !strings.Contains(stdout, "x.ndjson:10 ") || strings.Contains(stdout, "x.ndjson:11 ") {
		t.Fatalf("samples are the first ten in corpus order:\n%s", stdout)
	}
	if !strings.Contains(stdout, "matches   15") {
		t.Fatalf("the count covers every match:\n%s", stdout)
	}
}

func TestNoiseUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"../../rules/proc_dump.yml"},
		{"--corpus", "testdata/corpus"},
		{"--corpus", "testdata/corpus", "../../rules/proc_dump.yml", "../../rules/mshta_remote.yml"},
		{"--corpus", "testdata/missing", "../../rules/proc_dump.yml"},
	} {
		code, _, stderr := cli(t, append([]string{"noise", "--taxonomy", testTaxonomy}, args...)...)
		if code != exitUsage || stderr == "" {
			t.Errorf("%v: code %d, stderr %q", args, code, stderr)
		}
	}
}

func TestNoiseOnARuleThatDoesNotLoadFails(t *testing.T) {
	rule := writeRule(t, "budget: lots\n")
	code, stdout, _ := cli(t, "noise", "--taxonomy", testTaxonomy, "--corpus", "testdata/corpus", rule)
	if code != exitFail || !strings.Contains(stdout, "[yaml]") || !strings.Contains(stdout, "budget") {
		t.Fatalf("code %d\n%s", code, stdout)
	}
}

func TestSampleTextCutsOnARuneBoundary(t *testing.T) {
	raw := []byte(strings.Repeat("a", maxSample-1) + "é" + "tail")
	got := sampleText(raw)
	if !strings.HasSuffix(got, " ...") || !utf8.ValidString(got) {
		t.Fatalf("got %q", got[len(got)-10:])
	}
}
