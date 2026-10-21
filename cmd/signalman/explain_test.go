package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExplainPrintsTheTree(t *testing.T) {
	code, stdout, stderr := cli(t, "explain", "--taxonomy", testTaxonomy,
		"../../rules/proc_dump.yml", "testdata/lsass.json")
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
	for _, want := range []string{
		"rule  proc_dump  (T1003.001 / LSASS Memory Dump via comsvcs)  => MATCH",
		"NOT filter_backup",
		`("C:\Windows\explorer.exe")`,
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

func TestExplainTakesTheEventAsAFlag(t *testing.T) {
	code, stdout, stderr := cli(t, "explain", "../../rules/proc_dump.yml",
		"--event", "testdata/lsass.json", "--taxonomy", testTaxonomy)
	if code != exitOK || !strings.Contains(stdout, "=> MATCH") {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
}

func TestExplainANonMatchingEventStillExitsZero(t *testing.T) {
	dir := t.TempDir()
	ev := filepath.Join(dir, "ev.json")
	if err := os.WriteFile(ev, []byte(`{"channel":"Security","event_id":4688}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := cli(t, "explain", "--taxonomy", testTaxonomy, "../../rules/proc_dump.yml", ev)
	if code != exitOK || !strings.Contains(stdout, "=> NO MATCH") {
		t.Fatalf("code %d\n%s", code, stdout)
	}
}

func TestExplainUsageErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`[1]`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"../../rules/proc_dump.yml"},
		{"../../rules/proc_dump.yml", "a.json", "b.json"},
		{"../../rules/proc_dump.yml", "--event", "testdata/lsass.json", "testdata/lsass.json"},
		{"../../rules/proc_dump.yml", "testdata/missing.json"},
		{"../../rules/proc_dump.yml", bad},
	} {
		code, _, stderr := cli(t, append([]string{"explain", "--taxonomy", testTaxonomy}, args...)...)
		if code != exitUsage || stderr == "" {
			t.Errorf("%v: code %d, stderr %q", args, code, stderr)
		}
	}
}

func TestExplainARuleThatDoesNotLoadFails(t *testing.T) {
	code, stdout, _ := cli(t, "explain", "--taxonomy", testTaxonomy,
		"../../internal/sigma/testdata/rules_bad/no_id.yml", "testdata/lsass.json")
	if code != exitFail || !strings.Contains(stdout, "[missing-id]") {
		t.Fatalf("code %d\n%s", code, stdout)
	}
}
