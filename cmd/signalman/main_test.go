package main

import (
	"bytes"
	"strings"
	"testing"
)

const testTaxonomy = "../../config/taxonomy"

// cli runs the command in-process and returns its exit code and output.
func cli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestNoSubcommandIsAUsageError(t *testing.T) {
	code, _, stderr := cli(t)
	if code != exitUsage || !strings.Contains(stderr, "usage") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	code, _, stderr = cli(t, "frobnicate")
	if code != exitUsage || !strings.Contains(stderr, "frobnicate") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestTestPassesAgreeingFixtures(t *testing.T) {
	code, stdout, stderr := cli(t, "test", "--taxonomy", testTaxonomy, "testdata/pass")
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "ok    testdata/pass/proc_dump.yml  2 cases") {
		t.Fatalf("stdout:\n%s", stdout)
	}
}

func TestTestFailsOnDisagreement(t *testing.T) {
	code, stdout, _ := cli(t, "test", "--taxonomy", testTaxonomy, "testdata/fail/proc_dump.yml")
	if code != exitFail {
		t.Fatalf("code %d, want %d\n%s", code, exitFail, stdout)
	}
	for _, want := range []string{
		"FAIL  testdata/fail/proc_dump.yml",
		`case "claims a match that is not one" (line 3): want match, got no-match`,
		"1 rules, 0 passed, 1 failed",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

func TestTestFailsARuleWithNoFixture(t *testing.T) {
	code, stdout, _ := cli(t, "test", "--taxonomy", testTaxonomy, "testdata/nofixture")
	if code != exitFail || !strings.Contains(stdout, "proc_dump.test.yml") {
		t.Fatalf("code %d\n%s", code, stdout)
	}
}

func TestTestFailsARuleThatDoesNotLoad(t *testing.T) {
	code, stdout, _ := cli(t, "test", "--taxonomy", testTaxonomy, "../../internal/sigma/testdata/rules_bad/no_id.yml")
	if code != exitFail || !strings.Contains(stdout, "[missing-id]") {
		t.Fatalf("code %d\n%s", code, stdout)
	}
}

func TestTestWithNoRulesIsAUsageError(t *testing.T) {
	if code, _, _ := cli(t, "test", "--taxonomy", testTaxonomy); code != exitUsage {
		t.Fatalf("code %d", code)
	}
	if code, _, _ := cli(t, "test", "--taxonomy", testTaxonomy, "testdata/missing"); code != exitUsage {
		t.Fatalf("code %d", code)
	}
}

// The Plan B gate: twenty hand-written rules pass their fixtures, plus the
// signalman-canary rule from Plan E, which is loaded like any other.
func TestShippedRulesPassTheirFixtures(t *testing.T) {
	code, stdout, stderr := cli(t, "test", "--taxonomy", testTaxonomy, "../../rules")
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "21 rules, 21 passed, 0 failed") {
		t.Fatalf("expected twenty rules and the canary:\n%s", stdout)
	}
}

func TestFlagsMayFollowPositionalArguments(t *testing.T) {
	code, stdout, stderr := cli(t, "test", "testdata/pass", "--taxonomy", testTaxonomy)
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
}
