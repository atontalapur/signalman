package main

import "testing"

func TestFlagsHaveBoundedDefaults(t *testing.T) {
	f, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.queue != 256 || f.maxPoll != 500 || f.group != "differ" {
		t.Fatalf("defaults %+v", f)
	}
	if _, err := parseFlags([]string{"-queue", "0"}); err == nil {
		t.Fatal("an unbounded or empty window is refused")
	}
}
