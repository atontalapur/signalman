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

func TestPrimaryFlag(t *testing.T) {
	f, err := parseFlags(nil)
	if err != nil || f.primary != "v1" {
		t.Fatalf("default -primary %q, %v", f.primary, err)
	}
	if f, err := parseFlags([]string{"-primary", "v2"}); err != nil || f.primary != "v2" {
		t.Fatalf("-primary v2: %q, %v", f.primary, err)
	}
	if _, err := parseFlags([]string{"-primary", "v3"}); err == nil {
		t.Fatal("-primary v3 accepted")
	}
}
