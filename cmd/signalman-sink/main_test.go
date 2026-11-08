package main

import (
	"testing"
	"time"
)

func TestFlagDefaults(t *testing.T) {
	f, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.group != "signalman-sink" || f.table != "alerts" || f.batchRows != 5000 || f.flushInterval != time.Second {
		t.Fatalf("defaults %+v", f)
	}
	// signalmand serves :9464; both run on one host in the compose setup.
	if f.metricsAddr == ":9464" {
		t.Fatal("metrics address collides with signalmand")
	}
}

func TestFlagsRejectZeroSizes(t *testing.T) {
	for _, args := range [][]string{
		{"-batch-rows", "0"},
		{"-flush-interval", "0s"},
		{"-max-poll", "0"},
		{"-clickhouse", ""},
	} {
		if _, err := parseFlags(args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

// The events lane is its own consumer group, table, and metrics port, so it
// can run beside the alert lane on one host without sharing offsets.
func TestEventsLaneDefaults(t *testing.T) {
	f, err := parseFlags([]string{"-lane", "events"})
	if err != nil {
		t.Fatal(err)
	}
	if f.group != "signalman-events" || f.table != "events" {
		t.Fatalf("events lane defaults %+v", f)
	}
	for _, taken := range []string{":9464", ":9465", ":9466"} {
		if f.metricsAddr == taken {
			t.Fatalf("events lane metrics address %s collides with signalmand, the alert sink, or the differ", taken)
		}
	}
	// Explicit flags still win.
	f, err = parseFlags([]string{"-lane", "events", "-group", "g", "-table", "t", "-metrics-addr", ":1"})
	if err != nil {
		t.Fatal(err)
	}
	if f.group != "g" || f.table != "t" || f.metricsAddr != ":1" {
		t.Fatalf("explicit flags lost: %+v", f)
	}
	if _, err := parseFlags([]string{"-lane", "verdicts"}); err == nil {
		t.Fatal("unknown lane accepted")
	}
}
