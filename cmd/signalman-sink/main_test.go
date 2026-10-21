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
