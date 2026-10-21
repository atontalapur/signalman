package main

import (
	"log/slog"
	"strconv"
	"testing"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/sigma"
)

func TestFlagsRequireRules(t *testing.T) {
	if _, err := parseFlags(nil); err == nil {
		t.Fatal("-rules is required")
	}
	f, err := parseFlags([]string{"-rules", "r", "-match-workers", "3"})
	if err != nil {
		t.Fatal(err)
	}
	if f.matchWorkers != 3 || f.normalizeWorkers != 8 {
		t.Fatalf("flags %+v", f)
	}
}

func TestStrictLoadRefusesRejections(t *testing.T) {
	tax, err := sigma.LoadTaxonomy("../../internal/sigma/testdata/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	// This directory holds an aggregation rule and an unmapped logsource.
	dir := "../../internal/sigma/testdata/rules"
	if _, err := loadRules(dir, tax, true, log); err == nil {
		t.Fatal("-strict must refuse a rule set with rejections")
	}
	rs, err := loadRules(dir, tax, false, log)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) == 0 {
		t.Fatal("non-strict loads what it can")
	}
}

func TestTopicSpecsCoverEveryPipelineTopic(t *testing.T) {
	specs := topicSpecs(8)
	if len(specs) != 5 {
		t.Fatalf("%d topics", len(specs))
	}
	for _, s := range specs {
		if s.Partitions != 8 || s.Replication != 1 {
			t.Fatalf("spec %+v", s)
		}
		if s.Configs["max.message.bytes"] != strconv.Itoa(broker.MaxMessageBytes) {
			t.Fatalf("%s: max.message.bytes %q; topics and producer share one limit", s.Name, s.Configs["max.message.bytes"])
		}
	}
}
