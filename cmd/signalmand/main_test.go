package main

import (
	"log/slog"
	"testing"

	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus"
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
	if len(specs) != 7 {
		t.Fatalf("%d topics", len(specs))
	}
	for _, s := range specs {
		if s.Partitions != 8 || s.Replication != 1 {
			t.Fatalf("spec %+v", s)
		}
	}
}

func TestShadowFlagInstallsV2BesideV1(t *testing.T) {
	tax, err := sigma.LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := loadRules("../../internal/engine/v1/testdata/rules", tax, true, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseFlags([]string{"-rules", "r", "-shadow"})
	if err != nil || !f.shadow {
		t.Fatalf("-shadow: %+v %v", f, err)
	}
	slot := pipe.NewSlot(pipe.V1(rs), obs.New(prometheus.NewRegistry()))
	if err := install(slot, rs, true); err != nil {
		t.Fatal(err)
	}
	if slot.Load().Name() != "v1" || slot.Shadow() == nil || slot.Shadow().Name() != "v2" {
		t.Fatal("shadow mode serves from v1 with v2 beside it")
	}
	if err := install(slot, rs, false); err != nil || slot.Shadow() != nil {
		t.Fatal("without -shadow there is no shadow engine")
	}
}
