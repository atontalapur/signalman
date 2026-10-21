package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"

	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
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
	if _, err := loadRules(dir, tax, true, false, log); err == nil {
		t.Fatal("-strict must refuse a rule set with rejections")
	}
	rs, err := loadRules(dir, tax, false, false, log)
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

func TestCanaryNeedsItsRule(t *testing.T) {
	tax, err := sigma.LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	if _, err := loadRules("../../internal/engine/v1/testdata/rules", tax, true, true, log); err == nil {
		t.Fatal("a rule set without signalman-canary must be refused while the canary is on")
	}
	if _, err := loadRules("../../internal/engine/v1/testdata/rules", tax, true, false, log); err != nil {
		t.Fatalf("canary off: %v", err)
	}
	if _, err := loadRules("../../rules", tax, true, true, log); err != nil {
		t.Fatalf("shipped rules carry the canary: %v", err)
	}
	f, err := parseFlags([]string{"-rules", "r"})
	if err != nil || f.canaryInterval != 30*time.Second {
		t.Fatalf("default canary interval %v, err %v", f.canaryInterval, err)
	}
	if _, err := parseFlags([]string{"-rules", "r", "-canary-interval", "-1s"}); err == nil {
		t.Fatal("negative interval accepted")
	}
}

func TestShadowFlagInstallsV2BesideV1(t *testing.T) {
	tax, err := sigma.LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := loadRules("../../internal/engine/v1/testdata/rules", tax, true, false, slog.New(slog.DiscardHandler))
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

func TestParseRollout(t *testing.T) {
	for in, want := range map[string]int{
		"25\n":                        25,
		"0":                           0,
		"100":                         100,
		"# percent served by v2\n7\n": 7,
		"  42  \n\n":                  42,
	} {
		got, err := parseRollout([]byte(in))
		if err != nil || got != want {
			t.Fatalf("parseRollout(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "# only a comment\n", "101", "-1", "ten", "5\n6\n", "5%"} {
		if _, err := parseRollout([]byte(bad)); err == nil {
			t.Fatalf("parseRollout(%q) accepted", bad)
		}
	}
}

func TestRolloutFlagImpliesShadow(t *testing.T) {
	f, err := parseFlags([]string{"-rules", "r", "-rollout", "rollout.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.shadow || f.rolloutPoll != defaultRolloutPoll {
		t.Fatalf("flags %+v", f)
	}
	if defaultRolloutPoll >= 30*time.Second {
		t.Fatal("the poll interval alone would miss the 30 second rollback budget")
	}
}

func TestBadRolloutFileKeepsTheCurrentRollout(t *testing.T) {
	rs := fixtureRules(t)
	slot := pipe.NewSlot(pipe.V1(rs), obs.New(prometheus.NewRegistry()))
	if err := install(slot, rs, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rollout")
	writeFile(t, path, "30\n")
	if err := applyRollout(path, slot, slog.New(slog.DiscardHandler)); err != nil || slot.Rollout() != 30 {
		t.Fatalf("rollout %d, %v", slot.Rollout(), err)
	}
	writeFile(t, path, "thirty\n")
	if err := applyRollout(path, slot, slog.New(slog.DiscardHandler)); err == nil || slot.Rollout() != 30 {
		t.Fatalf("a bad file must be refused and leave 30%%, got %d, %v", slot.Rollout(), err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := applyRollout(path, slot, slog.New(slog.DiscardHandler)); err == nil || slot.Rollout() != 30 {
		t.Fatalf("a missing file must be refused and leave 30%%, got %d, %v", slot.Rollout(), err)
	}
}

func fixtureRules(t *testing.T) *sigma.RuleSet {
	t.Helper()
	tax, err := sigma.LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := loadRules("../../internal/engine/v1/testdata/rules", tax, true, false, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	// Write and rename, the way an operator's config tool should, so the
	// poller never reads half a file.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// TestRollbackTakesEffectWithin30Seconds runs the pipeline at 100% served
// by v2 under steady load, rewrites the rollout file to 0, and measures how
// long it takes until alerts come from v1, with the daemon's own poll
// interval and no SIGHUP. Every alert after the first v1 alert must come
// from v1 too: a rollback is not a flicker.
func TestRollbackTakesEffectWithin30Seconds(t *testing.T) {
	tax, err := sigma.LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	rs := fixtureRules(t)
	topics := map[string]int32{}
	for _, tp := range topicSpecs(2) {
		topics[tp.Name] = tp.Partitions
	}
	mem := broker.NewMemory(topics, broker.WithMaxPoll(20))
	m := obs.New(prometheus.NewRegistry())
	slot := pipe.NewSlot(pipe.V1(rs), m)
	if err := install(slot, rs, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rollout")
	writeFile(t, path, "100\n")
	log := slog.New(slog.DiscardHandler)
	if err := applyRollout(path, slot, log); err != nil {
		t.Fatal(err)
	}
	p, err := pipe.New(pipe.Config{Group: "signalmand", NormalizeWorkers: 2, MatchWorkers: 2, QueueSize: 16, MaxInflightBatches: 2},
		mem, pipe.NewNormalizer(tax, pipe.NormalizeConfig{}, m), slot, m, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- p.Run(ctx) }()
	go watchRollout(ctx, path, defaultRolloutPoll, slot, log)

	// Steady load: every record matches the dump rule, which is served by
	// v2 at 100% (bucket 95) and by v1 at 0%.
	go func() {
		body := `{"Channel":"Microsoft-Windows-Sysmon/Operational","event_id":1,` +
			`"Image":"C:\\Windows\\System32\\rundll32.exe","CommandLine":"rundll32.exe comsvcs.dll, MiniDump 1 x full","event_time":1790000000000}`
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for i := 0; ; i++ {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			_ = mem.Produce(ctx, []broker.Record{{Topic: pipe.TopicEventsRaw, Partition: broker.AnyPartition,
				Key: fmt.Appendf(nil, "host-%d", i%5), Value: []byte(body),
				Headers: []broker.Header{{Key: pipe.HeaderSource, Value: []byte("sysmon")}}}})
		}
	}()

	// Alerts in topic order. The dump rule's alerts are keyed by its id,
	// so they share one partition and its order is production order.
	engines := func() []string {
		end, err := mem.EndOffsets(ctx, pipe.TopicAlerts)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for part, n := range end {
			if n == 0 {
				continue
			}
			c, err := mem.ReadFrom(map[broker.TopicPartition]int64{{Topic: pipe.TopicAlerts, Partition: part}: 0})
			if err != nil {
				t.Fatal(err)
			}
			for got := int64(0); got < n; {
				f, err := c.Poll(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range f.Records {
					if r.Offset >= n {
						continue
					}
					got++
					var a pipe.Alert
					if err := json.Unmarshal(r.Value, &a); err != nil {
						t.Fatal(err)
					}
					out = append(out, a.Engine)
				}
			}
			c.Close()
		}
		return out
	}
	waitFor := func(what string, limit time.Duration, cond func([]string) bool) time.Duration {
		t.Helper()
		start := time.Now()
		for {
			if cond(engines()) {
				return time.Since(start)
			}
			select {
			case err := <-errc:
				t.Fatalf("pipeline stopped while waiting for %s: %v", what, err)
			default:
			}
			if time.Since(start) > limit {
				t.Fatalf("%s did not happen within %s", what, limit)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor("alerts served by v2", 10*time.Second, func(es []string) bool { return len(es) > 20 })
	if es := engines(); slices.Contains(es, "v1") {
		t.Fatal("at 100% the dump rule is served by v2 only")
	}

	writeFile(t, path, "0\n")
	took := waitFor("the rollback", 30*time.Second, func(es []string) bool { return slices.Contains(es, "v1") })
	t.Logf("rollback took effect %s after the rollout file changed (poll interval %s)", took.Round(time.Millisecond), defaultRolloutPoll)
	if took >= 30*time.Second {
		t.Fatalf("rollback took %s", took)
	}
	// Let more batches through, then check nothing went back to v2.
	settled := len(engines())
	waitFor("batches after the rollback", 10*time.Second, func(es []string) bool { return len(es) > settled+20 })
	es := engines()
	firstV1 := slices.Index(es, "v1")
	for i, e := range es[firstV1:] {
		if e != "v1" {
			t.Fatalf("alert %d after the rollback came from %s", firstV1+i, e)
		}
	}
	if slot.Rollout() != 0 || testutil.ToFloat64(m.RolloutPercent) != 0 {
		t.Fatalf("rollout %d after the rollback", slot.Rollout())
	}
	cancel()
	<-errc
}
