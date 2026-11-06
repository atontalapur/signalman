//go:build integration

package pipe

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker/kafka"
)

// TestPipelineOverRedpanda runs the pipeline and the audit against the
// compose stack. It uses the real topic names with a fresh consumer group,
// so it reprocesses whatever earlier runs left in events.raw.
func TestPipelineOverRedpanda(t *testing.T) {
	addr := os.Getenv("SIGNALMAN_BROKERS")
	if addr == "" {
		addr = "localhost:19092"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	b, err := kafka.Dial(ctx, kafka.Config{Brokers: strings.Split(addr, ","), ClientID: "signalman-it", MaxPollRecords: 100})
	if err != nil {
		t.Fatalf("redpanda not reachable at %s: %v", addr, err)
	}
	defer b.Close()
	var specs []kafka.TopicSpec
	for _, name := range []string{TopicEventsRaw, TopicEventsNorm, TopicVerdictsV1, TopicAlerts, TopicDrops} {
		specs = append(specs, kafka.TopicSpec{Name: name, Partitions: 8, Replication: 1})
	}
	if err := b.EnsureTopics(ctx, specs); err != nil {
		t.Fatal(err)
	}

	r := newRig(t, b, nil)
	slot := NewSlot(V1(r.rs), r.m)
	cfg := testConfig()
	cfg.Group = fmt.Sprintf("signalmand-it-%d", time.Now().UnixNano())
	a, err := NewAuditor(ctx, b, AuditConfig{Group: cfg.Group, Window: 1000}, slot.RuleCount, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	produceRaw(t, b, 0, 500)

	p, err := New(cfg, b, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(ctx)
	errc := make(chan error, 1)
	go func() { errc <- p.Run(runCtx) }()
	for {
		end, err := b.EndOffsets(ctx, TopicEventsRaw)
		if err != nil {
			t.Fatal(err)
		}
		c, err := b.CommittedOffsets(ctx, cfg.Group, TopicEventsRaw)
		if err != nil {
			t.Fatal(err)
		}
		done := true
		for part, e := range end {
			if c[part] < e {
				done = false
			}
		}
		if done {
			break
		}
		select {
		case err := <-errc:
			t.Fatalf("pipeline stopped: %v", err)
		case <-ctx.Done():
			t.Fatal("timed out")
		case <-time.After(100 * time.Millisecond):
		}
	}
	stop()
	<-errc
	reports, err := a.Step(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ingested int64
	for _, w := range reports {
		ingested += w.Ingested
	}
	if ingested < 500 {
		t.Fatalf("audited %d events, produced at least 500", ingested)
	}
}
