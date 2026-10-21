package differ

import (
	"bytes"
	"context"
	"testing"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// unshadowed is a v1 record written with no shadow beside it.
func unshadowed(part int32, seq uint64, matched ...bool) broker.Record {
	r := verdicts("v1", part, seq, "R", matched...)
	r.Value = bytes.Replace(r.Value, []byte(`,"shadow":"v2"`), nil, 1)
	return r
}

// committedAt waits until the differ has committed exactly next on topic
// partition 0.
func (r *running) committedAt(t *testing.T, mem *broker.Memory, group, topic string, next int64) {
	t.Helper()
	r.waitFor(t, topic+" committed", func() bool {
		c, _ := mem.CommittedOffsets(context.Background(), group, topic)
		return c[0] == next
	})
}

func TestDifferRestartAcrossARedeliveredRunReportsNothing(t *testing.T) {
	mem := newMemory()
	// Seqs 0 to 2 on both sides, then a redelivered batch from seq 1 that
	// v1 has started to write and v2 has not.
	for seq := uint64(0); seq < 3; seq++ {
		produce(t, mem, verdicts("v1", 0, seq, "R", false), verdicts("v2", 0, seq, "R", false))
	}
	produce(t, mem, verdicts("v1", 0, 1, "R", false))
	cfg := testConfig()
	r := start(t, mem, cfg)
	r.committedAt(t, mem, cfg.Group, pipe.TopicVerdictsV1, 4)
	r.committedAt(t, mem, cfg.Group, pipe.TopicVerdictsV2, 3)
	r.stop(t)

	// The rest of the redelivered batch, then one new event.
	produce(t, mem, verdicts("v1", 0, 2, "R", false), verdicts("v1", 0, 3, "R", false))
	produce(t, mem, verdicts("v2", 0, 1, "R", false), verdicts("v2", 0, 2, "R", false), verdicts("v2", 0, 3, "R", false))
	again := start(t, mem, cfg)
	again.committedAt(t, mem, cfg.Group, pipe.TopicVerdictsV1, 6)
	again.committedAt(t, mem, cfg.Group, pipe.TopicVerdictsV2, 6)
	again.stop(t)
	if ds := divergences(t, mem); len(ds) != 0 {
		t.Fatalf("a restart inside a redelivered run reported %+v", ds)
	}
}

func TestShadowedRedeliveryOfAnUnshadowedEventIsCompared(t *testing.T) {
	mem := newMemory()
	// signalmand ran without -shadow for seqs 0 and 1, then restarted with
	// it and redelivered them; v2 disagrees on seq 1.
	produce(t, mem, unshadowed(0, 0, false), unshadowed(0, 1, false))
	for seq := uint64(0); seq < 3; seq++ {
		produce(t, mem, verdicts("v1", 0, seq, "R", false), verdicts("v2", 0, seq, "R", seq == 1))
	}
	r := start(t, mem, testConfig())
	r.waitFor(t, "every shadowed event joined", func() bool { return r.joined() == 3 })
	r.stop(t)
	ds := divergences(t, mem)
	if len(ds) != 1 || ds[0].Seq != 1 || ds[0].Class != ClassFalsePositive {
		t.Fatalf("divergences %+v; the shadowed copies are compared, not passed over as repeats", ds)
	}
}

func TestV2RecordForAnEventV1WroteUnshadowedIsNotCounted(t *testing.T) {
	mem := newMemory()
	// v2's record for seq 1 landed, v1's did not, and signalmand came back
	// without -shadow and wrote seqs 1 and 2 unshadowed.
	produce(t, mem, verdicts("v1", 0, 0, "R", false), verdicts("v2", 0, 0, "R", false))
	produce(t, mem, verdicts("v2", 0, 1, "R", false))
	produce(t, mem, unshadowed(0, 1, false), unshadowed(0, 2, false))
	produce(t, mem, verdicts("v1", 0, 3, "R", false), verdicts("v2", 0, 3, "R", false))
	r := start(t, mem, testConfig())
	r.waitFor(t, "every event resolved", func() bool { return r.joined() == 3 })
	r.stop(t)
	if ds := divergences(t, mem); len(ds) != 0 {
		t.Fatalf("v1 has a verdict for seq 1, so v2's is not orphaned: %+v", ds)
	}
	if got := testutil.ToFloat64(r.m.Counted); got != 0 {
		t.Fatalf("counted %v", got)
	}
}

func TestShadowedHeadWhoseV2NeverArrivesIsReportedOnceV1MovesOnUnshadowed(t *testing.T) {
	mem := newMemory()
	// The shadow failed on seq 1, then signalmand restarted without
	// -shadow: no v2 record will ever be written for it.
	produce(t, mem, verdicts("v1", 0, 0, "R", false), verdicts("v2", 0, 0, "R", false))
	produce(t, mem, verdicts("v1", 0, 1, "R", true))
	produce(t, mem, unshadowed(0, 2, false), unshadowed(0, 3, false))
	cfg := testConfig()
	r := start(t, mem, cfg)
	r.committedAt(t, mem, cfg.Group, pipe.TopicVerdictsV1, 4)
	r.stop(t)
	ds := divergences(t, mem)
	if len(ds) != 1 || ds[0].Seq != 1 || ds[0].Class != ClassMissing || ds[0].Missing != "v2" {
		t.Fatalf("divergences %+v", ds)
	}
}

func TestShadowedHeadWaitsWhileItsV2IsStillUnread(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(1))
	produce(t, mem, verdicts("v1", 0, 0, "R", false))
	produce(t, mem, unshadowed(0, 1, false))
	// v2's record for seq 0 is durable before v1 moved on, as the pipeline
	// writes them; the differ must find it rather than report it missing.
	produce(t, mem, verdicts("v2", 0, 0, "R", false))
	r := start(t, mem, testConfig())
	r.waitFor(t, "both events resolved", func() bool { return r.joined() == 1 })
	r.committedAt(t, mem, "differ", pipe.TopicVerdictsV1, 2)
	r.stop(t)
	if ds := divergences(t, mem); len(ds) != 0 {
		t.Fatalf("divergences %+v", ds)
	}
}
