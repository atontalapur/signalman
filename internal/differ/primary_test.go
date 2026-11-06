package differ

import (
	"bytes"
	"context"
	"testing"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/prometheus/client_golang/prometheus"
)

// v2Primary turns a record from verdicts() into one written with v2
// serving: the v2 record names v1 as its shadow and the v1 record names
// nothing.
func v2Primary(r broker.Record) broker.Record {
	if r.Topic == pipe.TopicVerdictsV1 {
		r.Value = bytes.Replace(r.Value, []byte(`,"shadow":"v2"`), nil, 1)
		return r
	}
	r.Value = bytes.Replace(r.Value, []byte(`"engine":"v2"`), []byte(`"engine":"v2","shadow":"v1"`), 1)
	return r
}

func TestV2PrimaryDriftsAreClassifiedTheSameWay(t *testing.T) {
	mem := newMemory()
	// seq 0: v1 has no record (the oracle failed); seq 1: agree;
	// seq 2: v2 misses rule-0; seq 3: v2 matches rule-1 that v1 does not.
	produce(t, mem,
		v2Primary(verdicts("v2", 0, 0, "R", false)),
		v2Primary(verdicts("v2", 0, 1, "R", true)), v2Primary(verdicts("v1", 0, 1, "R", true)),
		v2Primary(verdicts("v2", 0, 2, "R", false, false)), v2Primary(verdicts("v1", 0, 2, "R", true, false)),
		v2Primary(verdicts("v2", 0, 3, "R", false, true)), v2Primary(verdicts("v1", 0, 3, "R", false, false)),
	)
	cfg := testConfig()
	cfg.Primary = "v2"
	r := start(t, mem, cfg)
	r.waitFor(t, "four seqs resolved", func() bool { return r.joined() == 4 })
	r.stop(t)
	got := map[uint64]Divergence{}
	for _, d := range divergences(t, mem) {
		got[d.Seq] = d
	}
	if len(got) != 3 {
		t.Fatalf("divergences %+v", got)
	}
	if d := got[0]; d.Class != ClassMissing || d.Missing != "v1" {
		t.Errorf("seq 0: %+v, want v1 missing", d)
	}
	if d := got[2]; d.Class != ClassFalseNegative || d.RuleID != "rule-0" {
		t.Errorf("seq 2: %+v", d)
	}
	if d := got[3]; d.Class != ClassFalsePositive || d.RuleID != "rule-1" {
		t.Errorf("seq 3: %+v", d)
	}
}

// With v2 primary, a v2 record with no shadow owes nothing, and the v1
// side is read only to answer the v2 side.
func TestV2PrimaryUnshadowedRecordsOweNothing(t *testing.T) {
	mem := newMemory()
	for seq := uint64(0); seq < 10; seq++ {
		r := verdicts("v2", 0, seq, "R", true)
		produce(t, mem, r)
	}
	cfg := testConfig()
	cfg.Primary = "v2"
	r := start(t, mem, cfg)
	r.waitFor(t, "the unshadowed v2 records consumed", func() bool {
		c, _ := mem.CommittedOffsets(context.Background(), cfg.Group, pipe.TopicVerdictsV2)
		return c[0] == 10
	})
	r.stop(t)
	if d := divergences(t, mem); len(d) != 0 {
		t.Fatalf("an unshadowed v2 record owes no v1 record: %+v", d[0])
	}
}

// The v1-primary differ on a v2-primary stream would read every v1 record
// as owing nothing and never compare: the primary has to be named.
func TestPrimaryMustBeAnEngine(t *testing.T) {
	for _, p := range []string{"v3", "V2", "both"} {
		if _, err := New(Config{Primary: p}, newMemory(), NewMetrics(prometheus.NewRegistry()), nil); err == nil {
			t.Errorf("primary %q accepted", p)
		}
	}
	d, err := New(Config{}, newMemory(), NewMetrics(prometheus.NewRegistry()), nil)
	if err != nil || d.cfg.Primary != "v1" {
		t.Fatalf("default primary %q, %v", d.cfg.Primary, err)
	}
}
