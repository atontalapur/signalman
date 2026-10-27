package cutover

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/atontalapur/signalman/internal/engine/v1"
	v2 "github.com/atontalapur/signalman/internal/engine/v2"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/verdict"
)

// PartitionDigest is one partition's verdict digest from each engine.
type PartitionDigest struct {
	Partition  int32  `json:"partition"`
	V1         string `json:"v1"`
	V2         string `json:"v2"`
	V1Verdicts uint64 `json:"v1_verdicts"`
	V2Verdicts uint64 `json:"v2_verdicts"`
}

// Equal reports whether the two engines agree on the partition: the same
// digest over the same number of verdicts.
func (p PartitionDigest) Equal() bool { return p.V1 == p.V2 && p.V1Verdicts == p.V2Verdicts }

// Replay is a corpus replay through both engines.
type Replay struct {
	Events     int               `json:"events"`
	Rules      int               `json:"rules"`
	RuleSetV   string            `json:"ruleset_v"`
	Partitions []PartitionDigest `json:"partitions"`
}

// Mismatched is the partitions the engines disagree on.
func (r Replay) Mismatched() []PartitionDigest {
	var out []PartitionDigest
	for _, p := range r.Partitions {
		if !p.Equal() {
			out = append(out, p)
		}
	}
	return out
}

// ReplayCorpus evaluates every event with v1 and v2 under rs and digests
// each engine's verdicts per partition (spec phase 08, corpus replay). The
// corpus is one ordered stream; event i goes to partition i mod partitions,
// so each partition is a stream in seq order like a topic partition is.
// The events are modified: Partition is set.
func ReplayCorpus(rs *sigma.RuleSet, evs []*event.Event, partitions int) (Replay, error) {
	if partitions <= 0 {
		return Replay{}, fmt.Errorf("partitions %d, want at least one", partitions)
	}
	if len(evs) == 0 {
		return Replay{}, errors.New("no events to replay")
	}
	e1, e2 := v1.New(rs), v2.New(rs)
	d1, d2 := verdict.NewSet(), verdict.NewSet()
	var buf []event.Verdict
	for i, ev := range evs {
		ev.Partition = int32(i % partitions)
		for _, eng := range []struct {
			eval func([]event.Verdict, *event.Event) []event.Verdict
			set  *verdict.Set
		}{{e1.EvaluateInto, d1}, {e2.EvaluateInto, d2}} {
			buf = eng.eval(buf[:0], ev)
			for _, v := range buf {
				if err := eng.set.Fold(v); err != nil {
					return Replay{}, err
				}
			}
		}
	}
	r := Replay{Events: len(evs), Rules: len(rs.Rules), RuleSetV: rs.Version}
	for _, p := range d1.Partitions() {
		a, _ := d1.Digest(p)
		pd := PartitionDigest{Partition: p, V1: a.Sum(), V1Verdicts: a.Verdicts()}
		if b, ok := d2.Digest(p); ok {
			pd.V2, pd.V2Verdicts = b.Sum(), b.Verdicts()
		}
		r.Partitions = append(r.Partitions, pd)
	}
	for _, p := range d2.Partitions() {
		if _, ok := d1.Digest(p); !ok {
			b, _ := d2.Digest(p)
			r.Partitions = append(r.Partitions, PartitionDigest{Partition: p, V2: b.Sum(), V2Verdicts: b.Verdicts()})
		}
	}
	return r, nil
}

// FuzzStats is the differential fuzzer's counters summed over its workers,
// as scripts/fuzz_stats.py sums them.
type FuzzStats struct {
	Workers        int   `json:"workers"`
	Compared       int64 `json:"compared"`
	RejectedByBoth int64 `json:"rejected_by_both"`
	Suppressed     int64 `json:"suppressed"`
	OracleTimeout  int64 `json:"oracle_timeout"`
	Skipped        int64 `json:"skipped"`
}

// ReadFuzzStats sums the per-worker JSON files a `make fuzz-differential`
// run leaves in dir. A file that does not parse fails the read rather than
// being summed around.
func ReadFuzzStats(dir string) (FuzzStats, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return FuzzStats{}, err
	}
	if len(files) == 0 {
		return FuzzStats{}, fmt.Errorf("no worker stats in %s", dir)
	}
	var s FuzzStats
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return FuzzStats{}, err
		}
		var c FuzzStats
		if err := json.Unmarshal(b, &c); err != nil {
			return FuzzStats{}, fmt.Errorf("unreadable worker stats %s: %w", filepath.Base(f), err)
		}
		s.Workers++
		s.Compared += c.Compared
		s.RejectedByBoth += c.RejectedByBoth
		s.Suppressed += c.Suppressed
		s.OracleTimeout += c.OracleTimeout
		s.Skipped += c.Skipped
	}
	return s, nil
}

func digestSummary(r Replay) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d events, %d rules (ruleset %s), %d partitions", r.Events, r.Rules, short(r.RuleSetV), len(r.Partitions))
	for _, p := range r.Partitions {
		mark := "match"
		if !p.Equal() {
			mark = "MISMATCH"
		}
		fmt.Fprintf(&b, "; p%d v1 %s/%d v2 %s/%d %s", p.Partition, p.V1, p.V1Verdicts, p.V2, p.V2Verdicts, mark)
	}
	return b.String()
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
