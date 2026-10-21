// Package differ compares the v1 and v2 verdict streams in shadow mode. It
// joins verdicts.v1 and verdicts.v2 on (partition, seq, rule_id) and
// classifies every disagreement into the spec's five classes (phase 08).
//
// The comparison is a function of the two streams alone: no wall clock,
// no arrival order between the topics, no map iteration order. Run it twice
// over the same topics and it writes the same divergence records in the
// same order on every partition.
package differ

import (
	"log/slog"
	"slices"

	"github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/engine/v2"
	"github.com/atontalapur/signalman/internal/pipe"
)

// TopicDivergences is where divergence records go, one per (partition,
// seq, rule_id) the engines disagree on, pinned to the event's partition.
const TopicDivergences = "divergences"

// Class is a divergence class from the spec's table.
type Class string

const (
	// ClassFalseNegative: v1 matched, v2 did not. A missed detection;
	// budget zero, halts the cutover.
	ClassFalseNegative Class = "v2_false_negative"
	// ClassFalsePositive: v2 matched, v1 did not. Noise the SOC would
	// absorb; budget zero, halts the cutover.
	ClassFalsePositive Class = "v2_false_positive"
	// ClassMissing: one engine has no verdict for the rule under the same
	// RuleSetV, or no record at all for an event it owed one for. Violates
	// invariant 1; budget zero, halts the cutover.
	ClassMissing Class = "missing_verdict"
	// ClassVersionSkew: a disagreement, or a rule only one side has, when
	// the two records carry different RuleSetV. Recorded and excluded from
	// the count. Non-empty at steady state means a reload is not atomic.
	ClassVersionSkew Class = "version_skew"
	// ClassOrdering is in the spec's table with budget "n/a": the join is
	// on Seq, so arrival order cannot produce a divergence. The differ never
	// emits it; TestDifferOutputDoesNotDependOnArrivalOrder holds it there.
	ClassOrdering Class = "ordering"
)

// Classes is every class, in the spec's order.
var Classes = []Class{ClassFalseNegative, ClassFalsePositive, ClassMissing, ClassVersionSkew, ClassOrdering}

// Counted reports whether the class is one of the three zero-budget
// classes that halt the cutover.
func (c Class) Counted() bool {
	return c == ClassFalseNegative || c == ClassFalsePositive || c == ClassMissing
}

// Side is one engine's verdict for the rule.
type Side struct {
	Matched   bool   `json:"matched"`
	RuleSetV  string `json:"ruleset_v"`
	TaxonomyV string `json:"taxonomy_v"`
}

// Divergence is one disagreement. Partition and Seq name the event: Seq is
// its offset in that events.raw partition, so the raw record is one fetch
// away. V1 or V2 is nil when that engine has no verdict, and Missing then
// names it.
type Divergence struct {
	Partition int32  `json:"partition"`
	Seq       uint64 `json:"seq"`
	RuleID    string `json:"rule_id"`
	Class     Class  `json:"class"`
	Excluded  bool   `json:"excluded"`
	Missing   string `json:"missing,omitempty"`
	V1        *Side  `json:"v1"`
	V2        *Side  `json:"v2"`
}

// LogAttrs is the divergence as structured log fields, for the divergence
// log in docs/cutover.md.
func (d Divergence) LogAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("class", string(d.Class)),
		slog.Bool("excluded", d.Excluded),
		slog.Int("partition", int(d.Partition)),
		slog.Uint64("seq", d.Seq),
		slog.String("rule_id", d.RuleID),
	}
	if d.Missing != "" {
		attrs = append(attrs, slog.String("missing", d.Missing))
	}
	for _, s := range []struct {
		name string
		v    *Side
	}{{v1.Name, d.V1}, {v2.Name, d.V2}} {
		if s.v != nil {
			attrs = append(attrs,
				slog.Bool(s.name+"_matched", s.v.Matched),
				slog.String(s.name+"_ruleset_v", s.v.RuleSetV),
				slog.String(s.name+"_taxonomy_v", s.v.TaxonomyV))
		}
	}
	return attrs
}

// Compare classifies every disagreement between v1's and v2's records for
// one event, in rule id order. Either record may be nil, meaning that
// engine wrote none; both nil is nothing to compare.
//
// Version skew is decided by RuleSetV alone. RuleSetV already hashes the
// taxonomy, so two records under one RuleSetV and different TaxonomyV are
// not a reload in progress; they are a broken data contract, and their
// disagreements count in the class they would have anyway.
func Compare(r1, r2 *pipe.EventVerdicts) []Divergence {
	var out []Divergence
	skew := r1 != nil && r2 != nil && r1.RuleSetV != r2.RuleSetV
	add := func(id string, a, b *pipe.RuleVerdict) {
		d := Divergence{RuleID: id}
		if r1 != nil {
			d.Partition, d.Seq = r1.Partition, r1.Seq
		} else {
			d.Partition, d.Seq = r2.Partition, r2.Seq
		}
		if a != nil {
			d.V1 = &Side{Matched: a.Matched, RuleSetV: r1.RuleSetV, TaxonomyV: r1.TaxonomyV}
		}
		if b != nil {
			d.V2 = &Side{Matched: b.Matched, RuleSetV: r2.RuleSetV, TaxonomyV: r2.TaxonomyV}
		}
		switch {
		case a != nil && b != nil && a.Matched == b.Matched:
			return
		case skew:
			d.Class, d.Excluded = ClassVersionSkew, true
		case a == nil || b == nil:
			d.Class = ClassMissing
		case a.Matched:
			d.Class = ClassFalseNegative
		default:
			d.Class = ClassFalsePositive
		}
		if a == nil {
			d.Missing = v1.Name
		} else if b == nil {
			d.Missing = v2.Name
		}
		out = append(out, d)
	}

	// Both engines write rules in rule set order, which is rule id order,
	// so the common case is a positional walk with no map.
	if r1 != nil && r2 != nil && sameRules(r1.Verdicts, r2.Verdicts) {
		for i := range r1.Verdicts {
			add(r1.Verdicts[i].RuleID, &r1.Verdicts[i], &r2.Verdicts[i])
		}
		return out
	}
	byID := func(r *pipe.EventVerdicts) map[string]*pipe.RuleVerdict {
		m := map[string]*pipe.RuleVerdict{}
		if r != nil {
			for i := range r.Verdicts {
				m[r.Verdicts[i].RuleID] = &r.Verdicts[i]
			}
		}
		return m
	}
	m1, m2 := byID(r1), byID(r2)
	ids := make([]string, 0, max(len(m1), len(m2)))
	for id := range m1 {
		ids = append(ids, id)
	}
	for id := range m2 {
		if m1[id] == nil {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		add(id, m1[id], m2[id])
	}
	return out
}

// sameRules reports whether a and b name the same rules in the same order,
// in strictly increasing id order, so a positional walk is a join on id
// and its output is already sorted.
func sameRules(a, b []pipe.RuleVerdict) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].RuleID != b[i].RuleID || (i > 0 && a[i-1].RuleID >= a[i].RuleID) {
			return false
		}
	}
	return true
}
