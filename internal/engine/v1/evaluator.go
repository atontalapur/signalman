// Package v1 is the reference evaluator: the permanent oracle every later
// engine is compared against.
//
// It is written to be obviously correct when read, not to be fast. There is
// no index, no prefilter, no cache, and no reordering. Every enabled rule is
// walked for every event, in rule id order, with the same tree walker the
// rule loader produced. When v2 and v1 disagree, the argument that v1 is
// right has to be short enough to hold in one reading, and every
// optimization shortens that argument.
//
// Speed belongs to v2. This file is never optimized by rule.
package v1

import (
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/sigma/ast"
)

// Name is the engine identity stamped on every verdict. The differ groups on
// it, so it is part of the data contract, not a log string.
const Name = "v1"

// Evaluator holds the rule set. It is read-only after construction: two
// engines share one event in the shadow lane, so evaluation may not write to
// the rule set, the event, or the evaluator.
type Evaluator struct {
	rs *sigma.RuleSet
}

func New(rs *sigma.RuleSet) *Evaluator { return &Evaluator{rs: rs} }

// RuleSet returns the rule set being evaluated, so a caller can report the
// versions a verdict stream was produced under.
func (e *Evaluator) RuleSet() *sigma.RuleSet { return e.rs }

// Evaluate returns exactly one verdict per rule, in rule id order.
//
// A rule whose logsource does not cover the event yields an explicit false
// verdict. That is the invariant: "did not match" and "was never evaluated"
// have to stay distinguishable, because a detection that silently never ran
// is the failure mode this whole pipeline exists to rule out.
func (e *Evaluator) Evaluate(ev *event.Event) []event.Verdict {
	return e.EvaluateInto(make([]event.Verdict, 0, len(e.rs.Rules)), ev)
}

// EvaluateInto appends the verdicts to dst and returns it. The pipeline
// evaluates millions of events and hands the same buffer back each time;
// pass dst[:0] to reuse it.
func (e *Evaluator) EvaluateInto(dst []event.Verdict, ev *event.Event) []event.Verdict {
	for i := range e.rs.Rules {
		r := &e.rs.Rules[i]
		matched := false
		if r.LogSource.Matches(ev) {
			matched = ast.Eval(r.Cond, ev)
		}
		dst = append(dst, event.Verdict{
			Seq:       ev.Seq,
			Partition: ev.Partition,
			RuleID:    r.ID,
			Matched:   matched,
			Engine:    Name,
			RuleSetV:  e.rs.Version,
			TaxonomyV: e.rs.TaxonomyV,
		})
	}
	return dst
}
