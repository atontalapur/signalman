// Package v2 is the compiled engine. It produces the same verdicts as v1,
// the permanent oracle, and is proven to by digest comparison; everything
// here exists to make that same answer cheaper.
//
// A verdict is still a pure function of (Event, RuleSetV, TaxonomyV). The
// compiled structures are built in rule set order, which is rule id order,
// and nothing in evaluation iterates a map in an order that can reach a
// verdict.
package v2

import (
	"fmt"
	"sync"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

// Name is the engine identity stamped on every verdict. The differ groups
// on it.
const Name = "v2"

// Evaluator holds a compiled program. Like v1 it is safe for concurrent use
// and evaluation writes nothing it shares: per-event state is a scratch
// taken from a pool for the length of one call.
type Evaluator struct {
	rs   *sigma.RuleSet
	prog *Program
	pool sync.Pool
}

// New compiles rs. It panics on a tree the loader did not bind, the same
// programming error ast.Eval panics on in v1; Compile returns it instead.
func New(rs *sigma.RuleSet) *Evaluator {
	p, err := Compile(rs)
	if err != nil {
		panic(fmt.Sprintf("v2.New: %v", err))
	}
	e := &Evaluator{rs: rs, prog: p}
	e.pool.New = func() any { return newScratch(p) }
	return e
}

// RuleSet returns the rule set being evaluated.
func (e *Evaluator) RuleSet() *sigma.RuleSet { return e.rs }

// Program returns the compiled program, for reporting its shape.
func (e *Evaluator) Program() *Program { return e.prog }

// Evaluate returns exactly one verdict per rule, in rule id order.
func (e *Evaluator) Evaluate(ev *event.Event) []event.Verdict {
	return e.EvaluateInto(make([]event.Verdict, 0, len(e.rs.Rules)), ev)
}

// EvaluateInto appends the verdicts to dst and returns it. Every rule gets a
// verdict: a rule the compiled program never walks for this event still
// emits an explicit false.
func (e *Evaluator) EvaluateInto(dst []event.Verdict, ev *event.Event) []event.Verdict {
	s := e.pool.Get().(*scratch)
	s.reset(ev)
	for i := range e.prog.Trees {
		dst = append(dst, event.Verdict{
			Seq:       ev.Seq,
			Partition: ev.Partition,
			RuleID:    e.prog.Trees[i].RuleID,
			Matched:   s.eval(e.prog.Trees[i].Root),
			Engine:    Name,
			RuleSetV:  e.rs.Version,
			TaxonomyV: e.rs.TaxonomyV,
		})
	}
	s.ev = nil
	e.pool.Put(s)
	return dst
}

// scratch is one event's working state. done and val are the predicate
// bitset: bit i of done says predicate i has been evaluated for this event,
// and bit i of val holds its result.
type scratch struct {
	p    *Program
	ev   *event.Event
	done []uint64
	val  []uint64
}

func newScratch(p *Program) *scratch {
	w := (len(p.Preds) + 63) / 64
	return &scratch{p: p, done: make([]uint64, w), val: make([]uint64, w)}
}

func (s *scratch) reset(ev *event.Event) {
	s.ev = ev
	clear(s.done)
	clear(s.val)
}

// pred reads predicate i from the bitset, evaluating it on first use.
// Laziness cannot change a result: matchers have no side effects, so an
// unevaluated predicate is one no tree needed.
func (s *scratch) pred(i int32) bool {
	w, bit := i>>6, uint64(1)<<(uint(i)&63)
	if s.done[w]&bit != 0 {
		return s.val[w]&bit != 0
	}
	p := s.p.Preds[i].src
	r := p.M.Match(s.ev.Field(p.Field), s.ev)
	s.done[w] |= bit
	if r {
		s.val[w] |= bit
	}
	return r
}

func (s *scratch) eval(n int32) bool {
	nd := s.p.nodes[n]
	switch nd.op {
	case opPred:
		return s.pred(nd.a)
	case opAnd:
		for _, k := range s.p.kids[nd.a:nd.b] {
			if !s.eval(k) {
				return false
			}
		}
		return true
	case opOr:
		for _, k := range s.p.kids[nd.a:nd.b] {
			if s.eval(k) {
				return true
			}
		}
		return false
	default: // opNot
		return !s.eval(nd.a)
	}
}
