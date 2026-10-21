// Package v2 is the compiled engine. It produces the same verdicts as v1,
// the permanent oracle, and is proven to by digest comparison; everything
// here exists to make that same answer cheaper.
//
// A verdict is still a pure function of (Event, RuleSetV, TaxonomyV). The
// compiled structures are built in rule set order, which is rule id order.
// The one place evaluation ranges over a map is the event's own fields,
// and there it only sets bits and fills a per-field cache, both of which
// come out the same in any order.
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
// taken from a pool for the length of one call. Once the pool holds a
// scratch grown to fit the traffic, EvaluateInto allocates nothing.
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

// EvaluateInto appends the verdicts to dst and returns it; pass dst[:0] to
// reuse a buffer. Every rule gets a verdict. A rule settled by presence
// gating or the prefilter is never walked, and its verdict is an explicit
// false: both tests are necessary conditions for a match, checked against
// v1 by gate_test.go and prefilter_test.go.
func (e *Evaluator) EvaluateInto(dst []event.Verdict, ev *event.Event) []event.Verdict {
	s := e.pool.Get().(*scratch)
	s.reset(ev)
	s.load()
	for i := range e.prog.Trees {
		matched := s.gateOK(i) && s.candidate(i) && s.eval(e.prog.Trees[i].Root)
		dst = append(dst, event.Verdict{
			Seq:       ev.Seq,
			Partition: ev.Partition,
			RuleID:    e.prog.Trees[i].RuleID,
			Matched:   matched,
			Engine:    Name,
			RuleSetV:  e.rs.Version,
			TaxonomyV: e.rs.TaxonomyV,
		})
	}
	s.ev = nil
	e.pool.Put(s)
	return dst
}

// scratch is one event's working state, reused across events.
//
//   - done and val are the predicate bitset: bit i of done says predicate
//     i has been evaluated for this event, bit i of val holds its result.
//   - present is the field presence bitset over Program.fields.
//   - cand is the prefilter's candidate bitset over rules.
//   - seen, vals, spanLo, and spanHi are the per-field cache: the event's
//     value for each program field, and its scalars folded into text.
//   - epoch stamps seen and the literal stamps, so neither is cleared per
//     event.
type scratch struct {
	p  *Program
	ev *event.Event

	done, val []uint64
	present   []uint64
	cand      []uint64

	epoch          uint32
	seen           []uint32
	vals           []event.Value
	spanLo, spanHi []int32
	spans          []span
	text           []byte

	hits     []int32
	litEpoch []uint32
	litField []int32
	tmp, num []byte
}

func newScratch(p *Program) *scratch {
	w := (len(p.Preds) + 63) / 64
	nf := len(p.fields)
	return &scratch{
		p:        p,
		done:     make([]uint64, w),
		val:      make([]uint64, w),
		present:  make([]uint64, p.fieldWords),
		cand:     make([]uint64, (len(p.Trees)+63)/64),
		seen:     make([]uint32, nf),
		vals:     make([]event.Value, nf),
		spanLo:   make([]int32, nf),
		spanHi:   make([]int32, nf),
		litEpoch: make([]uint32, len(p.lits)),
		litField: make([]int32, len(p.lits)),
	}
}

func (s *scratch) reset(ev *event.Event) {
	s.ev = ev
	clear(s.done)
	clear(s.val)
	clear(s.present)
	s.spans = s.spans[:0]
	s.text = s.text[:0]
	if s.epoch == ^uint32(0) {
		// Four billion events on one scratch: start the stamps over rather
		// than let a wrapped epoch read as this event's.
		clear(s.seen)
		clear(s.litEpoch)
		s.epoch = 0
	}
	s.epoch++
}

// load makes the one pass over the event's fields: it caches each program
// field's value and folded text, sets the presence bitset, and runs the
// folded text through the prefilter. The map is ranged in its own order;
// every effect here is a bit set or a per-field slot written once, so the
// order cannot reach a verdict.
func (s *scratch) load() {
	pf := s.p.pf
	copy(s.cand, pf.always)
	for name, v := range s.ev.Fields {
		fi, ok := s.p.fieldIdx[name]
		if !ok {
			// No predicate names this field. Only a keyword literal can
			// be found in it.
			if pf.filter != nil && pf.keyword {
				s.scanLoose(v)
			}
			continue
		}
		s.seen[fi] = s.epoch
		s.vals[fi] = v
		if v.Kind != event.KindNull {
			s.present[fi>>6] |= 1 << (uint(fi) & 63)
		}
		lo := int32(len(s.spans))
		if v.Kind == event.KindList {
			for _, item := range v.L {
				s.foldSpan(item)
			}
		} else {
			s.foldSpan(v)
		}
		hi := int32(len(s.spans))
		s.spanLo[fi], s.spanHi[fi] = lo, hi
		if pf.filter != nil {
			for _, sp := range s.spans[lo:hi] {
				s.scanSpan(fi, s.text[sp.off:sp.end])
			}
		}
	}
}

// foldSpan appends one scalar's folded text to the arena. A null or nested
// list has no text and gets no span.
func (s *scratch) foldSpan(v event.Value) {
	off := int32(len(s.text))
	var ok bool
	s.text, ok = appendFoldedText(s.text, v)
	if ok {
		s.spans = append(s.spans, span{off: off, end: int32(len(s.text))})
	}
}

func (s *scratch) scanLoose(v event.Value) {
	if v.Kind == event.KindList {
		for _, item := range v.L {
			if s.foldTmp(item) {
				s.scanSpan(-1, s.tmp)
			}
		}
		return
	}
	if s.foldTmp(v) {
		s.scanSpan(-1, s.tmp)
	}
}

// gateOK is the presence test: every field rule i requires is present.
func (s *scratch) gateOK(rule int) bool {
	w := s.p.fieldWords
	mask := s.p.reqMask[rule*w : rule*w+w]
	for k, m := range mask {
		if m&^s.present[k] != 0 {
			return false
		}
	}
	return true
}

// pred reads predicate i from the bitset, evaluating it on first use.
// Laziness cannot change a result: predicates have no side effects, so an
// unevaluated predicate is one no tree needed.
func (s *scratch) pred(i int32) bool {
	w, bit := i>>6, uint64(1)<<(uint(i)&63)
	if s.done[w]&bit != 0 {
		return s.val[w]&bit != 0
	}
	r := s.test(&s.p.cpreds[i])
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
