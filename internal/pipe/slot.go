package pipe

import (
	"sync"
	"sync/atomic"

	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus"
)

// Slot holds the engine new batches are evaluated with. Store swaps it
// atomically; a batch reads the slot exactly once, when ingest forms it,
// and every item in the batch is evaluated with that engine. So a reload
// lands between batches by construction: no batch straddles two RuleSetV
// values, and no lock is held while evaluating.
type Slot struct {
	cur atomic.Pointer[active]
	m   *obs.Metrics

	mu     sync.Mutex
	counts map[string]int // every RuleSetV ever active -> rule count
	shown  *active        // the version series currently exported
}

// active is one engine plus the rule metadata alerts need.
type active struct {
	eng   Engine
	rules map[string]*sigma.Rule

	// evalObs is the rule_eval_seconds child per rule, in RuleSet order,
	// made on first use so a pipeline that never samples exports none.
	evalOnce sync.Once
	evalObs  []prometheus.Observer
}

// observers returns the rule_eval_seconds child for every rule.
func (a *active) observers(m *obs.Metrics) []prometheus.Observer {
	a.evalOnce.Do(func() {
		rs := a.eng.RuleSet()
		a.evalObs = make([]prometheus.Observer, len(rs.Rules))
		for i := range rs.Rules {
			a.evalObs[i] = m.RuleEval.WithLabelValues(rs.Rules[i].ID)
		}
	})
	return a.evalObs
}

// NewSlot starts with e active.
func NewSlot(e Engine, m *obs.Metrics) *Slot {
	s := &Slot{m: m, counts: map[string]int{}}
	s.Store(e)
	return s
}

// Load returns the engine the next batch will use.
func (s *Slot) Load() Engine { return s.cur.Load().eng }

// Store makes e the engine for every batch formed from now on. Batches
// already formed finish under the engine they started with.
func (s *Slot) Store(e Engine) {
	rs := e.RuleSet()
	a := &active{eng: e, rules: make(map[string]*sigma.Rule, len(rs.Rules))}
	for i := range rs.Rules {
		a.rules[rs.Rules[i].ID] = &rs.Rules[i]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[rs.Version] = len(rs.Rules)
	s.cur.Store(a)
	if s.shown != nil {
		old := s.shown.eng.RuleSet()
		s.m.RuleSetVersion.DeleteLabelValues(old.Version, old.TaxonomyV)
	}
	s.m.RuleSetVersion.WithLabelValues(rs.Version, rs.TaxonomyV).Set(1)
	s.shown = a
}

// RuleCount reports how many verdicts per event a rule set version owes.
// Every version that was ever active stays known for the life of the
// process, so the audit can check verdicts written before a reload.
func (s *Slot) RuleCount(rulesetV string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.counts[rulesetV]
	return n, ok
}

func (s *Slot) load() *active { return s.cur.Load() }
