package pipe

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/sigma"
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

// active is one engine, an optional shadow engine evaluated alongside it,
// and the rule metadata alerts need. The pair is one value, so a reload
// swaps both at once and no event is evaluated by v1 under one RuleSetV
// and by its shadow under another.
type active struct {
	eng    Engine
	shadow Engine // nil: no shadow lane
	rules  map[string]*sigma.Rule
}

// NewSlot starts with e active.
func NewSlot(e Engine, m *obs.Metrics) *Slot {
	s := &Slot{m: m, counts: map[string]int{}}
	s.Store(e)
	return s
}

// Load returns the engine the next batch will use.
func (s *Slot) Load() Engine { return s.cur.Load().eng }

// Shadow returns the shadow engine the next batch will use, or nil.
func (s *Slot) Shadow() Engine { return s.cur.Load().shadow }

// Store makes e the engine for every batch formed from now on, with no
// shadow. Batches already formed finish under the engine they started with.
func (s *Slot) Store(e Engine) { s.store(e, nil) }

// StoreWithShadow makes primary the engine and shadow the shadow engine for
// every batch formed from now on. Both must carry the same RuleSetV and
// TaxonomyV, and different names, or nothing is stored: a shadow under
// another rule set would make every comparison version skew, and one with
// the primary's name would write into the primary's verdict topic.
func (s *Slot) StoreWithShadow(primary, shadow Engine) error {
	p, sh := primary.RuleSet(), shadow.RuleSet()
	if p.Version != sh.Version || p.TaxonomyV != sh.TaxonomyV {
		return fmt.Errorf("shadow %s is under ruleset %s taxonomy %s, primary %s under %s taxonomy %s",
			shadow.Name(), sh.Version, sh.TaxonomyV, primary.Name(), p.Version, p.TaxonomyV)
	}
	if primary.Name() == shadow.Name() {
		return fmt.Errorf("shadow and primary are both named %q", primary.Name())
	}
	s.store(primary, shadow)
	return nil
}

func (s *Slot) store(e, shadow Engine) {
	rs := e.RuleSet()
	a := &active{eng: e, shadow: shadow, rules: make(map[string]*sigma.Rule, len(rs.Rules))}
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
