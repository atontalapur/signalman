package pipe

import (
	"fmt"
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

// active is one engine, an optional shadow engine evaluated alongside it,
// and the rule metadata alerts need. The pair is one value, so a reload
// swaps both at once and no event is evaluated by v1 under one RuleSetV
// and by its shadow under another.
//
// percent is the rollout, and served the rules the shadow serves alerts
// for under it. Both are read with the engines, once per batch, so a
// rollout change also lands between batches and every event's alerts come
// from one routing decision.
type active struct {
	eng     Engine
	shadow  Engine // nil: no shadow lane
	rules   map[string]*sigma.Rule
	percent int
	served  map[string]bool // empty without a shadow

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
	// A reload changes rules, not routing: the rollout carries over.
	if cur := s.cur.Load(); cur != nil {
		a.percent = cur.percent
	}
	a.route()
	s.counts[rs.Version] = len(rs.Rules)
	s.cur.Store(a)
	if s.shown != nil {
		old := s.shown.eng.RuleSet()
		s.m.RuleSetVersion.DeleteLabelValues(old.Version, old.TaxonomyV)
	}
	s.m.RuleSetVersion.WithLabelValues(rs.Version, rs.TaxonomyV).Set(1)
	s.exportRules(a)
	s.shown = a
}

// exportRules gives every rule in the new set a rule_matches_total series,
// at zero if it is new, and removes the series of rules the reload dropped.
//
// The zero is what makes SignalmanRuleWentSilent work. A taxonomy change
// needs a restart, and a rule the change silences never matches in the new
// process; without a zero its series would end at the restart, drop out of
// the alert's 24h window, and the alert would have nothing to compare. A
// rule removed on purpose loses its series, so it is not reported as gone
// silent. A batch still in flight under the old set can bring a dropped
// rule's series back with its last matches; it then stays until restart.
// Caller holds s.mu.
func (s *Slot) exportRules(a *active) {
	if s.shown != nil {
		for id := range s.shown.rules {
			if _, kept := a.rules[id]; !kept {
				s.m.RuleMatches.DeleteLabelValues(id)
			}
		}
	}
	for id := range a.rules {
		s.m.RuleMatches.WithLabelValues(id)
	}
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

// SetRollout makes percent the rollout for every batch formed from now on:
// the shadow engine serves the alerts of every rule with
// RolloutBucket(rule) < percent, and the primary serves the rest. Both
// engines keep evaluating every rule. A rollback is SetRollout with a lower
// percent, and it lands at the next batch.
func (s *Slot) SetRollout(percent int) error {
	if percent < 0 || percent > 100 {
		return fmt.Errorf("rollout %d%% is outside 0 to 100", percent)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.cur.Load()
	if percent > 0 && cur.shadow == nil {
		return fmt.Errorf("rollout %d%% with no shadow engine to serve it", percent)
	}
	// A fresh active, not a copy: it holds a sync.Once. The rule_eval
	// children it makes on first use are the same series as before.
	a := &active{eng: cur.eng, shadow: cur.shadow, rules: cur.rules, percent: percent}
	a.route()
	s.cur.Store(a)
	s.m.RolloutPercent.Set(float64(percent))
	return nil
}

// Rollout is the percentage the next batch will be routed with.
func (s *Slot) Rollout() int { return s.cur.Load().percent }

// route fills served from percent. Without a shadow nothing is served by
// it, whatever the percent.
func (a *active) route() {
	a.served = map[string]bool{}
	if a.shadow == nil {
		return
	}
	for id := range a.rules {
		if ServedByShadow(id, a.percent) {
			a.served[id] = true
		}
	}
}
