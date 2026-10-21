package v2

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"

	v1 "github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

func TestRequiredFieldsDerivation(t *testing.T) {
	cases := []struct{ name, det, want string }{
		{"and is a union", "  a: {Image|endswith: x}\n  b: {CommandLine|contains: y}\n  condition: a and b\n", "CommandLine Image"},
		{"one map is an and", "  a: {Image|endswith: x, CommandLine|contains: y}\n  condition: a\n", "CommandLine Image"},
		{"or is an intersection", "  a: {Image|endswith: x, User: u}\n  b: {CommandLine|contains: y, User: v}\n  condition: a or b\n", "User"},
		{"not requires nothing", "  a: {Image|endswith: x}\n  condition: not a\n", ""},
		{"and not keeps the positive side", "  a: {Image|endswith: x}\n  b: {CommandLine|contains: y}\n  condition: a and not b\n", "Image"},
		{"null matches absence", "  a: {Image: null}\n  condition: a\n", ""},
		{"a null in the list matches absence", "  a: {Image: [null, x]}\n  condition: a\n", ""},
		{"all with values", "  a: {Image|contains|all: [x, y]}\n  condition: a\n", "Image"},
		{"regex and numeric still need the field", "  a: {CommandLine|re: x, EventID|gt: 3}\n  condition: a\n", "CommandLine EventID"},
		{"keyword names no field", "  kw: [mimikatz]\n  condition: kw\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ruleFrom(t, c.det)
			got := requiredFields(r.Cond)
			sort.Strings(got)
			if strings.Join(got, " ") != c.want {
				t.Fatalf("requiredFields = %q, want %q", got, c.want)
			}
		})
	}
}

// A gated-out rule is never walked, and still gets its explicit false
// verdict in rule id order, so len(verdicts) == len(rules) always.
func TestGatedRuleStillEmitsAFalseVerdict(t *testing.T) {
	rs := v1Fixtures(t)
	e := New(rs)
	ev := &event.Event{Seq: 3, Fields: map[string]event.Value{
		"channel":  event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id": event.Int(1),
		// Image and CommandLine absent: the comsvcs rule is gated out.
		"ParentImage": event.String(`C:\x\veeam.exe`),
	}}
	vs := e.Evaluate(ev)
	if len(vs) != len(rs.Rules) {
		t.Fatalf("got %d verdicts for %d rules", len(vs), len(rs.Rules))
	}
	for i, v := range vs {
		if v.RuleID != rs.Rules[i].ID || v.Matched {
			t.Fatalf("verdict %d = %+v, want an explicit false for %s", i, v, rs.Rules[i].ID)
		}
	}
	s := e.pool.Get().(*scratch)
	defer e.pool.Put(s)
	s.reset(ev)
	s.load()
	if s.gateOK(0) {
		t.Fatal("rule 0 needs Image and CommandLine and must be gated out")
	}
}

// A negated rule must never be gated on the field it negates: "not
// selection" is true exactly when the field is absent.
func TestGatingDoesNotSkipANegatedRule(t *testing.T) {
	tax, err := sigma.LoadTaxonomy("../v1/testdata/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	r := ruleFrom(t, "  a: {CommandLine|contains: evil}\n  condition: not a\n")
	rs := &sigma.RuleSet{Rules: []sigma.Rule{*r}, Version: "x", TaxonomyV: tax.Version}
	ev := &event.Event{Fields: map[string]event.Value{
		"channel":  event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id": event.Int(1),
	}}
	want := v1.New(rs).Evaluate(ev)[0].Matched
	if !want {
		t.Fatal("v1 must match a negated selection on an absent field")
	}
	if got := New(rs).Evaluate(ev)[0].Matched; got != want {
		t.Fatalf("v2 = %v, v1 = %v", got, want)
	}
}

// Gating soundness over the same streams as the prefilter: a rule gated
// out is a rule v1 evaluates false.
func TestGatingSound(t *testing.T) {
	check := func(t *testing.T, rs *sigma.RuleSet, evs []*event.Event) {
		ref := v1.New(rs)
		e := New(rs)
		gated := 0
		var buf []event.Verdict
		for _, ev := range evs {
			buf = ref.EvaluateInto(buf[:0], ev)
			s := e.pool.Get().(*scratch)
			s.reset(ev)
			s.load()
			for i, v := range buf {
				if !s.gateOK(i) {
					gated++
					if v.Matched {
						t.Fatalf("rule %s gated out on an event v1 matches: %v", v.RuleID, ev.Fields)
					}
				}
			}
			e.pool.Put(s)
		}
		if gated == 0 {
			t.Fatal("nothing was gated; the property was not exercised")
		}
		t.Logf("%d (rule, event) pairs gated out", gated)
	}
	for _, src := range fixtureSources(t) {
		t.Run(src.name, func(t *testing.T) { check(t, src.rs, genEvents(src.rs, 40, 9)) })
	}
	t.Run("corpus", func(t *testing.T) {
		if testing.Short() {
			t.Skip("corpus is not a short test")
		}
		rs := corpusSource(t)
		check(t, rs, genEvents(rs, 1, 10))
	})
}

// The hot path allocates nothing once the scratch has grown to fit the
// events. Under -race sync.Pool drops entries on purpose, so the count is
// only meaningful without it.
func TestEvaluateIntoDoesNotAllocate(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops entries under the race detector")
	}
	sources := fixtureSources(t)
	if !testing.Short() {
		if _, err := corpusDir(); err == nil {
			sources = append(sources, ruleSource{"corpus", corpusSource(t)})
		}
	}
	for _, src := range sources {
		t.Run(src.name, func(t *testing.T) {
			e := New(src.rs)
			evs := genEvents(src.rs, 2, 11)
			buf := make([]event.Verdict, 0, len(src.rs.Rules))
			for _, ev := range evs {
				buf = e.EvaluateInto(buf[:0], ev)
			}
			i := 0
			allocs := testing.AllocsPerRun(len(evs), func() {
				buf = e.EvaluateInto(buf[:0], evs[i%len(evs)])
				i++
			})
			if allocs != 0 {
				t.Fatalf("EvaluateInto allocated %.2f times per event", allocs)
			}
		})
	}
}

func TestParseInt10IsStrconv(t *testing.T) {
	for _, s := range []string{"", "0", "-0", "+0", "+", "-", "12", "-12", "007", "1_000", " 1", "1 ",
		"9223372036854775807", "9223372036854775808", "-9223372036854775808", "-9223372036854775809",
		"99999999999999999999", "0x10", "١٢"} {
		checkParseInt10(t, s)
	}
}

func checkParseInt10(t *testing.T, s string) {
	t.Helper()
	want, err := strconv.ParseInt(s, 10, 64)
	got, ok := parseInt10(s)
	if ok != (err == nil) || (ok && got != want) {
		t.Fatalf("parseInt10(%q) = %d,%v; strconv = %d,%v", s, got, ok, want, err)
	}
}

func FuzzParseInt10(f *testing.F) {
	f.Add("123")
	f.Add("-9223372036854775808")
	f.Fuzz(func(t *testing.T, s string) { checkParseInt10(t, s) })
}

// textEqualFold compares an integer's text with plain equality, which is
// only right if no rune case-folds to a digit or a minus sign.
func TestDigitsHaveNoCaseFolds(t *testing.T) {
	for _, r := range "0123456789-" {
		if unicode.SimpleFold(r) != r {
			t.Fatalf("%q folds to %q", r, unicode.SimpleFold(r))
		}
	}
}

func TestCIDRPrecheckOnlyRejectsWhatParseAddrRejects(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "::1", "fe80::1%eth0", "1.2.3", "abc", "12", "true", "", "::ffff:1.2.3.4", "g::1"} {
		if !maybeAddr(s) {
			if _, err := netip.ParseAddr(s); err == nil {
				t.Fatalf("precheck rejected %q, which parses", s)
			}
		}
	}
}

func FuzzCIDRPrecheck(f *testing.F) {
	f.Add("10.0.0.1")
	f.Add("fe80::1%x")
	f.Fuzz(func(t *testing.T, s string) {
		if !maybeAddr(s) {
			if _, err := netip.ParseAddr(s); err == nil {
				t.Fatalf("precheck rejected %q, which parses", s)
			}
		}
	})
}
