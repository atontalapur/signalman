package ast

import (
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

// constMatcher ignores the value and returns a fixed answer, so tests can
// exercise the tree walker without the match package.
type constMatcher bool

func (m constMatcher) Match(event.Value, *event.Event) bool { return bool(m) }

func pred(name string, ok bool) *Pred {
	return &Pred{Field: name, Desc: name, M: constMatcher(ok)}
}

func TestEval(t *testing.T) {
	ev := &event.Event{}
	tr, fa := pred("t", true), pred("f", false)
	cases := []struct {
		name string
		n    Node
		want bool
	}{
		{"pred true", tr, true},
		{"pred false", fa, false},
		{"and all true", &And{Children: []Node{tr, tr}}, true},
		{"and one false", &And{Children: []Node{tr, fa}}, false},
		{"or one true", &Or{Children: []Node{fa, tr}}, true},
		{"or all false", &Or{Children: []Node{fa, fa}}, false},
		{"not", &Not{Child: fa}, true},
		{"nested", &And{Children: []Node{tr, &Not{Child: &Or{Children: []Node{fa, fa}}}}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Eval(c.n, ev); got != c.want {
				t.Fatalf("Eval = %v want %v", got, c.want)
			}
		})
	}
}

func TestEvalPanicsOnUnboundNodes(t *testing.T) {
	for _, n := range []Node{&Ident{Name: "x"}, &Quant{Count: QuantAll, Them: true}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("Eval(%T) did not panic", n)
				}
			}()
			Eval(n, &event.Event{})
		}()
	}
}

func TestStringAndCanonical(t *testing.T) {
	n := &And{Children: []Node{
		&Ident{Name: "a"},
		&Not{Child: &Or{Children: []Node{&Quant{Count: QuantOne, Pattern: "s_*"}, &Quant{Count: QuantAll, Them: true}}}},
		pred("Image endswith .exe", true),
	}}
	if got, want := String(n), "(and a (not (or (1of s_*) (allof them))) [Image endswith .exe])"; got != want {
		t.Fatalf("String = %s want %s", got, want)
	}
	if got, want := Canonical(n), `(and "a" (not (or (1of "s_*") (allof them))) ["Image endswith .exe"])`; got != want {
		t.Fatalf("Canonical = %s want %s", got, want)
	}
}

// Canonical must not let a crafted name collide with the tree structure.
func TestCanonicalQuotesSeparators(t *testing.T) {
	a := Canonical(&And{Children: []Node{&Ident{Name: "x y"}}})
	b := Canonical(&And{Children: []Node{&Ident{Name: "x"}, &Ident{Name: "y"}}})
	if a == b {
		t.Fatalf("Canonical collision: %s", a)
	}
}

func TestSortedNames(t *testing.T) {
	m := map[string]Node{"c": nil, "a": nil, "b": nil}
	got := SortedNames(m)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("SortedNames = %v", got)
	}
}
