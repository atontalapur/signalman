package sigma

import (
	"errors"
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/sigma/ast"
)

func TestParsePrecedence(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a", "a"},
		{"a and b", "(and a b)"},
		{"a or b and c", "(or a (and b c))"},
		{"(a or b) and c", "(and (or a b) c)"},
		{"not a and b", "(and (not a) b)"},
		{"a and not (b or c)", "(and a (not (or b c)))"},
		{"a and b and c", "(and a b c)"},
		{"1 of selection_*", "(1of selection_*)"},
		{"all of them", "(allof them)"},
		{"any of filter*", "(1of filter*)"},
		{"1 of selection_* and not all of filter_*", "(and (1of selection_*) (not (allof filter_*)))"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			n, err := ParseCondition(c.in)
			if err != nil {
				t.Fatalf("parse %q: %v", c.in, err)
			}
			if got := ast.String(n); got != c.want {
				t.Fatalf("parse %q = %s want %s", c.in, got, c.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "a and", "(a", "a b", "and a", "1 of", "of them", ")", "2 of them"} {
		if _, err := ParseCondition(in); err == nil {
			t.Fatalf("expected error parsing %q", in)
		}
	}
}

func TestParseAggregationPropagates(t *testing.T) {
	_, err := ParseCondition("selection | count() > 5")
	if !errors.Is(err, ErrAggregation) {
		t.Fatalf("err = %v want ErrAggregation", err)
	}
}

func FuzzParseCondition(f *testing.F) {
	for _, s := range []string{
		"a", "a and b", "not (a or b)", "1 of selection_*", "all of them",
		"((((a))))", "a and not b or c",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// The only contract is that no input panics and none recurses
		// without bound. Errors are fine.
		_, _ = ParseCondition(s)
	})
}

func TestParseDepthCap(t *testing.T) {
	ok := strings.Repeat("(", maxDepth) + "a" + strings.Repeat(")", maxDepth)
	if _, err := ParseCondition(ok); err != nil {
		t.Fatalf("depth %d should parse: %v", maxDepth, err)
	}
	deep := strings.Repeat("(", maxDepth+1) + "a" + strings.Repeat(")", maxDepth+1)
	if _, err := ParseCondition(deep); err == nil {
		t.Fatalf("depth %d should be rejected", maxDepth+1)
	}
	nots := strings.Repeat("not ", maxDepth+1) + "a"
	if _, err := ParseCondition(nots); err == nil {
		t.Fatal("deep not chain should be rejected")
	}
}
