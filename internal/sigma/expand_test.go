package sigma

import (
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/sigma/ast"
)

func expandStr(t *testing.T, cond string, names ...string) string {
	t.Helper()
	n, err := ParseCondition(cond)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	e, err := Expand(n, names)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	return ast.String(e)
}

func TestExpandQuantifiers(t *testing.T) {
	names := []string{"filter_a", "filter_b", "selection_1", "selection_2"}
	cases := []struct{ cond, want string }{
		{"1 of selection_*", "(or selection_1 selection_2)"},
		{"all of selection_*", "(and selection_1 selection_2)"},
		{"all of them", "(and filter_a filter_b selection_1 selection_2)"},
		{"1 of them", "(or filter_a filter_b selection_1 selection_2)"},
		{"selection_1 and not 1 of filter_*", "(and selection_1 (not (or filter_a filter_b)))"},
	}
	for _, c := range cases {
		t.Run(c.cond, func(t *testing.T) {
			if got := expandStr(t, c.cond, names...); got != c.want {
				t.Fatalf("expand %q = %s want %s", c.cond, got, c.want)
			}
		})
	}
}

func TestExpandSingleMatchCollapses(t *testing.T) {
	if got := expandStr(t, "1 of selection_*", "selection_1"); got != "selection_1" {
		t.Fatalf("got %s want selection_1", got)
	}
}

func TestExpandIsOrderIndependent(t *testing.T) {
	a := expandStr(t, "all of them", "b", "a", "c")
	b := expandStr(t, "all of them", "c", "b", "a")
	if a != b {
		t.Fatalf("expansion depends on input order: %s vs %s", a, b)
	}
}

// An exact pattern with no star must still resolve, and the caller's slice
// must not be reordered under it.
func TestExpandExactPatternAndCallerSliceUntouched(t *testing.T) {
	names := []string{"selection_2", "selection_1"}
	if got := expandStr(t, "1 of selection_1", names...); got != "selection_1" {
		t.Fatalf("got %s want selection_1", got)
	}
	if names[0] != "selection_2" || names[1] != "selection_1" {
		t.Fatalf("Expand reordered the caller's slice: %v", names)
	}
}

func TestExpandLeavesNoQuantNodes(t *testing.T) {
	n, err := ParseCondition("1 of selection_* and not all of filter_*")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	e, err := Expand(n, []string{"selection_1", "selection_2", "filter_a", "filter_b"})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	var walk func(ast.Node)
	walk = func(n ast.Node) {
		switch n := n.(type) {
		case *ast.And:
			for _, c := range n.Children {
				walk(c)
			}
		case *ast.Or:
			for _, c := range n.Children {
				walk(c)
			}
		case *ast.Not:
			walk(n.Child)
		case *ast.Quant:
			t.Fatalf("Quant survived expansion: %s", ast.String(n))
		}
	}
	walk(e)
}

func TestExpandErrors(t *testing.T) {
	n, _ := ParseCondition("1 of nomatch_*")
	if _, err := Expand(n, []string{"selection"}); err == nil ||
		!strings.Contains(err.Error(), "nomatch_*") {
		t.Fatalf("expected an error naming the pattern, got %v", err)
	}
	n2, _ := ParseCondition("undefined_selection")
	if _, err := Expand(n2, []string{"selection"}); err == nil {
		t.Fatal("expected an error for an undefined selection name")
	}
	n3, _ := ParseCondition("all of them")
	if _, err := Expand(n3, nil); err == nil {
		t.Fatal("expected an error for them over an empty detection block")
	}
}
