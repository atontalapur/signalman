package sigma

import (
	"fmt"
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/sigma/ast"
)

// Expand resolves quantifiers into plain boolean nodes and verifies that
// every identifier names a defined selection. Doing this at parse time
// means an evaluator only ever sees And, Or, Not, and Pred.
//
// names is copied and sorted, so the caller's order cannot affect the
// resulting tree.
func Expand(n ast.Node, names []string) (ast.Node, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	defined := make(map[string]bool, len(sorted))
	for _, s := range sorted {
		defined[s] = true
	}
	return expand(n, sorted, defined)
}

func expand(n ast.Node, sorted []string, defined map[string]bool) (ast.Node, error) {
	switch n := n.(type) {
	case *ast.And:
		kids, err := expandAll(n.Children, sorted, defined)
		if err != nil {
			return nil, err
		}
		return &ast.And{Children: kids}, nil
	case *ast.Or:
		kids, err := expandAll(n.Children, sorted, defined)
		if err != nil {
			return nil, err
		}
		return &ast.Or{Children: kids}, nil
	case *ast.Not:
		c, err := expand(n.Child, sorted, defined)
		if err != nil {
			return nil, err
		}
		return &ast.Not{Child: c}, nil
	case *ast.Ident:
		if !defined[n.Name] {
			return nil, fmt.Errorf("condition refers to %q, which is not defined in the detection block", n.Name)
		}
		return n, nil
	case *ast.Quant:
		return expandQuant(n, sorted)
	}
	return nil, fmt.Errorf("unexpected node %T in expansion", n)
}

func expandAll(in []ast.Node, sorted []string, defined map[string]bool) ([]ast.Node, error) {
	out := make([]ast.Node, len(in))
	for i, c := range in {
		e, err := expand(c, sorted, defined)
		if err != nil {
			return nil, err
		}
		out[i] = e
	}
	return out, nil
}

func expandQuant(q *ast.Quant, sorted []string) (ast.Node, error) {
	var picked []ast.Node
	for _, name := range sorted {
		if q.Them || matchSelectionGlob(q.Pattern, name) {
			picked = append(picked, &ast.Ident{Name: name})
		}
	}
	if len(picked) == 0 {
		target := q.Pattern
		if q.Them {
			target = "them"
		}
		return nil, fmt.Errorf("quantifier over %q matches no selection in the detection block", target)
	}
	if len(picked) == 1 {
		return picked[0], nil
	}
	if q.Count == ast.QuantAll {
		return &ast.And{Children: picked}, nil
	}
	return &ast.Or{Children: picked}, nil
}

// matchSelectionGlob implements the prefix glob in the condition grammar:
// an identifier optionally ending in a single star.
func matchSelectionGlob(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}
