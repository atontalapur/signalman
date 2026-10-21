package v2

import (
	"sort"

	"github.com/atontalapur/signalman/internal/sigma/ast"
	"github.com/atontalapur/signalman/internal/sigma/match"
)

// requiredFields derives the fields that must be present, with a non-null
// value, for n to be true. Absent and null read the same (ev.Field returns
// null for both), and every test except a null test fails on null, so a
// leaf with no null value requires its field.
//
// And takes the union of its children, Or the intersection, and Not
// requires nothing: "not selection" is true exactly when the field is
// missing, so gating it on that field would invert it. A keyword reads
// every field and requires none.
func requiredFields(n ast.Node) []string {
	set := fieldSet(n)
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func fieldSet(n ast.Node) map[string]bool {
	switch n := n.(type) {
	case *ast.And:
		out := map[string]bool{}
		for _, c := range n.Children {
			for f := range fieldSet(c) {
				out[f] = true
			}
		}
		return out
	case *ast.Or:
		var out map[string]bool
		for i, c := range n.Children {
			cs := fieldSet(c)
			if i == 0 {
				out = cs
				continue
			}
			for f := range out {
				if !cs[f] {
					delete(out, f)
				}
			}
		}
		return out
	case *ast.Pred:
		if n.Keyword {
			return nil
		}
		spec, err := match.Plan(n.Mods, n.Vals)
		if err != nil {
			return nil
		}
		for _, v := range spec.Values {
			if v.Kind == match.SpecNull {
				return nil
			}
		}
		return map[string]bool{n.Field: true}
	}
	return nil // Not
}
