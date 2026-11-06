package sigma

import (
	"fmt"
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/sigma/ast"
)

// shape renders a tree with field names included, which ast.String leaves
// out, so a rename that went missing on one side shows up as a difference.
func shape(n ast.Node) string {
	var b strings.Builder
	var walk func(ast.Node)
	walk = func(n ast.Node) {
		switch n := n.(type) {
		case *ast.And:
			b.WriteString("(and")
			for _, c := range n.Children {
				b.WriteString(" ")
				walk(c)
			}
			b.WriteString(")")
		case *ast.Or:
			b.WriteString("(or")
			for _, c := range n.Children {
				b.WriteString(" ")
				walk(c)
			}
			b.WriteString(")")
		case *ast.Not:
			b.WriteString("(not ")
			walk(n.Child)
			b.WriteString(")")
		case *ast.Pred:
			fmt.Fprintf(&b, "[%q %q]", n.Field, n.Desc)
		case *ast.Ident:
			fmt.Fprintf(&b, "<%s>", n.Name)
		default:
			fmt.Fprintf(&b, "?%T", n)
		}
	}
	walk(n)
	return b.String()
}

// substitute is bind, restated here so the test does not lean on the code
// it is checking.
func substitute(n ast.Node, sels map[string]ast.Node) ast.Node {
	switch n := n.(type) {
	case *ast.And:
		kids := make([]ast.Node, len(n.Children))
		for i, c := range n.Children {
			kids[i] = substitute(c, sels)
		}
		return &ast.And{Children: kids}
	case *ast.Or:
		kids := make([]ast.Node, len(n.Children))
		for i, c := range n.Children {
			kids[i] = substitute(c, sels)
		}
		return &ast.Or{Children: kids}
	case *ast.Not:
		return &ast.Not{Child: substitute(n.Child, sels)}
	case *ast.Ident:
		return sels[n.Name]
	}
	return n
}

// The named condition exists for explain output. It is only trustworthy if
// substituting its selections gives back exactly the tree v1 evaluates.
func TestNamedConditionSubstitutesToTheBoundTree(t *testing.T) {
	tax, err := LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := RuleFiles("../../rules", "testdata/rules")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, p := range paths {
		r, lerr := LoadRule(p, tax)
		if lerr != nil {
			continue
		}
		checked++
		if r.Condition == nil {
			t.Fatalf("%s: no named condition", p)
		}
		got := shape(substitute(r.Condition, r.Selections))
		if want := shape(r.Cond); got != want {
			t.Errorf("%s:\nnamed  %s\nbound  %s", p, got, want)
		}
	}
	if checked < 20 {
		t.Fatalf("only %d rules checked", checked)
	}
}

func TestNamedConditionKeepsSelectionNames(t *testing.T) {
	tax := loadTax(t)
	r, lerr := LoadRule("testdata/rules/proc_dump.yml", tax)
	if lerr != nil {
		t.Fatal(lerr)
	}
	want := "(and <selection_img> <selection_cli> (not <filter_backup>))"
	if got := shape(r.Condition); got != want {
		t.Fatalf("condition = %s, want %s", got, want)
	}
	for _, name := range []string{"selection_img", "selection_cli", "filter_backup"} {
		if r.Selections[name] == nil {
			t.Errorf("selection %s missing", name)
		}
	}
}

func TestLoadRuleKeepsTags(t *testing.T) {
	tax, err := LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	r, lerr := LoadRule("../../rules/proc_dump.yml", tax)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if strings.Join(r.Tags, ",") != "attack.credential-access,attack.t1003.001" {
		t.Fatalf("tags = %v", r.Tags)
	}
}
