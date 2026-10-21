package sigma

import (
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma/ast"
)

// collectPreds returns the leaves of a tree in walk order.
func collectPreds(n ast.Node) []*ast.Pred {
	var out []*ast.Pred
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
		case *ast.Pred:
			out = append(out, n)
		}
	}
	walk(n)
	return out
}

// A compiled engine interns predicates and derives prefilter literals from
// the detection entry, so the leaf has to carry what its matcher was built
// from, not only the display string.
func TestDetectionPredCarriesItsSource(t *testing.T) {
	sels, _ := compileYAML(t, `
selection:
  CommandLine|contains|all:
    - comsvcs
    - 4688
  Image: null
keywords:
  - mimikatz
condition: selection or keywords
`)
	preds := collectPreds(sels["selection"])
	if len(preds) != 2 {
		t.Fatalf("got %d preds, want 2", len(preds))
	}
	cl := preds[0]
	if cl.Field != "CommandLine" || cl.Keyword {
		t.Fatalf("pred = %+v", cl)
	}
	if strings.Join(cl.Mods, "|") != "contains|all" {
		t.Fatalf("mods = %v, want the chain as written", cl.Mods)
	}
	if len(cl.Vals) != 2 || cl.Vals[0].Kind != event.KindString || cl.Vals[0].S != "comsvcs" ||
		cl.Vals[1].Kind != event.KindInt || cl.Vals[1].I != 4688 {
		t.Fatalf("vals = %+v", cl.Vals)
	}
	if img := preds[1]; img.Field != "Image" || len(img.Mods) != 0 || len(img.Vals) != 1 || img.Vals[0].Kind != event.KindNull {
		t.Fatalf("null pred = %+v", img)
	}

	kw := collectPreds(sels["keywords"])
	if len(kw) != 1 || !kw[0].Keyword || kw[0].Field != "" || len(kw[0].Vals) != 1 || kw[0].Vals[0].S != "mimikatz" {
		t.Fatalf("keyword pred = %+v", kw)
	}
}

func TestLoadRuleRenameKeepsThePredSource(t *testing.T) {
	tax := loadTax(t)
	r, lerr := LoadRule("testdata/rules/list_condition.yml", tax)
	if lerr != nil {
		t.Fatal(lerr)
	}
	for _, p := range collectPreds(r.Cond) {
		if p.Field != "NewProcessName" || strings.Join(p.Mods, "|") != "endswith" || len(p.Vals) != 1 {
			t.Fatalf("renamed pred lost its source: %+v", p)
		}
	}
	ls := collectPreds(r.LogSource.Node)
	if len(ls) == 0 {
		t.Fatal("the security entry has match criteria")
	}
	for _, p := range ls {
		if len(p.Mods) != 0 || len(p.Vals) != 1 || p.Keyword {
			t.Fatalf("logsource pred has no source: %+v", p)
		}
	}
}
