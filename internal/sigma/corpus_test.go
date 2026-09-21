package sigma

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

const corpusDir = "../../corpora/sigmahq/rules"

// TestCorpusEveryRuleIsAcceptedOrRejectedWithAReason is the gate for Plan A.
// There is no third outcome: a rule either loads or produces exactly one
// LoadError carrying a code and a reason.
//
// It is skipped under -short and when the corpus is not vendored, because
// the corpus is a third-party clone under corpora/, which is gitignored.
func TestCorpusEveryRuleIsAcceptedOrRejectedWithAReason(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus acceptance is not a short test")
	}
	if _, err := os.Stat(corpusDir); err != nil {
		t.Skip("SigmaHQ corpus not vendored: git clone --depth 1 https://github.com/SigmaHQ/sigma corpora/sigmahq")
	}
	tax, err := LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	rs, errs, err := LoadRuleSet(corpusDir, tax)
	if err != nil {
		t.Fatal(err)
	}

	want := countRuleFiles(t, corpusDir)
	if got := len(rs.Rules) + len(errs); got != want {
		t.Fatalf("accounted for %d rules but the tree has %d files", got, want)
	}
	for _, e := range errs {
		if e.Code == "" || e.Reason == "" {
			t.Fatalf("rejection without a code or reason: %+v", e)
		}
		if e.Path == "" {
			t.Fatalf("rejection without a path: %+v", e)
		}
	}
	t.Logf("corpus: %d files, %d loaded, %d rejected, ruleset %s taxonomy %s",
		want, len(rs.Rules), len(errs), rs.Version, rs.TaxonomyV)
}

// TestCorpusLoadIsDeterministic guards the property the whole equivalence
// argument rests on: the same files give the same rule set version, so two
// engines can be compared by digest rather than by diffing verdicts.
func TestCorpusLoadIsDeterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus acceptance is not a short test")
	}
	if _, err := os.Stat(corpusDir); err != nil {
		t.Skip("SigmaHQ corpus not vendored")
	}
	tax, err := LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	first, firstErrs, err := LoadRuleSet(corpusDir, tax)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		got, gotErrs, err := LoadRuleSet(corpusDir, tax)
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != first.Version {
			t.Fatalf("load %d: RuleSetV %s, want %s", i, got.Version, first.Version)
		}
		if len(gotErrs) != len(firstErrs) {
			t.Fatalf("load %d: %d rejections, want %d", i, len(gotErrs), len(firstErrs))
		}
	}
}

func countRuleFiles(t *testing.T, dir string) int {
	t.Helper()
	var n int
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(p); ext == ".yml" || ext == ".yaml" {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
