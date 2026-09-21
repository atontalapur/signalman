package sigma

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/atontalapur/signalman/internal/sigma/ast"
)

// RuleSet is every rule that loaded, plus the two versions that make a
// verdict stream comparable to another one.
type RuleSet struct {
	// Rules is sorted by ID, so iteration order is fixed regardless of how
	// the filesystem returned the files.
	Rules []Rule
	// Version is RuleSetV: a hash over each rule's ID and the canonical form
	// of its bound tree, plus the taxonomy version it was bound against.
	// Two loads of the same rules produce the same version, and a change to
	// any rule's semantics changes it.
	Version   string
	TaxonomyV string
}

// LoadRuleSet loads every .yml and .yaml file under dir. Rejections are
// returned rather than raised, because a corpus run needs the full list, but
// no rule is ever dropped without an entry in it.
func LoadRuleSet(dir string, tax *Taxonomy) (*RuleSet, []LoadError, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(p); ext == ".yml" || ext == ".yaml" {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(paths)

	rs := &RuleSet{TaxonomyV: tax.Version}
	var errs []LoadError
	byID := make(map[string]string, len(paths))
	for _, p := range paths {
		r, lerr := LoadRule(p, tax)
		if lerr != nil {
			errs = append(errs, *lerr)
			continue
		}
		if prev, dup := byID[r.ID]; dup {
			// Two rules with one id make verdicts ambiguous: a verdict is
			// keyed on the rule id, so the second rule's verdicts would be
			// indistinguishable from the first's.
			errs = append(errs, LoadError{
				Path:   p,
				RuleID: r.ID,
				Code:   CodeDuplicateID,
				Reason: fmt.Sprintf("id already claimed by %s, this file is %s", prev, p),
				Line:   1,
			})
			continue
		}
		byID[r.ID] = p
		rs.Rules = append(rs.Rules, *r)
	}
	sort.Slice(rs.Rules, func(i, j int) bool { return rs.Rules[i].ID < rs.Rules[j].ID })

	// Canonical, not String: every string is quoted, so a value carrying a
	// separator cannot collide with the structure around it.
	h := sha256.New()
	for _, r := range rs.Rules {
		h.Write([]byte(r.ID))
		h.Write([]byte(ast.Canonical(r.Cond)))
	}
	h.Write([]byte(tax.Version))
	rs.Version = hex.EncodeToString(h.Sum(nil))[:16]
	return rs, errs, nil
}
