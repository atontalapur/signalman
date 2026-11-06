package sigma

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/sigma/ast"
)

// RuleSet is every rule that loaded, plus the two versions that make a
// verdict stream comparable to another one.
type RuleSet struct {
	// Rules is sorted by ID, so iteration order is fixed regardless of how
	// the filesystem returned the files.
	Rules []Rule
	// Version is RuleSetV: a hash over each rule's ID, the canonical form of
	// its logsource test, and the canonical form of its bound, renamed
	// tree, plus the taxonomy version it was bound against. Two loads of
	// the same rules produce the same version, and a change to anything
	// that decides a verdict changes it.
	Version   string
	TaxonomyV string
}

// LoadRuleSet loads every .yml and .yaml file under dir. Rejections are
// returned rather than raised, because a corpus run needs the full list, but
// no rule is ever dropped without an entry in it.
//
// Fixture files (see IsFixture) sit beside their rules and are skipped.
func LoadRuleSet(dir string, tax *Taxonomy) (*RuleSet, []LoadError, error) {
	paths, err := RuleFiles(dir)
	if err != nil {
		return nil, nil, err
	}
	rs, errs := LoadRuleFiles(paths, tax)
	return rs, errs, nil
}

// IsFixture reports whether path is a rule's test fixture file,
// <rule>.test.yml, rather than a rule.
func IsFixture(path string) bool {
	ext := filepath.Ext(path)
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	return strings.HasSuffix(strings.TrimSuffix(filepath.Base(path), ext), ".test")
}

// FixturePath is where a rule's fixture file lives: beside it, with .test
// before the extension.
func FixturePath(rulePath string) string {
	ext := filepath.Ext(rulePath)
	return strings.TrimSuffix(rulePath, ext) + ".test" + ext
}

// RuleFiles expands files and directories into a sorted, deduplicated list
// of rule files. Directories are walked for .yml and .yaml. Fixture files
// are skipped even when named directly, because a shell glob such as
// rules/*.yml hands them over alongside the rules.
func RuleFiles(roots ...string) ([]string, error) {
	seen := map[string]bool{}
	var paths []string
	var absErr error
	add := func(p string) {
		p = filepath.Clean(p)
		if IsFixture(p) {
			return
		}
		// Dedupe on the absolute path, so rules/a.yml and /repo/rules/a.yml
		// are one file rather than a false duplicate id. The first spelling
		// given is kept for display.
		key, err := filepath.Abs(p)
		if err != nil {
			absErr = err
			return
		}
		if seen[key] {
			return
		}
		seen[key] = true
		paths = append(paths, p)
	}
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			add(root)
			continue
		}
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if ext := filepath.Ext(p); ext == ".yml" || ext == ".yaml" {
				add(p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if absErr != nil {
		return nil, absErr
	}
	sort.Strings(paths)
	return paths, nil
}

// LoadRuleFiles loads the given rule files as one rule set. The paths are
// sorted first, so the outcome, including which file keeps a duplicated id,
// does not depend on the order the caller listed them in.
func LoadRuleFiles(paths []string, tax *Taxonomy) (*RuleSet, []LoadError) {
	paths = append([]string(nil), paths...)
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

	rs.Version = ruleSetVersion(rs.Rules, tax.Version)
	return rs, errs
}

// ruleSetVersion hashes exactly what an engine evaluates for each rule: its
// logsource test and its bound, renamed condition tree. Hashing those trees,
// not the rule file's fields, means anything the loader folds into them is
// covered without being listed here.
//
// Canonical, not String: every string is quoted and every form is
// parenthesized, so a value carrying a separator cannot collide with the
// structure around it, and one rule's forms cannot run into the next.
func ruleSetVersion(rules []Rule, taxV string) string {
	h := sha256.New()
	for _, r := range rules {
		ls := "(any)"
		if r.LogSource.Node != nil {
			ls = ast.Canonical(r.LogSource.Node)
		}
		fmt.Fprintf(h, "(rule %q (logsource %s) (cond %s))", r.ID, ls, ast.Canonical(r.Cond))
	}
	fmt.Fprintf(h, "(taxonomy %q)", taxV)
	return hex.EncodeToString(h.Sum(nil))[:16]
}
