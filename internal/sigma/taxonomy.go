package sigma

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma/ast"
	"github.com/atontalapur/signalman/internal/sigma/match"
	"gopkg.in/yaml.v3"
)

// LogSource is the abstract source a rule declares. It means nothing until
// the taxonomy binds it to concrete field names and match criteria.
type LogSource struct {
	Category string
	Product  string
	Service  string
}

func (ls LogSource) String() string {
	return fmt.Sprintf("product=%s category=%s service=%s", ls.Product, ls.Category, ls.Service)
}

// TaxonomyEntry is one logsource binding: which events belong to the
// logsource, and what the rule's abstract field names are called on them.
type TaxonomyEntry struct {
	LogSource LogSource
	Match     map[string]event.Value
	Fields    map[string]string
	Path      string
}

// Taxonomy is the loaded set of bindings.
type Taxonomy struct {
	// Version is TaxonomyV: the content hash of every loaded file. It is
	// carried on every verdict, because a taxonomy change can silently
	// change what a rule matches.
	Version string
	entries []TaxonomyEntry
}

type taxonomyFile struct {
	LogSource struct {
		Category string `yaml:"category"`
		Product  string `yaml:"product"`
		Service  string `yaml:"service"`
	} `yaml:"logsource"`
	Match  map[string]any    `yaml:"match"`
	Fields map[string]string `yaml:"fields"`
}

// LoadTaxonomy reads every .yml file in dir. Files are read in sorted order
// and hashed in that order, so the version is reproducible: the same bytes
// always give the same TaxonomyV, on any machine, in any order on disk.
func LoadTaxonomy(dir string) (*Taxonomy, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no taxonomy files in %s", dir)
	}

	h := sha256.New()
	t := &Taxonomy{}
	seen := make(map[LogSource]string, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		h.Write([]byte(filepath.Base(p)))
		h.Write(b)

		var f taxonomyFile
		if err := yaml.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		ls := LogSource{
			Category: f.LogSource.Category,
			Product:  f.LogSource.Product,
			Service:  f.LogSource.Service,
		}
		if ls == (LogSource{}) {
			return nil, fmt.Errorf("%s: entry has no logsource", p)
		}
		if prev, dup := seen[ls]; dup {
			// Two entries for one logsource would make Resolve depend on
			// file order, and the whole point of TaxonomyV is that nothing
			// here depends on order.
			return nil, fmt.Errorf("duplicate logsource %s in %s and %s", ls, prev, p)
		}
		seen[ls] = p

		m := make(map[string]event.Value, len(f.Match))
		for k, v := range f.Match {
			val, err := toValue(v)
			if err != nil {
				return nil, fmt.Errorf("%s: match %q: %w", p, k, err)
			}
			m[k] = val
		}
		t.entries = append(t.entries, TaxonomyEntry{
			LogSource: ls,
			Match:     m,
			Fields:    f.Fields,
			Path:      p,
		})
	}
	t.Version = hex.EncodeToString(h.Sum(nil))[:16]
	return t, nil
}

// Resolve finds the entry for a rule's logsource. All three components must
// agree exactly, and a blank component in the rule matches only a blank
// component in the entry. There is no rule-side wildcard: a rule that omits
// the service is a different logsource from one that names it, and the two
// can carry different field mappings.
func (t *Taxonomy) Resolve(ls LogSource) (*TaxonomyEntry, bool) {
	for i := range t.entries {
		if t.entries[i].LogSource == ls {
			return &t.entries[i], true
		}
	}
	return nil, false
}

// LogSourceMatcher is the logsource test, kept separate from the condition
// tree so that a logsource mismatch can emit an explicit false verdict
// without walking the condition. The zero value admits every event, which is
// what an entry with no match criteria means.
type LogSourceMatcher struct{ Node ast.Node }

func (m LogSourceMatcher) Matches(ev *event.Event) bool {
	if m.Node == nil {
		return true
	}
	return ast.Eval(m.Node, ev)
}

// MatcherFor builds the logsource test from an entry's match criteria. Keys
// are sorted, so the tree shape does not move with map iteration.
func (t *Taxonomy) MatcherFor(e *TaxonomyEntry) LogSourceMatcher {
	keys := make([]string, 0, len(e.Match))
	for k := range e.Match {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	kids := make([]ast.Node, 0, len(keys))
	for _, k := range keys {
		v := e.Match[k]
		m, err := match.Build(nil, []event.Value{v})
		if err != nil {
			// Build with no modifiers on a scalar cannot fail. A panic here
			// would mean the taxonomy carries a value kind toValue accepted
			// and Build did not, which is a programming error, not bad input.
			panic(fmt.Sprintf("taxonomy match %q: %v", k, err))
		}
		kids = append(kids, &ast.Pred{Field: k, Desc: describe(k, []event.Value{v}), M: m})
	}
	if len(kids) == 0 {
		return LogSourceMatcher{}
	}
	if len(kids) == 1 {
		return LogSourceMatcher{Node: kids[0]}
	}
	return LogSourceMatcher{Node: &ast.And{Children: kids}}
}
