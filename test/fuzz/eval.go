package fuzz

import (
	"fmt"
	"path/filepath"
	"sync"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

// taxonomyDir is the real taxonomy, not a fixture. The fuzzer compares the
// shipping frontend against the oracle, so it binds rules the way the
// pipeline will.
var taxonomyDir = filepath.Join("..", "..", "config", "taxonomy")

var taxCache sync.Map // dir -> *taxResult

type taxResult struct {
	tax *sigma.Taxonomy
	err error
}

// taxonomy loads and caches a taxonomy. The fuzzer runs this millions of
// times; re-reading and re-hashing the files per case would make the
// execution count the plan's gate asks for unreachable.
func taxonomy(dir string) (*sigma.Taxonomy, error) {
	if v, ok := taxCache.Load(dir); ok {
		r := v.(*taxResult)
		return r.tax, r.err
	}
	tax, err := sigma.LoadTaxonomy(dir)
	v, _ := taxCache.LoadOrStore(dir, &taxResult{tax: tax, err: err})
	r := v.(*taxResult)
	return r.tax, r.err
}

// EvalOnce loads one rule from YAML and evaluates it against one event
// through the v1 reference evaluator.
//
// The event arrives keyed by the field names the rule writes, which is what
// the oracle understands: pySigma converts a rule to a query over columns
// named exactly as the rule names them, and has no taxonomy layer. Signalman
// reads taxonomy-mapped names, so the bridge renames the fields and stamps
// the logsource match criteria on the event. Both engines then see the same
// event, expressed in the terms each of them works in.
//
// It goes through v1 rather than walking the tree itself. A second walker
// written for the fuzzer would be a second thing to be wrong, and the whole
// point is to check what ships.
func EvalOnce(ruleYAML []byte, taxDir string, raw map[string]string) (bool, error) {
	tax, err := taxonomy(taxDir)
	if err != nil {
		return false, err
	}
	r, lerr := sigma.LoadRuleBytes("fuzz.yml", ruleYAML, tax)
	if lerr != nil {
		return false, lerr
	}
	ls, err := declaredLogSource(ruleYAML)
	if err != nil {
		return false, err
	}
	entry, ok := tax.Resolve(ls)
	if !ok {
		// LoadRuleBytes rejects an unmapped logsource, so reaching this
		// would mean the loader and Resolve disagree about the same rule.
		return false, fmt.Errorf("rule loaded but logsource %s does not resolve", ls)
	}

	ev := buildEvent(entry, raw)
	rs := &sigma.RuleSet{Rules: []sigma.Rule{*r}, TaxonomyV: tax.Version}
	verdicts := v1.New(rs).Evaluate(ev)
	if len(verdicts) != 1 {
		return false, fmt.Errorf("got %d verdicts for one rule", len(verdicts))
	}
	return verdicts[0].Matched, nil
}

// buildEvent renames the oracle's event into the taxonomy's field names and
// applies the entry's match criteria last, so a generated field called
// channel cannot push the event out of the logsource its rule declares. A
// logsource mismatch is a correct false verdict, but the oracle has no
// logsource concept, so a fuzzer that let it happen would report a
// divergence on every such case.
func buildEvent(entry *sigma.TaxonomyEntry, raw map[string]string) *event.Event {
	fields := make(map[string]event.Value, len(raw)+len(entry.Match))
	for k, v := range raw {
		name := k
		if mapped, ok := entry.Fields[k]; ok {
			name = mapped
		}
		fields[name] = event.String(v)
	}
	for k, v := range entry.Match {
		fields[k] = v
	}
	return &event.Event{Fields: fields}
}

// declaredLogSource reads the logsource block. Rule holds the compiled
// matcher rather than the declaration, and the fuzzer needs the declaration
// to find the field mapping the oracle's event has to be expressed in.
func declaredLogSource(ruleYAML []byte) (sigma.LogSource, error) {
	var doc struct {
		LogSource struct {
			Category string `yaml:"category"`
			Product  string `yaml:"product"`
			Service  string `yaml:"service"`
		} `yaml:"logsource"`
	}
	if err := yaml.Unmarshal(ruleYAML, &doc); err != nil {
		return sigma.LogSource{}, err
	}
	return sigma.LogSource{
		Category: doc.LogSource.Category,
		Product:  doc.LogSource.Product,
		Service:  doc.LogSource.Service,
	}, nil
}

// bridgeable reports whether the case can reach the oracle at all. The
// bridge is JSON, and JSON cannot carry a string that is not valid UTF-8:
// encoding one substitutes U+FFFD, so the oracle would answer a question
// nobody asked. Signalman's own handling of invalid UTF-8 is covered by the
// unit tests in internal/sigma. Recorded in KNOWN_DIVERGENCES.md.
func bridgeable(ruleYAML string, raw map[string]string) bool {
	if !utf8.ValidString(ruleYAML) {
		return false
	}
	for k, v := range raw {
		if !utf8.ValidString(k) || !utf8.ValidString(v) {
			return false
		}
	}
	return true
}

// missingField reports whether the rule read a field the event does not
// carry. SQLite answers a comparison against a missing column with NULL, so
// a negated condition over an absent field is false there and true in Sigma.
// Recorded in KNOWN_DIVERGENCES.md.
func missingField(ruleFields []string, raw map[string]string) bool {
	for _, f := range ruleFields {
		if _, ok := raw[f]; !ok {
			return true
		}
	}
	return false
}
