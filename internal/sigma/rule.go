package sigma

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/sigma/ast"
	"github.com/atontalapur/signalman/internal/sigma/match"
	"gopkg.in/yaml.v3"
)

// Rule is a loaded, bound rule: the condition tree with every selection
// substituted and every field name resolved through the taxonomy. Nothing
// about evaluating it depends on the file it came from.
type Rule struct {
	ID        string
	Title     string
	Level     string
	Status    string
	Path      string
	LogSource LogSourceMatcher
	Cond      ast.Node
	// Fields lists every event field the rule reads, sorted. Later phases
	// use it for presence gating; it is cheap to compute here and awkward
	// to recover later.
	Fields []string
}

// Error codes carried by LoadError. The set is closed: the corpus acceptance
// report has one paragraph per code stating whether the rejection is
// intended, so a new code is a documentation change too.
const (
	CodeYAML        = "yaml"
	CodeMissingID   = "missing-id"
	CodeDuplicateID = "duplicate-id"
	CodeNoTaxonomy  = "no-taxonomy"
	CodeCondition   = "condition"
	CodeDetection   = "detection"
	CodeModifier    = "modifier"
	CodeAggregation = "aggregation"
)

// LoadError is a structured rejection. Every rejection is reported, counted,
// and attributable to a rule, because a silently skipped rule is a missed
// detection with no signal attached to it.
type LoadError struct {
	Path   string
	RuleID string
	Code   string
	Reason string
	Line   int
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("%s:%d [%s] rule %s: %s", e.Path, e.Line, e.Code, e.RuleID, e.Reason)
}

type ruleFile struct {
	Title     string `yaml:"title"`
	ID        string `yaml:"id"`
	Status    string `yaml:"status"`
	Level     string `yaml:"level"`
	LogSource struct {
		Category string `yaml:"category"`
		Product  string `yaml:"product"`
		Service  string `yaml:"service"`
	} `yaml:"logsource"`
	Detection map[string]any `yaml:"detection"`
}

// LoadRule reads and binds one rule file.
func LoadRule(path string, tax *Taxonomy) (*Rule, *LoadError) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, &LoadError{Path: path, Code: CodeYAML, Reason: err.Error(), Line: 1}
	}
	return LoadRuleBytes(path, b, tax)
}

// LoadRuleBytes binds a rule from source already in memory. The fuzzer and
// the corpus tools generate rules that never touch the disk; path is used
// only for error messages.
func LoadRuleBytes(path string, src []byte, tax *Taxonomy) (*Rule, *LoadError) {
	var f ruleFile
	if err := yaml.Unmarshal(src, &f); err != nil {
		return nil, &LoadError{Path: path, Code: CodeYAML, Reason: err.Error(), Line: 1}
	}
	fail := func(code, reason string, line int) *LoadError {
		return &LoadError{Path: path, RuleID: f.ID, Code: code, Reason: reason, Line: line}
	}
	if f.ID == "" {
		return nil, fail(CodeMissingID, "rule has no id", 1)
	}

	condLine := conditionLine(src)
	conds, err := conditionStrings(f.Detection)
	if err != nil {
		return nil, fail(CodeCondition, err.Error(), condLine)
	}

	sels, names, err := CompileDetection(f.Detection)
	if err != nil {
		code := CodeDetection
		if errors.Is(err, match.ErrUnsupportedModifier) {
			// Classified on the sentinel, never on error text: the text is
			// for humans and changes; the code is counted in the corpus
			// acceptance report.
			code = CodeModifier
		}
		return nil, fail(code, err.Error(), 1)
	}

	// A list of conditions is an OR over the parsed arms. Each arm is
	// parsed, expanded, and bound on its own.
	arms := make([]ast.Node, 0, len(conds))
	for _, c := range conds {
		parsed, err := ParseCondition(c)
		if err != nil {
			code := CodeCondition
			if errors.Is(err, ErrAggregation) {
				code = CodeAggregation
			}
			return nil, fail(code, err.Error(), condLine)
		}
		expanded, err := Expand(parsed, names)
		if err != nil {
			return nil, fail(CodeCondition, err.Error(), condLine)
		}
		arms = append(arms, expanded)
	}
	var cond ast.Node
	if len(arms) == 1 {
		cond = arms[0]
	} else {
		cond = &ast.Or{Children: arms}
	}

	// The taxonomy is resolved last, after everything that decides whether
	// this engine can express the rule at all. A rule carrying an
	// aggregation pipe reports "aggregation" even on a logsource nobody
	// mapped, so the corpus acceptance report measures the engine rather
	// than this deployment's config. Either way the rule is rejected.
	ls := LogSource{
		Category: f.LogSource.Category,
		Product:  f.LogSource.Product,
		Service:  f.LogSource.Service,
	}
	entry, ok := tax.Resolve(ls)
	if !ok {
		return nil, fail(CodeNoTaxonomy, fmt.Sprintf("no taxonomy entry for %s", ls), 1)
	}

	bound := bind(cond, sels)
	renamed, fields := rename(bound, entry.Fields)

	return &Rule{
		ID:        f.ID,
		Title:     f.Title,
		Level:     f.Level,
		Status:    f.Status,
		Path:      path,
		LogSource: tax.MatcherFor(entry),
		Cond:      renamed,
		Fields:    fields,
	}, nil
}

// conditionStrings reads the condition key, which Sigma allows to be a
// single string or a list of strings. Any other shape is an error naming the
// type, because guessing at it would bind a rule to something its author did
// not write.
func conditionStrings(det map[string]any) ([]string, error) {
	raw, ok := det["condition"]
	if !ok || raw == nil {
		return nil, errors.New("detection block has no condition")
	}
	switch v := raw.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, errors.New("detection block has an empty condition")
		}
		return []string{v}, nil
	case []any:
		if len(v) == 0 {
			return nil, errors.New("detection block has an empty condition list")
		}
		out := make([]string, 0, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("condition item %d is %T, want a string", i, item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("condition is %T, want a string or a list of strings", raw)
	}
}

// bind substitutes each selection's compiled subtree for its identifier.
func bind(n ast.Node, sels map[string]ast.Node) ast.Node {
	switch n := n.(type) {
	case *ast.And:
		return &ast.And{Children: bindAll(n.Children, sels)}
	case *ast.Or:
		return &ast.Or{Children: bindAll(n.Children, sels)}
	case *ast.Not:
		return &ast.Not{Child: bind(n.Child, sels)}
	case *ast.Ident:
		// Expand has already verified that the name is defined.
		return sels[n.Name]
	default:
		return n
	}
}

func bindAll(in []ast.Node, sels map[string]ast.Node) []ast.Node {
	out := make([]ast.Node, len(in))
	for i, c := range in {
		out[i] = bind(c, sels)
	}
	return out
}

// rename rewrites predicate field names through the taxonomy mapping and
// collects the sorted set of fields the rule reads. A field with no mapping
// keeps its name, which is what an event source that already uses Sigma
// field names needs.
func rename(n ast.Node, mapping map[string]string) (ast.Node, []string) {
	seen := map[string]bool{}
	out := renameNode(n, mapping, seen)
	fields := make([]string, 0, len(seen))
	for f := range seen {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	return out, fields
}

func renameNode(n ast.Node, mapping map[string]string, seen map[string]bool) ast.Node {
	switch n := n.(type) {
	case *ast.And:
		kids := make([]ast.Node, len(n.Children))
		for i, c := range n.Children {
			kids[i] = renameNode(c, mapping, seen)
		}
		return &ast.And{Children: kids}
	case *ast.Or:
		kids := make([]ast.Node, len(n.Children))
		for i, c := range n.Children {
			kids[i] = renameNode(c, mapping, seen)
		}
		return &ast.Or{Children: kids}
	case *ast.Not:
		return &ast.Not{Child: renameNode(n.Child, mapping, seen)}
	case *ast.Pred:
		field := n.Field
		if to, ok := mapping[field]; ok && to != "" {
			field = to
		}
		if field != "" {
			seen[field] = true
		}
		return &ast.Pred{Field: field, Desc: n.Desc, M: n.M}
	}
	return n
}

// conditionLine finds the 1-based line of the condition key, so the error
// points at something an author can open.
func conditionLine(src []byte) int {
	for i, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "condition:") {
			return i + 1
		}
	}
	return 1
}
