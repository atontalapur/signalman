package sigma

import (
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/event"
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
	Tags   []string
	// Budget is the rule's declared noise budget in matches per 100,000
	// events, or nil when it declares none. It is checked by signalman
	// noise and has no effect on evaluation or on RuleSetV.
	Budget *float64

	// Condition and Selections keep the selection names that binding
	// erases, for explain output. Condition is the expanded condition with
	// an ast.Ident where each selection goes; Selections maps each name to
	// its field-renamed subtree. Substituting one into the other gives Cond.
	// Condition is never evaluated: ast.Eval panics on an Ident, and Cond
	// is the tree every engine walks.
	Condition  ast.Node
	Selections map[string]ast.Node
}

// Error codes carried by LoadError. The set is closed: the corpus acceptance
// report has one paragraph per code stating whether the rejection is
// intended, so a new code is a documentation change too.
const (
	CodeYAML        = "yaml"
	CodeMissingID   = "missing-id"
	CodeInvalidID   = "invalid-id"
	CodeLevel       = "level"
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
	// Err is the underlying cause when there is one, so a caller can
	// classify by type instead of by Reason, which quotes the rule.
	Err error
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("%s:%d [%s] rule %s: %s", e.Path, e.Line, e.Code, e.RuleID, e.Reason)
}

func (e *LoadError) Unwrap() error { return e.Err }

type ruleFile struct {
	Title  string `yaml:"title"`
	ID     string `yaml:"id"`
	Status string `yaml:"status"`
	Level  string `yaml:"level"`
	// Tags is decoded loosely: tags are display metadata, and a malformed
	// tag list must not change which rules load.
	Tags any `yaml:"tags"`
	// Budget is validated by budgetValue rather than by the decoder, so a
	// bad value gets a reason and a line instead of a decode error.
	Budget    any `yaml:"budget"`
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
	// A UUID's hex is case insensitive, and macOS uuidgen writes upper
	// case. The id is lowered here, before anything compares, hashes, or
	// reports it, so the duplicate check, RuleSetV, verdicts, and alerts all
	// see one spelling. Two rules whose ids differ only in case would
	// otherwise both load and write the same alerts row.
	if canonicalUUID(f.ID) {
		f.ID = strings.ToLower(f.ID)
	}
	budget, err := budgetValue(f.Budget)
	if err != nil {
		return nil, fail(CodeYAML, err.Error(), keyLine(src, "budget:"))
	}

	condLine := keyLine(src, "condition:")
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
		lerr := fail(code, err.Error(), 1)
		lerr.Err = err
		return nil, lerr
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
	// The id and level are checked after everything about the engine and
	// before the taxonomy, for the same reason the taxonomy is last: a rule
	// with an aggregation pipe and no level still reports "aggregation".
	// The alerts table holds rule_id as a UUID and severity as an enum of
	// the five Sigma levels, so a rule outside either would load, match, and
	// produce alerts no insert can store.
	if !canonicalUUID(f.ID) {
		return nil, fail(CodeInvalidID, fmt.Sprintf("id %q is not a UUID in the 8-4-4-4-12 hex form", f.ID), keyLine(src, "id:"))
	}
	if !Levels[f.Level] {
		reason := "rule has no level; want one of informational, low, medium, high, critical"
		if f.Level != "" {
			reason = fmt.Sprintf("level %q is not one of informational, low, medium, high, critical", f.Level)
		}
		return nil, fail(CodeLevel, reason, keyLine(src, "level:"))
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
	named := make(map[string]ast.Node, len(names))
	for _, name := range names {
		named[name] = renameNode(sels[name], entry.Fields, map[string]bool{})
	}

	return &Rule{
		ID:         f.ID,
		Title:      f.Title,
		Level:      f.Level,
		Status:     f.Status,
		Path:       path,
		LogSource:  tax.MatcherFor(entry),
		Cond:       renamed,
		Fields:     fields,
		Tags:       tagList(f.Tags),
		Budget:     budget,
		Condition:  cond,
		Selections: named,
	}, nil
}

// Levels are the Sigma rule levels, spelled as the spec spells them. They
// are the values the alerts table's severity enum accepts.
var Levels = map[string]bool{
	"informational": true, "low": true, "medium": true, "high": true, "critical": true,
}

// canonicalUUID reports whether s is a UUID in the 36-character hyphenated
// form, hex digits in either case. Braces, a urn:uuid: prefix, and the
// 32-digit form are refused: a rule id is compared as a string everywhere,
// so it has one spelling, and LoadRuleBytes lowers the hex to give it one.
func canonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// tagList keeps the string items of a tag list and ignores anything else.
func tagList(raw any) []string {
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
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
		out := &ast.Pred{
			Field: field, Desc: n.Desc, Key: n.Key, M: n.M,
			Mods: n.Mods, Vals: n.Vals, Keyword: n.Keyword,
		}
		if slices.Contains(n.Mods, "fieldref") {
			renameFieldRef(out, mapping, seen)
		}
		return out
	}
	return n
}

// renameFieldRef maps a fieldref predicate's values, which are Sigma field
// names, through the same mapping as its field, then rebuilds M and Key
// from the renamed values so every engine reads the event field. Desc keeps
// the names as written, like the field it describes.
func renameFieldRef(p *ast.Pred, mapping map[string]string, seen map[string]bool) {
	vals := make([]event.Value, len(p.Vals))
	for i, v := range p.Vals {
		vals[i] = v
		name, ok := v.Text()
		if !ok {
			continue
		}
		if to, ok := mapping[name]; ok && to != "" {
			name = to
			vals[i] = event.String(name)
		}
		seen[name] = true
	}
	m, err := match.Build(p.Mods, vals)
	if err != nil {
		// Build accepted these mods over string values at compile time,
		// and renaming only swaps one string for another.
		panic(fmt.Sprintf("sigma: rebuilding renamed fieldref: %v", err))
	}
	p.Vals, p.M, p.Key = vals, m, predKey(p.Mods, vals)
}

// keyLine finds the 1-based line of the first line starting with key, so
// the error points at something an author can open.
func keyLine(src []byte, key string) int {
	for i, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), key) {
			return i + 1
		}
	}
	return 1
}

// budgetValue reads the optional budget key: a finite, non-negative number
// of matches per 100,000 events. Anything else is an author error, reported
// rather than read as no budget, since a budget that silently never applies
// is a noise gate that never closes.
func budgetValue(raw any) (*float64, error) {
	var b float64
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case int:
		b = float64(v)
	case int64:
		b = float64(v)
	case uint64:
		b = float64(v)
	case float64:
		b = v
	default:
		return nil, fmt.Errorf("budget must be a number of matches per 100k events, got %T", raw)
	}
	if math.IsNaN(b) || math.IsInf(b, 0) || b < 0 {
		return nil, fmt.Errorf("budget must be a finite, non-negative number of matches per 100k events, got %v", b)
	}
	return &b, nil
}
