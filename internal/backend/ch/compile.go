package ch

import (
	"errors"
	"fmt"
	"strings"

	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/sigma/ast"
	"github.com/atontalapur/signalman/internal/sigma/match"
)

// Rejection codes. The set is closed and machine-readable: a caller
// classifies on Code, never on Reason, which quotes the rule.
const (
	// CodeUnbound is an Ident or Quant left in the tree. A loaded rule never
	// has one; a hand-built tree might.
	CodeUnbound = "unbound-node"
	// CodeUnknownNode is a node type this compiler does not know, or nil.
	CodeUnknownNode = "unknown-node"
	// CodeNoSource is a predicate that does not carry the detection entry
	// it was built from (Pred.Mods and Pred.Vals), so its matcher is an
	// opaque closure with nothing to compile.
	CodeNoSource = "pred-without-source"
	// CodePlan is a predicate whose entry match.Plan rejects. A loaded rule
	// never has one.
	CodePlan = "plan"
	// CodeRegex is a regex that has no RE2 rendering.
	CodeRegex = "regex"
	// CodeTooLarge is a query over MaxQueryBytes.
	CodeTooLarge = "too-large"
)

// MaxQueryBytes is ClickHouse's default max_query_size. A larger WHERE
// clause would be refused by a stock server, so it is refused here, with a
// code, instead of failing at run time. The usual cause is a windash value
// expanded to thousands of variants.
const MaxQueryBytes = 256 << 10

// Rejection is a rule or tree this backend cannot express exactly.
type Rejection struct {
	RuleID string
	Code   string
	Reason string
}

func (r *Rejection) Error() string {
	if r.RuleID == "" {
		return fmt.Sprintf("ch: [%s] %s", r.Code, r.Reason)
	}
	return fmt.Sprintf("ch: rule %s: [%s] %s", r.RuleID, r.Code, r.Reason)
}

func reject(code, format string, args ...any) *Rejection {
	return &Rejection{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// CompileRule returns the WHERE expression that selects the events r
// matches: the logsource test and the condition, as v1 evaluates them.
func CompileRule(r *sigma.Rule) (string, error) {
	where, err := compileRule(r)
	if err != nil {
		var rj *Rejection
		if errors.As(err, &rj) {
			rj.RuleID = r.ID
		}
		return "", err
	}
	return where, nil
}

func compileRule(r *sigma.Rule) (string, error) {
	cond, err := Compile(r.Cond)
	if err != nil {
		return "", err
	}
	where := cond
	if r.LogSource.Node != nil {
		ls, err := Compile(r.LogSource.Node)
		if err != nil {
			return "", err
		}
		where = "(" + ls + ") AND (" + cond + ")"
	}
	if len(where) > MaxQueryBytes {
		return "", reject(CodeTooLarge, "the WHERE clause is %d bytes, over the %d byte limit", len(where), MaxQueryBytes)
	}
	return where, nil
}

// Compile returns the WHERE expression for a bound tree.
func Compile(n ast.Node) (string, error) {
	var b strings.Builder
	if err := emit(&b, n); err != nil {
		return "", err
	}
	if b.Len() > MaxQueryBytes {
		return "", reject(CodeTooLarge, "the WHERE clause is %d bytes, over the %d byte limit", b.Len(), MaxQueryBytes)
	}
	return b.String(), nil
}

func emit(b *strings.Builder, n ast.Node) error {
	switch n := n.(type) {
	case *ast.And:
		return emitJunction(b, n.Children, " AND ", "1")
	case *ast.Or:
		return emitJunction(b, n.Children, " OR ", "0")
	case *ast.Not:
		b.WriteString("NOT (")
		if err := emit(b, n.Child); err != nil {
			return err
		}
		b.WriteString(")")
		return nil
	case *ast.Pred:
		return emitPred(b, n)
	case *ast.Ident:
		return reject(CodeUnbound, "identifier %q was never bound to a selection", n.Name)
	case *ast.Quant:
		return reject(CodeUnbound, "quantifier was never expanded")
	case nil:
		return reject(CodeUnknownNode, "nil node")
	}
	return reject(CodeUnknownNode, "node type %T", n)
}

// emitJunction writes an AND or OR. The empty forms are the identities
// ast.Eval returns for them.
func emitJunction(b *strings.Builder, kids []ast.Node, op, empty string) error {
	if len(kids) == 0 {
		b.WriteString(empty)
		return nil
	}
	for i, k := range kids {
		if i > 0 {
			b.WriteString(op)
		}
		b.WriteString("(")
		if err := emit(b, k); err != nil {
			return err
		}
		b.WriteString(")")
	}
	return nil
}

func emitPred(b *strings.Builder, p *ast.Pred) error {
	if p.Keyword {
		return emitKeyword(b, p)
	}
	if len(p.Vals) == 0 {
		return reject(CodeNoSource, "predicate %q carries no detection entry", p.Desc)
	}
	spec, err := match.Plan(p.Mods, p.Vals)
	if err != nil {
		return reject(CodePlan, "predicate %q: %v", p.Desc, err)
	}
	if spec.All {
		parts := make([]string, 0, len(spec.Values))
		for _, v := range spec.Values {
			s, err := valueSQL(p.Field, v)
			if err != nil {
				return err
			}
			parts = append(parts, s)
		}
		b.WriteString(join(parts, " AND "))
		return nil
	}
	// An OR across values: every pattern value shares one hasAny and one
	// arrayExists, in value order, ahead of the other kinds.
	var patterns, parts []string
	for _, v := range spec.Values {
		if v.Kind == match.SpecPattern {
			patterns = append(patterns, v.Patterns...)
			continue
		}
		s, err := valueSQL(p.Field, v)
		if err != nil {
			return err
		}
		parts = append(parts, s)
	}
	if len(patterns) > 0 {
		parts = append([]string{patternsSQL(colFolded+"["+quote(p.Field)+"]", patterns)}, parts...)
	}
	b.WriteString(join(parts, " OR "))
	return nil
}

// emitKeyword is a bare keyword: contains over every text value of every
// field, which is what v1's keyword matcher walks.
func emitKeyword(b *strings.Builder, p *ast.Pred) error {
	if len(p.Vals) != 1 {
		return reject(CodeNoSource, "keyword %q carries %d values, want 1", p.Desc, len(p.Vals))
	}
	spec, err := match.Plan([]string{"contains"}, p.Vals)
	if err != nil {
		return reject(CodePlan, "keyword %q: %v", p.Desc, err)
	}
	b.WriteString(patternsSQL("arrayFlatten(mapValues("+colFolded+"))", spec.Values[0].Patterns))
	return nil
}

func valueSQL(field string, v match.ValueSpec) (string, error) {
	f := quote(field)
	switch v.Kind {
	case match.SpecNull:
		return "NOT has(" + colPresent + ", " + f + ")", nil
	case match.SpecPattern:
		return patternsSQL(colFolded+"["+f+"]", v.Patterns), nil
	case match.SpecRegex:
		pat, err := re2Pattern(v.Regex.String())
		if err != nil {
			return "", reject(CodeRegex, "field %q: %v", field, err)
		}
		return "arrayExists(x -> match(x, " + quote(pat) + "), " + colText + "[" + f + "])", nil
	case match.SpecCIDR:
		lo, hi := prefixRange(v.Prefix)
		return "arrayExists(x -> x >= " + quote(lo) + " AND x <= " + quote(hi) + ", " + colIPs + "[" + f + "])", nil
	case match.SpecCompare:
		op := map[string]string{"lt": "<", "lte": "<=", "gt": ">", "gte": ">="}[v.Op]
		if op == "" {
			return "", reject(CodePlan, "field %q: unknown comparison %q", field, v.Op)
		}
		return "arrayExists(x -> x " + op + " " + int64Lit(v.N) + ", " + colInts + "[" + f + "])", nil
	case match.SpecFieldRef:
		return "hasAny(" + colEqFold + "[" + f + "], " + colEqFold + "[" + quote(v.Field) + "])", nil
	}
	return "", reject(CodePlan, "field %q: unknown value kind %d", field, v.Kind)
}

// patternsSQL is an OR of Sigma wildcard patterns over an Array(String) of
// folded texts. Patterns without a wildcard become one hasAny, an exact
// byte comparison; the rest share one arrayExists.
func patternsSQL(arr string, patterns []string) string {
	var exact, tests []string
	for _, p := range patterns {
		parts := match.CompileWildcard(p).Parts()
		if lit, ok := exactLiteral(parts); ok {
			exact = append(exact, lit)
			continue
		}
		tests = append(tests, wildcardSQL("x", parts))
	}
	var out []string
	switch len(exact) {
	case 0:
	case 1:
		out = append(out, "has("+arr+", "+quote(exact[0])+")")
	default:
		out = append(out, "hasAny("+arr+", "+quoteList(exact)+")")
	}
	if len(tests) > 0 {
		out = append(out, "arrayExists(x -> "+join(tests, " OR ")+", "+arr+")")
	}
	return join(out, " OR ")
}

func exactLiteral(parts []match.WildcardPart) (string, bool) {
	switch {
	case len(parts) == 0:
		return "", true
	case len(parts) == 1 && parts[0].Kind == match.PartLiteral:
		return parts[0].Lit, true
	}
	return "", false
}

// wildcardSQL tests one folded text x against a pattern with at least one
// wildcard. The shapes the corpus is made of compile to byte functions on
// valid UTF-8, where a byte match is a rune match; anything else is LIKE,
// whose _ is one code point on valid UTF-8, which is what ? means.
func wildcardSQL(x string, parts []match.WildcardPart) string {
	isLit := func(i int) bool { return parts[i].Kind == match.PartLiteral }
	isAny := func(i int) bool { return parts[i].Kind == match.PartAny }
	switch {
	case len(parts) == 1 && isAny(0):
		return "1"
	case len(parts) == 2 && isLit(0) && isAny(1):
		return "startsWith(" + x + ", " + quote(parts[0].Lit) + ")"
	case len(parts) == 2 && isAny(0) && isLit(1):
		return "endsWith(" + x + ", " + quote(parts[1].Lit) + ")"
	case len(parts) == 3 && isAny(0) && isLit(1) && isAny(2):
		return "position(" + x + ", " + quote(parts[1].Lit) + ") > 0"
	}
	return x + " LIKE " + quote(likePattern(parts))
}

func likePattern(parts []match.WildcardPart) string {
	var b strings.Builder
	for _, p := range parts {
		switch p.Kind {
		case match.PartAny:
			b.WriteByte('%')
		case match.PartOne:
			b.WriteByte('_')
		default:
			for i := 0; i < len(p.Lit); i++ {
				if c := p.Lit[i]; c == '%' || c == '_' || c == '\\' {
					b.WriteByte('\\')
				}
				b.WriteByte(p.Lit[i])
			}
		}
	}
	return b.String()
}

func join(parts []string, op string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, ")"+op+"(") + ")"
}
