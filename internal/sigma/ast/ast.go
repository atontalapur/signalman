// Package ast holds the evaluable rule tree. After binding, a tree contains
// only And, Or, Not, and Pred. Ident and Quant exist between parsing and
// expansion and never reach an evaluator.
package ast

import (
	"fmt"
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/event"
)

type Node interface{ node() }

type And struct{ Children []Node }
type Or struct{ Children []Node }
type Not struct{ Child Node }
type Ident struct{ Name string }

type QuantCount uint8

const (
	QuantOne QuantCount = iota // "1" and "any"
	QuantAll
)

type Quant struct {
	Count   QuantCount
	Pattern string // selection name glob, empty when Them is set
	Them    bool
}

// Matcher tests one field value. The event is passed because fieldref
// compares two fields on the same event. It has the same shape as
// match.Matcher so match values satisfy it without match importing ast.
type Matcher interface {
	Match(v event.Value, ev *event.Event) bool
}

// Pred is a leaf. Desc is the human-readable form used by explain output.
type Pred struct {
	Field string
	Desc  string
	M     Matcher
}

func (*And) node()   {}
func (*Or) node()    {}
func (*Not) node()   {}
func (*Ident) node() {}
func (*Quant) node() {}
func (*Pred) node()  {}

// Match reads the field, treating absence as null so that a null matcher
// matches both an absent field and an explicit null.
func (p *Pred) Match(ev *event.Event) bool {
	return p.M.Match(ev.Field(p.Field), ev)
}

// Eval is the single tree walker for a bound tree. Ident and Quant are a
// programming error at this point (binding was skipped), not bad input, so
// they panic rather than push an unreachable error branch into every
// evaluator.
func Eval(n Node, ev *event.Event) bool {
	switch n := n.(type) {
	case *And:
		for _, c := range n.Children {
			if !Eval(c, ev) {
				return false
			}
		}
		return true
	case *Or:
		for _, c := range n.Children {
			if Eval(c, ev) {
				return true
			}
		}
		return false
	case *Not:
		return !Eval(n.Child, ev)
	case *Pred:
		return n.Match(ev)
	}
	panic(fmt.Sprintf("ast.Eval: unbound node %T", n))
}

// String renders a node in a stable s-expression form. Used by tests and by
// the explain command. It never sorts children, because child order is
// already deterministic by construction.
func String(n Node) string {
	var b strings.Builder
	write(&b, n, false)
	return b.String()
}

// Canonical is String with every name and description quoted, so a string
// containing a space or a parenthesis cannot collide with the tree
// structure. Use it for hashing, never for display.
func Canonical(n Node) string {
	var b strings.Builder
	write(&b, n, true)
	return b.String()
}

func write(b *strings.Builder, n Node, quote bool) {
	str := func(s string) string {
		if quote {
			return fmt.Sprintf("%q", s)
		}
		return s
	}
	switch n := n.(type) {
	case *And:
		writeList(b, "and", n.Children, quote)
	case *Or:
		writeList(b, "or", n.Children, quote)
	case *Not:
		b.WriteString("(not ")
		write(b, n.Child, quote)
		b.WriteString(")")
	case *Ident:
		b.WriteString(str(n.Name))
	case *Quant:
		if n.Count == QuantAll {
			b.WriteString("(allof ")
		} else {
			b.WriteString("(1of ")
		}
		if n.Them {
			b.WriteString("them")
		} else {
			b.WriteString(str(n.Pattern))
		}
		b.WriteString(")")
	case *Pred:
		b.WriteString("[" + str(n.Desc) + "]")
	default:
		b.WriteString("?")
	}
}

func writeList(b *strings.Builder, op string, kids []Node, quote bool) {
	b.WriteString("(" + op)
	for _, k := range kids {
		b.WriteString(" ")
		write(b, k, quote)
	}
	b.WriteString(")")
}

// SortedNames returns map keys in a fixed order. Every tree construction
// path uses it, because Go map iteration order would otherwise leak into
// the shape of the tree and break determinism.
func SortedNames(m map[string]Node) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
