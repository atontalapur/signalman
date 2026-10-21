package v2

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/sigma/ast"
)

// Program is a rule set compiled for evaluation. Every leaf predicate in
// every rule, logsource tests included, is interned once into Preds; each
// rule's condition becomes a Tree whose leaves are indices into Preds. An
// event fills a bitset of predicate results lazily, so a predicate shared by
// forty rules is evaluated at most once per event.
//
// A Program is read-only after Compile. Per-event state lives in a scratch
// the evaluator owns per call.
type Program struct {
	// Preds is deduplicated: no two entries share a Key.
	Preds []Pred
	// ByField maps an event field name to the indices of the predicates
	// that read it, in ascending order. Keyword predicates read every field
	// and are listed under "".
	ByField map[string][]int
	// Trees is one per rule, in rule set order, which is rule id order.
	Trees []Tree

	nodes  []node
	kids   []int32
	leaves int
}

// Pred is one interned leaf.
type Pred struct {
	Field string
	// Key is the canonical form the table is deduplicated on. Two leaves
	// with equal keys are built from the same field, keyword flag,
	// modifier chain, and values, and so have the same matcher.
	Key string
	src *ast.Pred
}

// Tree is one rule's compiled condition, with the logsource test folded in
// as the first conjunct.
type Tree struct {
	RuleID string
	Root   int32
}

type op uint8

const (
	opPred op = iota
	opAnd
	opOr
	opNot
)

// node is one tree node. For opPred, a is the predicate index; for opAnd
// and opOr, kids[a:b] are the children; for opNot, a is the child.
type node struct {
	op   op
	a, b int32
}

// Compile builds the program. It fails only on a tree the rule loader did
// not bind, which is a programming error upstream rather than bad input.
func Compile(rs *sigma.RuleSet) (*Program, error) {
	c := &compiler{
		p:     &Program{ByField: map[string][]int{}},
		index: map[string]int{},
	}
	c.p.Trees = make([]Tree, 0, len(rs.Rules))
	for i := range rs.Rules {
		r := &rs.Rules[i]
		cond, err := c.node(r.Cond)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		root := cond
		if r.LogSource.Node != nil {
			// v1 tests the logsource and only then walks the condition;
			// a conjunction with the logsource first is the same function.
			ls, err := c.node(r.LogSource.Node)
			if err != nil {
				return nil, fmt.Errorf("rule %s logsource: %w", r.ID, err)
			}
			root = c.list(opAnd, []int32{ls, cond})
		}
		c.p.Trees = append(c.p.Trees, Tree{RuleID: r.ID, Root: root})
	}
	return c.p, nil
}

// Leaves is the number of leaf predicates before interning, so the table
// size can be reported against it.
func (p *Program) Leaves() int { return p.leaves }

type compiler struct {
	p     *Program
	index map[string]int
}

func (c *compiler) emit(n node) int32 {
	c.p.nodes = append(c.p.nodes, n)
	return int32(len(c.p.nodes) - 1)
}

func (c *compiler) list(o op, kids []int32) int32 {
	start := int32(len(c.p.kids))
	c.p.kids = append(c.p.kids, kids...)
	return c.emit(node{op: o, a: start, b: int32(len(c.p.kids))})
}

func (c *compiler) node(n ast.Node) (int32, error) {
	switch n := n.(type) {
	case *ast.And, *ast.Or:
		var kids []ast.Node
		o := opAnd
		if a, ok := n.(*ast.And); ok {
			kids = a.Children
		} else {
			kids = n.(*ast.Or).Children
			o = opOr
		}
		idx := make([]int32, 0, len(kids))
		for _, k := range kids {
			i, err := c.node(k)
			if err != nil {
				return 0, err
			}
			idx = append(idx, i)
		}
		return c.list(o, idx), nil
	case *ast.Not:
		ch, err := c.node(n.Child)
		if err != nil {
			return 0, err
		}
		return c.emit(node{op: opNot, a: ch}), nil
	case *ast.Pred:
		c.p.leaves++
		return c.emit(node{op: opPred, a: int32(c.intern(n))}), nil
	}
	return 0, fmt.Errorf("unbound node %T", n)
}

func (c *compiler) intern(p *ast.Pred) int {
	key := predKey(p)
	if i, ok := c.index[key]; ok {
		return i
	}
	i := len(c.p.Preds)
	c.p.Preds = append(c.p.Preds, Pred{Field: p.Field, Key: key, src: p})
	c.index[key] = i
	c.p.ByField[p.Field] = append(c.p.ByField[p.Field], i)
	return i
}

// predKey is the canonical form of a leaf. Every string is quoted, so a
// value containing a separator cannot make two different leaves collide,
// which Desc alone would allow ("a', 'b" against "a", "b"). The value kind
// is kept even though string matchers compare on text: a key that is too
// fine only costs a duplicate predicate, one that is too coarse merges two
// different tests.
func predKey(p *ast.Pred) string {
	var b strings.Builder
	b.WriteString(strconv.Quote(p.Field))
	if p.Keyword {
		b.WriteString(" kw")
	}
	b.WriteString(" m")
	for _, m := range p.Mods {
		b.WriteByte(' ')
		b.WriteString(strconv.Quote(m))
	}
	b.WriteString(" v")
	for _, v := range p.Vals {
		b.WriteByte(' ')
		b.WriteString(strconv.Itoa(int(v.Kind)))
		if s, ok := v.Text(); ok {
			b.WriteString(strconv.Quote(s))
		}
	}
	return b.String()
}
