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
// event fills a lazily evaluated bitset of predicate results, so a
// predicate shared by forty rules is evaluated at most once per event.
//
// Before any tree is walked, two cheaper tests can settle a rule as false:
// field presence gating (a bitset AND of the rule's required fields against
// the fields the event has) and the literal prefilter (an Aho-Corasick scan
// for the literals the rule requires). Both are necessary conditions for a
// match, never sufficient ones.
//
// A Program is read-only after Compile. Per-event state lives in a scratch
// the evaluator owns for the length of one call.
type Program struct {
	// Preds is deduplicated: no two entries share a Key.
	Preds []Pred
	// ByField maps an event field name to the indices of the predicates
	// that read it, in ascending order. Keyword predicates read every field
	// and are listed under "".
	ByField map[string][]int
	// Trees is one per rule, in rule set order, which is rule id order.
	Trees []Tree
	// Always lists, by index into Trees, the rules with no derivable
	// required literal: the prefilter admits them on every event.
	Always []int

	// fields is the field table: every field a non-keyword predicate
	// reads, in first-use order. Presence bitsets, required-field masks,
	// and prefilter slots all index it.
	fields   []string
	fieldIdx map[string]int32
	// reqMask holds each rule's required fields as fieldWords words.
	reqMask    []uint64
	fieldWords int

	cpreds []cpred
	reqs   [][]Literal // per rule, the prefilter alternatives
	lits   []string
	pf     *prefilter
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
	// Desc is the first interned leaf's display form, for explain output.
	Desc string
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
// not bind, or a leaf whose modifier chain no longer plans, both of which
// are programming errors upstream rather than bad input.
func Compile(rs *sigma.RuleSet) (*Program, error) {
	c := &compiler{
		p:     &Program{ByField: map[string][]int{}, fieldIdx: map[string]int32{}},
		index: map[string]int{},
	}
	p := c.p
	p.Trees = make([]Tree, 0, len(rs.Rules))
	full := make([]ast.Node, 0, len(rs.Rules))
	for i := range rs.Rules {
		r := &rs.Rules[i]
		root := r.Cond
		if r.LogSource.Node != nil {
			// v1 tests the logsource and only then walks the condition; a
			// conjunction with the logsource first is the same function.
			root = &ast.And{Children: []ast.Node{r.LogSource.Node, r.Cond}}
		}
		idx, err := c.node(root)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		p.Trees = append(p.Trees, Tree{RuleID: r.ID, Root: idx})
		full = append(full, root)
	}

	p.fieldWords = (len(p.fields) + 63) / 64
	p.reqMask = make([]uint64, len(rs.Rules)*p.fieldWords)
	for i, root := range full {
		for _, f := range requiredFields(root) {
			fi := p.fieldIdx[f] // every required field is a predicate field
			p.reqMask[i*p.fieldWords+int(fi>>6)] |= 1 << (uint(fi) & 63)
		}
	}

	if err := c.buildPrefilter(rs); err != nil {
		return nil, err
	}
	return p, nil
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
		i, err := c.intern(n)
		if err != nil {
			return 0, err
		}
		return c.emit(node{op: opPred, a: int32(i)}), nil
	}
	return 0, fmt.Errorf("unbound node %T", n)
}

func (c *compiler) field(name string) int32 {
	if fi, ok := c.p.fieldIdx[name]; ok {
		return fi
	}
	fi := int32(len(c.p.fields))
	c.p.fields = append(c.p.fields, name)
	c.p.fieldIdx[name] = fi
	return fi
}

func (c *compiler) intern(p *ast.Pred) (int, error) {
	key := predKey(p)
	if i, ok := c.index[key]; ok {
		return i, nil
	}
	fi := int32(-1)
	if !p.Keyword {
		fi = c.field(p.Field)
	}
	cp, err := compilePred(p, fi)
	if err != nil {
		return 0, err
	}
	i := len(c.p.Preds)
	c.p.Preds = append(c.p.Preds, Pred{Field: p.Field, Key: key, Desc: p.Desc})
	c.p.cpreds = append(c.p.cpreds, cp)
	c.index[key] = i
	c.p.ByField[p.Field] = append(c.p.ByField[p.Field], i)
	return i, nil
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
