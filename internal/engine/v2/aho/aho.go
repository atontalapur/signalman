// Package aho is an Aho-Corasick automaton over bytes: one pass over a text
// reports every occurrence of every pattern.
//
// It is written here rather than imported. The prefilter needs three things
// the common Go packages do not give together: a scan that allocates
// nothing in steady state (hits go into a caller-owned buffer), every
// overlapping occurrence rather than leftmost-longest, and a build whose
// state numbering depends only on the pattern order, so the program is
// reproducible. The automaton is about a hundred lines, and its tests
// compare it against bytes.Contains on random and fuzzed input.
package aho

import (
	"errors"
	"fmt"
	"sort"
)

// Matcher is immutable after New and safe for concurrent Scan calls.
type Matcher struct {
	// root is the dense transition table of the start state, where most
	// scan steps land on text that matches nothing.
	root [256]int32
	// Edges of state s are edgeByte/edgeTo[edgeStart[s]:edgeStart[s+1]],
	// sorted by byte.
	edgeStart []int32
	edgeByte  []byte
	edgeTo    []int32
	fail      []int32
	// out is the pattern ending exactly at a state, or -1. dict is the
	// nearest state down the failure chain whose out is set, or -1.
	out  []int32
	dict []int32
}

// New builds the automaton. Patterns must be non-empty and distinct; a
// pattern's id is its index.
func New(patterns []string) (*Matcher, error) {
	type tnode struct {
		next map[byte]int32
		out  int32
	}
	nodes := []tnode{{next: map[byte]int32{}, out: -1}}
	for id, p := range patterns {
		if p == "" {
			return nil, errors.New("aho: empty pattern")
		}
		s := int32(0)
		for i := 0; i < len(p); i++ {
			nx, ok := nodes[s].next[p[i]]
			if !ok {
				nodes = append(nodes, tnode{next: map[byte]int32{}, out: -1})
				nx = int32(len(nodes) - 1)
				nodes[s].next[p[i]] = nx
			}
			s = nx
		}
		if nodes[s].out >= 0 {
			return nil, fmt.Errorf("aho: duplicate pattern %q", p)
		}
		nodes[s].out = int32(id)
	}

	n := len(nodes)
	m := &Matcher{
		edgeStart: make([]int32, n+1),
		fail:      make([]int32, n),
		out:       make([]int32, n),
		dict:      make([]int32, n),
	}
	// Freeze the trie with sorted edges, so numbering and lookups never
	// depend on map order.
	for s := 0; s < n; s++ {
		m.edgeStart[s] = int32(len(m.edgeByte))
		keys := make([]int, 0, len(nodes[s].next))
		for c := range nodes[s].next {
			keys = append(keys, int(c))
		}
		sort.Ints(keys)
		for _, c := range keys {
			m.edgeByte = append(m.edgeByte, byte(c))
			m.edgeTo = append(m.edgeTo, nodes[s].next[byte(c)])
		}
		m.out[s] = nodes[s].out
	}
	m.edgeStart[n] = int32(len(m.edgeByte))

	// Breadth first, so a state's failure target is always finished
	// before the state itself. Root children fail to the root.
	queue := make([]int32, 0, n)
	for e := m.edgeStart[0]; e < m.edgeStart[1]; e++ {
		child := m.edgeTo[e]
		m.root[m.edgeByte[e]] = child
		m.fail[child] = 0
		queue = append(queue, child)
	}
	m.dict[0] = -1
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		f := m.fail[s]
		if m.out[f] >= 0 {
			m.dict[s] = f
		} else {
			m.dict[s] = m.dict[f]
		}
		for e := m.edgeStart[s]; e < m.edgeStart[s+1]; e++ {
			child := m.edgeTo[e]
			m.fail[child] = m.step(m.fail[s], m.edgeByte[e])
			queue = append(queue, child)
		}
	}
	return m, nil
}

// edge returns the trie child of s on c, or -1.
func (m *Matcher) edge(s int32, c byte) int32 {
	lo, hi := m.edgeStart[s], m.edgeStart[s+1]
	for lo < hi {
		mid := int32(uint32(lo+hi) >> 1)
		switch b := m.edgeByte[mid]; {
		case b == c:
			return m.edgeTo[mid]
		case b < c:
			lo = mid + 1
		default:
			hi = mid
		}
	}
	return -1
}

// step is the automaton transition: follow failure links until an edge on
// c exists, ending at the root's dense table.
func (m *Matcher) step(s int32, c byte) int32 {
	for s != 0 {
		if nx := m.edge(s, c); nx >= 0 {
			return nx
		}
		s = m.fail[s]
	}
	return m.root[c]
}

// Scan appends the id of every pattern occurrence in text to hits and
// returns it. A pattern occurring twice is reported twice.
func (m *Matcher) Scan(text []byte, hits []int32) []int32 {
	s := int32(0)
	for _, c := range text {
		s = m.step(s, c)
		t := s
		if m.out[t] < 0 {
			t = m.dict[t]
		}
		for t >= 0 {
			hits = append(hits, m.out[t])
			t = m.dict[t]
		}
	}
	return hits
}
