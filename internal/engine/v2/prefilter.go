package v2

import (
	"fmt"

	"github.com/atontalapur/signalman/internal/engine/v2/aho"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/sigma/ast"
	"github.com/atontalapur/signalman/internal/sigma/match"
)

// Literal is one alternative of a rule's prefilter requirement: Text, folded
// to lower case, must occur in the folded text of Field's value (or of one of
// its list elements). A Keyword literal may occur in any field.
type Literal struct {
	Field   string
	Keyword bool
	Text    string
}

// requiredLiterals derives a necessary condition for n to be true, as a set
// of alternatives: if n evaluates true on an event, at least one returned
// literal occurs in that event. An empty result means no such set could be
// derived, and the rule must be evaluated on every event.
//
// Soundness is the only requirement; selectivity is a heuristic. The rules:
//
//   - A leaf yields literals only for wildcard tests (equals, contains,
//     startswith, endswith, with any encoding transform). Each pattern
//     contributes its longest literal run, which every match contains. A
//     regex, cidr, numeric, fieldref, or null test yields nothing, and a
//     leaf with one such value yields nothing at all, because any value can
//     be the one that matched.
//   - A leaf with |all needs every value, so one value's literals suffice.
//   - And needs every child, so the best child's set suffices. This is the
//     conjunctive position the literal is harvested from.
//   - Or needs some child, so it yields the union of its children's sets,
//     and nothing if any child has none.
//   - Not yields nothing, ever. A literal under a negation is evidence the
//     rule did not match, not that it might have.
func requiredLiterals(n ast.Node) []Literal {
	switch n := n.(type) {
	case *ast.And:
		var best []Literal
		for _, c := range n.Children {
			if ls := requiredLiterals(c); better(ls, best) {
				best = ls
			}
		}
		return best
	case *ast.Or:
		var out []Literal
		for _, c := range n.Children {
			ls := requiredLiterals(c)
			if len(ls) == 0 {
				return nil
			}
			out = append(out, ls...)
		}
		return out
	case *ast.Pred:
		return predLiterals(n)
	}
	return nil // Not, and anything unbound
}

// better prefers the set whose shortest literal is longest, then the
// smaller set. A short literal admits more events; so does a set with more
// alternatives.
func better(a, b []Literal) bool {
	if len(a) == 0 {
		return false
	}
	if len(b) == 0 {
		return true
	}
	ma, mb := minLen(a), minLen(b)
	if ma != mb {
		return ma > mb
	}
	return len(a) < len(b)
}

func minLen(ls []Literal) int {
	m := len(ls[0].Text)
	for _, l := range ls[1:] {
		m = min(m, len(l.Text))
	}
	return m
}

func predLiterals(p *ast.Pred) []Literal {
	mods := p.Mods
	if p.Keyword {
		// A keyword is Contains over every field value; planning it as a
		// contains entry yields exactly the pattern its matcher was built
		// from.
		mods = []string{"contains"}
	}
	spec, err := match.Plan(mods, p.Vals)
	if err != nil {
		// The loader built this leaf from the same chain, so it cannot
		// fail here. If it somehow does, no literal is the safe answer.
		return nil
	}
	perValue := make([][]Literal, 0, len(spec.Values))
	for _, v := range spec.Values {
		ls := valueLiterals(p, v)
		if len(ls) == 0 && !spec.All {
			return nil
		}
		perValue = append(perValue, ls)
	}
	if spec.All {
		var best []Literal
		for _, ls := range perValue {
			if better(ls, best) {
				best = ls
			}
		}
		return best
	}
	var out []Literal
	for _, ls := range perValue {
		out = append(out, ls...)
	}
	return out
}

func valueLiterals(p *ast.Pred, v match.ValueSpec) []Literal {
	if v.Kind != match.SpecPattern {
		return nil
	}
	out := make([]Literal, 0, len(v.Patterns))
	for _, pat := range v.Patterns {
		longest := ""
		for _, run := range match.CompileWildcard(pat).Literals() {
			if len(run) > len(longest) {
				longest = run
			}
		}
		if longest == "" {
			return nil
		}
		out = append(out, Literal{Field: p.Field, Keyword: p.Keyword, Text: longest})
	}
	return out
}

// slot says a literal hit admits rule when found in field (an index into
// the program's field table, or -1 for a keyword literal, found anywhere).
type slot struct {
	field int32
	rule  int32
}

// prefilter is the compiled literal index.
type prefilter struct {
	filter  *aho.Matcher // nil when no rule has a literal
	lits    []string
	slots   [][]slot // per literal id
	keyword bool     // some literal is a keyword literal
	always  []uint64
}

// buildPrefilter derives each rule's literals from its condition and, only
// when the condition yields none, from its logsource. The logsource literal
// (a channel name) is true of every event on that channel, so it is a weak
// key, but it is sound and keeps a regex-only rule off other channels.
func (c *compiler) buildPrefilter(rs *sigma.RuleSet) error {
	p := c.p
	pf := &prefilter{}
	litID := map[string]int32{}
	p.reqs = make([][]Literal, len(rs.Rules))
	for i := range rs.Rules {
		r := &rs.Rules[i]
		ls := requiredLiterals(r.Cond)
		if len(ls) == 0 && r.LogSource.Node != nil {
			ls = requiredLiterals(r.LogSource.Node)
		}
		p.reqs[i] = ls
		if len(ls) == 0 {
			p.Always = append(p.Always, i)
			continue
		}
		for _, l := range ls {
			id, ok := litID[l.Text]
			if !ok {
				id = int32(len(pf.lits))
				litID[l.Text] = id
				pf.lits = append(pf.lits, l.Text)
				pf.slots = append(pf.slots, nil)
			}
			f := int32(-1)
			if l.Keyword {
				pf.keyword = true
			} else {
				// A literal comes from a leaf, so its field is in the
				// program's field table.
				f = p.fieldIdx[l.Field]
			}
			pf.slots[id] = append(pf.slots[id], slot{field: f, rule: int32(i)})
		}
	}
	pf.always = make([]uint64, (len(rs.Rules)+63)/64)
	for _, i := range p.Always {
		pf.always[i>>6] |= 1 << (uint(i) & 63)
	}
	if len(pf.lits) > 0 {
		m, err := aho.New(pf.lits)
		if err != nil {
			return fmt.Errorf("prefilter: %w", err)
		}
		pf.filter = m
	}
	p.pf = pf
	p.lits = pf.lits
	return nil
}

// AlwaysSize is how many rules the prefilter can never skip: rules with no
// derivable required literal. It is a metric to watch, because every rule
// in it is walked for every event.
func (p *Program) AlwaysSize() int { return len(p.Always) }

// scanSpan runs one folded scalar of field fi (-1 for a field no predicate
// names) through the automaton and admits every rule whose literal it holds
// in the field the literal is required in.
func (s *scratch) scanSpan(fi int32, text []byte) {
	pf := s.p.pf
	s.hits = pf.filter.Scan(text, s.hits[:0])
	for _, id := range s.hits {
		// A literal found twice in one field admits the same rules twice;
		// skip the repeat.
		if s.litEpoch[id] == s.epoch && s.litField[id] == fi {
			continue
		}
		s.litEpoch[id], s.litField[id] = s.epoch, fi
		for _, sl := range pf.slots[id] {
			if sl.field == -1 || (fi >= 0 && sl.field == fi) {
				s.cand[sl.rule>>6] |= 1 << (uint(sl.rule) & 63)
			}
		}
	}
}

func (s *scratch) candidate(rule int) bool {
	return s.cand[rule>>6]&(1<<(uint(rule)&63)) != 0
}
