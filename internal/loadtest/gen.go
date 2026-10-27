package loadtest

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/sigma/ast"
	"github.com/atontalapur/signalman/internal/sigma/match"
)

// AimedFields builds a deterministic stream of event field maps aimed at
// the rule set: for each rule, perRule events that try to satisfy its
// condition, some perturbed or mixed with another rule's fields. Random
// events would make every verdict false, which hides a lost or duplicated
// match; aiming at the rules keeps true verdicts common.
//
// It is the generator of the v2 equivalence harness
// (internal/engine/v2/harness_test.go) without the edge-case events and
// without Seq: here the broker assigns Seq when the record is produced.
func AimedFields(rs *sigma.RuleSet, perRule int, seed int64) []map[string]event.Value {
	rng := rand.New(rand.NewSource(seed))
	var out []map[string]event.Value
	for i := range rs.Rules {
		r := &rs.Rules[i]
		for range perRule {
			f := map[string]event.Value{}
			if rng.Intn(10) != 0 {
				satisfyLogsource(r, f)
			}
			satisfy(r.Cond, f, rng)
			switch rng.Intn(4) {
			case 0:
				perturb(f, rng)
			case 1:
				o := &rs.Rules[rng.Intn(len(rs.Rules))]
				satisfy(o.Cond, f, rng)
			}
			out = append(out, f)
		}
	}
	return out
}

func satisfyLogsource(r *sigma.Rule, f map[string]event.Value) {
	var walk func(ast.Node)
	walk = func(n ast.Node) {
		switch n := n.(type) {
		case *ast.And:
			for _, c := range n.Children {
				walk(c)
			}
		case *ast.Pred:
			if len(n.Vals) > 0 {
				f[n.Field] = n.Vals[0]
			}
		}
	}
	if r.LogSource.Node != nil {
		walk(r.LogSource.Node)
	}
}

// satisfy writes field values that try to make n true. It is a heuristic,
// not a solver: Or picks one arm, Not is left to chance.
func satisfy(n ast.Node, f map[string]event.Value, rng *rand.Rand) {
	switch n := n.(type) {
	case *ast.And:
		for _, c := range n.Children {
			satisfy(c, f, rng)
		}
	case *ast.Or:
		satisfy(n.Children[rng.Intn(len(n.Children))], f, rng)
	case *ast.Not:
		if rng.Intn(3) == 0 {
			satisfy(n.Child, f, rng)
		}
	case *ast.Pred:
		satisfyPred(n, f, rng)
	}
}

func satisfyPred(p *ast.Pred, f map[string]event.Value, rng *rand.Rand) {
	if len(p.Vals) == 0 {
		return
	}
	if p.Keyword {
		s, _ := p.Vals[0].Text()
		f[fmt.Sprintf("Message%d", rng.Intn(3))] = event.String("pre " + caseFlip(s, rng) + " post")
		return
	}
	var comparison string
	var all, fieldref bool
	var transforms []string
	for _, m := range p.Mods {
		switch m {
		case "contains", "startswith", "endswith", "re", "cidr", "lt", "lte", "gt", "gte":
			comparison = m
		case "all":
			all = true
		case "fieldref":
			fieldref = true
		case "i":
		default:
			transforms = append(transforms, m)
		}
	}
	pick := p.Vals[rng.Intn(len(p.Vals))]
	if pick.Kind == event.KindNull {
		if rng.Intn(2) == 0 {
			delete(f, p.Field)
		} else {
			f[p.Field] = event.Null()
		}
		return
	}
	text, _ := pick.Text()
	if fieldref {
		v := event.String("ref-" + strconv.Itoa(rng.Intn(5)))
		f[p.Field] = v
		f[text] = v
		return
	}
	switch comparison {
	case "cidr":
		if pfx, err := netip.ParsePrefix(text); err == nil {
			f[p.Field] = event.String(pfx.Masked().Addr().String())
		}
		return
	case "lt", "lte", "gt", "gte":
		n, _ := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
		f[p.Field] = event.Int(n + int64(rng.Intn(3)-1))
		return
	case "re":
		f[p.Field] = event.String(strings.Map(func(r rune) rune {
			if strings.ContainsRune(`\^$.|?*+()[]{}`, r) {
				return -1
			}
			return r
		}, text))
		return
	}

	texts := []string{text}
	if all {
		texts = texts[:0]
		for _, v := range p.Vals {
			s, _ := v.Text()
			texts = append(texts, s)
		}
	}
	for i, s := range texts {
		s = unwild(s)
		for _, tr := range transforms {
			s = applyTransform(tr, s, rng)
		}
		texts[i] = caseFlip(s, rng)
	}
	s := strings.Join(texts, " ")
	switch comparison {
	case "contains":
		s = "x" + s + "y"
	case "startswith":
		s += "_tail"
	case "endswith":
		s = "head_" + s
	}
	var v event.Value
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && rng.Intn(2) == 0 {
		v = event.Int(n)
	} else {
		v = event.String(s)
	}
	if rng.Intn(6) == 0 {
		v = event.List(event.String("decoy"), v)
	}
	f[p.Field] = v
}

func applyTransform(tr, s string, rng *rand.Rand) string {
	switch tr {
	case "base64":
		return match.Base64(s)
	case "base64offset":
		return match.Base64Offsets(s)[rng.Intn(3)]
	case "utf16le", "wide":
		return match.UTF16LE(s)
	case "utf16be":
		return match.UTF16BE(s)
	case "utf16":
		return match.UTF16(s)
	case "windash":
		if vs, err := match.WinDashVariants(s); err == nil {
			return vs[rng.Intn(len(vs))]
		}
	}
	return s
}

// unwild turns a Sigma wildcard pattern into one string it matches.
func unwild(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s) && strings.IndexByte(`*?\`, s[i+1]) >= 0:
			i++
			b.WriteByte(s[i])
		case c == '*':
			b.WriteString("zz")
		case c == '?':
			b.WriteByte('q')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func caseFlip(s string, rng *rand.Rand) string {
	switch rng.Intn(3) {
	case 0:
		return strings.ToUpper(s)
	case 1:
		return strings.ToLower(s)
	}
	return s
}

func perturb(f map[string]event.Value, rng *rand.Rand) {
	if len(f) == 0 {
		return
	}
	names := make([]string, 0, len(f))
	for k := range f {
		names = append(names, k)
	}
	sort.Strings(names)
	k := names[rng.Intn(len(names))]
	switch rng.Intn(3) {
	case 0:
		delete(f, k)
	case 1:
		f[k] = event.Null()
	default:
		if s, ok := f[k].Text(); ok && len(s) > 1 {
			f[k] = event.String(s[:len(s)/2])
		}
	}
}
