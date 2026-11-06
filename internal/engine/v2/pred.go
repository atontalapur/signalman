package v2

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma/ast"
	"github.com/atontalapur/signalman/internal/sigma/match"
)

// cpred is an interned leaf compiled for the hot path. It is built from the
// same match.Plan the v1 closure is built from and implements the same
// test, but reads the event's fields from the per-event fold cache and
// allocates nothing. Equivalence with v1 is not argued from the code: it is
// checked by digest over the corpus and by FuzzPrefilterSound, which
// compares v2's verdict with v1's on every generated case.
type cpred struct {
	field   int32 // index into Program.fields; unused for a keyword
	keyword bool
	all     bool
	vals    []cval
}

type cval struct {
	kind   match.SpecKind
	pats   []*match.Folded
	re     *regexp.Regexp
	prefix netip.Prefix
	op     string
	n      int64
	ref    string // fieldref: the other field, read by name
}

func compilePred(p *ast.Pred, field int32) (cpred, error) {
	mods := p.Mods
	if p.Keyword {
		// The keyword matcher is Contains on every field value.
		mods = []string{"contains"}
	}
	spec, err := match.Plan(mods, p.Vals)
	if err != nil {
		return cpred{}, fmt.Errorf("predicate %s: %w", p.Desc, err)
	}
	cp := cpred{field: field, keyword: p.Keyword, all: spec.All}
	for _, v := range spec.Values {
		cv := cval{kind: v.Kind, re: v.Regex, prefix: v.Prefix, op: v.Op, n: v.N, ref: v.Field}
		for _, pat := range v.Patterns {
			cv.pats = append(cv.pats, match.CompileWildcard(pat).Folded())
		}
		cp.vals = append(cp.vals, cv)
	}
	return cp, nil
}

// span is one folded scalar in the scratch text arena.
type span struct{ off, end int32 }

// test evaluates predicate i against the loaded event.
func (s *scratch) test(cp *cpred) bool {
	if cp.keyword {
		return s.keyword(cp)
	}
	v := event.Null()
	var lo, hi int32
	if s.seen[cp.field] == s.epoch {
		v = s.vals[cp.field]
		lo, hi = s.spanLo[cp.field], s.spanHi[cp.field]
	}
	if cp.all {
		for i := range cp.vals {
			if !s.value(&cp.vals[i], v, lo, hi) {
				return false
			}
		}
		return true
	}
	for i := range cp.vals {
		if s.value(&cp.vals[i], v, lo, hi) {
			return true
		}
	}
	return false
}

// value is one rule value against the field's value v, whose folded
// scalars are spans[lo:hi].
func (s *scratch) value(cv *cval, v event.Value, lo, hi int32) bool {
	switch cv.kind {
	case match.SpecNull:
		return v.Kind == event.KindNull
	case match.SpecPattern:
		for _, sp := range s.spans[lo:hi] {
			b := s.text[sp.off:sp.end]
			for _, p := range cv.pats {
				if p.Match(b) {
					return true
				}
			}
		}
		return false
	}
	// A list is an OR over its elements for every other test too.
	if v.Kind == event.KindList {
		for _, item := range v.L {
			if s.item(cv, item) {
				return true
			}
		}
		return false
	}
	return s.item(cv, v)
}

// item is a non-pattern test on one scalar. A null or nested list has no
// text and fails every one of them, as it does in v1.
func (s *scratch) item(cv *cval, v event.Value) bool {
	switch cv.kind {
	case match.SpecRegex:
		switch v.Kind {
		case event.KindString:
			return cv.re.MatchString(v.S)
		case event.KindInt:
			s.num = strconv.AppendInt(s.num[:0], v.I, 10)
			return cv.re.Match(s.num)
		case event.KindBool:
			return cv.re.MatchString(strconv.FormatBool(v.B))
		}
		return false
	case match.SpecCIDR:
		// An integer or boolean's text is never an address, which
		// maybeAddr would also conclude; only strings can match.
		if v.Kind != event.KindString || !maybeAddr(v.S) {
			return false
		}
		addr, err := netip.ParseAddr(v.S)
		return err == nil && cv.prefix.Contains(addr)
	case match.SpecCompare:
		var got int64
		switch v.Kind {
		case event.KindInt:
			got = v.I
		case event.KindString:
			n, ok := parseInt10(strings.TrimSpace(v.S))
			if !ok {
				return false
			}
			got = n
		default:
			return false
		}
		switch cv.op {
		case "lt":
			return got < cv.n
		case "lte":
			return got <= cv.n
		case "gt":
			return got > cv.n
		default: // gte; Plan produces no other operator
			return got >= cv.n
		}
	case match.SpecFieldRef:
		if !hasText(v) {
			return false
		}
		// Absent reads as the zero Value, which is null, as ev.Field does.
		other := s.ev.Fields[cv.ref]
		if other.Kind == event.KindList {
			for _, r := range other.L {
				if hasText(r) && s.textEqualFold(v, r) {
					return true
				}
			}
			return false
		}
		return hasText(other) && s.textEqualFold(v, other)
	}
	return false
}

// keyword is Contains over every scalar of every field. Map order cannot
// change an OR, so the fields are walked in whatever order the map yields.
func (s *scratch) keyword(cp *cpred) bool {
	p := cp.vals[0].pats[0]
	for _, v := range s.ev.Fields {
		if v.Kind == event.KindList {
			for _, item := range v.L {
				if s.foldTmp(item) && p.Match(s.tmp) {
					return true
				}
			}
			continue
		}
		if s.foldTmp(v) && p.Match(s.tmp) {
			return true
		}
	}
	return false
}

// foldTmp folds one scalar's text into s.tmp, reporting false for a value
// with no text.
func (s *scratch) foldTmp(v event.Value) bool {
	var ok bool
	s.tmp, ok = appendFoldedText(s.tmp[:0], v)
	return ok
}

// appendFoldedText appends the folded form of v.Text(), which is what the
// v1 wildcard matcher lowercases and compares.
func appendFoldedText(dst []byte, v event.Value) ([]byte, bool) {
	switch v.Kind {
	case event.KindString:
		return match.AppendFold(dst, v.S), true
	case event.KindInt:
		return strconv.AppendInt(dst, v.I, 10), true
	case event.KindBool:
		return strconv.AppendBool(dst, v.B), true
	}
	return dst, false
}

func hasText(v event.Value) bool {
	return v.Kind == event.KindString || v.Kind == event.KindInt || v.Kind == event.KindBool
}

// textEqualFold is strings.EqualFold(a.Text(), b.Text()) without
// formatting an integer into a new string. An integer's text is ASCII
// digits and a minus sign, none of which has a case fold
// (TestDigitsHaveNoCaseFolds), so against it EqualFold is plain equality.
func (s *scratch) textEqualFold(a, b event.Value) bool {
	if a.Kind == event.KindInt && b.Kind == event.KindInt {
		return a.I == b.I
	}
	if b.Kind == event.KindInt {
		a, b = b, a
	}
	switch a.Kind {
	case event.KindInt:
		s.num = strconv.AppendInt(s.num[:0], a.I, 10)
		if b.Kind == event.KindString {
			return string(s.num) == b.S
		}
		return false // a boolean's text is never digits
	case event.KindBool:
		if b.Kind == event.KindBool {
			return a.B == b.B
		}
		return strings.EqualFold(strconv.FormatBool(a.B), b.S)
	}
	if b.Kind == event.KindBool {
		return strings.EqualFold(a.S, strconv.FormatBool(b.B))
	}
	return strings.EqualFold(a.S, b.S)
}

// maybeAddr is a cheap necessary condition for netip.ParseAddr to succeed:
// an address has a dot or a colon, and before any zone only hex digits,
// dots, and colons. Rejecting here avoids the error value ParseAddr
// allocates for a string that is not an address.
func maybeAddr(s string) bool {
	sep := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%':
			return sep
		case c == '.' || c == ':':
			sep = true
		case '0' <= c && c <= '9', 'a' <= c && c <= 'f', 'A' <= c && c <= 'F':
		default:
			return false
		}
	}
	return sep
}

// parseInt10 accepts exactly what strconv.ParseInt(s, 10, 64) accepts and
// returns the same value, without the error value ParseInt allocates on
// failure. FuzzParseInt10 holds it to that.
func parseInt10(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	neg := false
	switch s[0] {
	case '+':
		s = s[1:]
	case '-':
		neg = true
		s = s[1:]
	}
	if s == "" {
		return 0, false
	}
	const limit = uint64(1) << 63
	var n uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		if n > (limit-uint64(c-'0'))/10 {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	if neg {
		if n > limit {
			return 0, false
		}
		return -int64(n), true
	}
	if n >= limit {
		return 0, false
	}
	return int64(n), true
}
