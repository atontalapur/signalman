package match

import (
	"bytes"
	"unicode/utf8"
)

type foldedShape uint8

const (
	shapeExact    foldedShape = iota // lit
	shapePrefix                      // lit*
	shapeSuffix                      // *lit
	shapeContains                    // *lit*
	shapeGeneral                     // anything else
)

// Folded is a wildcard pattern for callers that fold their input once and
// test it against many patterns: a compiled engine folds each event field
// with AppendFold and reuses the bytes. It never allocates.
//
// The common shapes (exact, prefix, suffix, contains) become byte
// comparisons. That is equivalent to the rune comparison MatchString does
// because both sides are valid UTF-8, where a byte match of one valid
// encoding inside another can only start on a rune boundary. Everything
// else runs the same backtracking walk as MatchString, over runes decoded
// in place.
type Folded struct {
	shape foldedShape
	lit   []byte
	toks  []wtok
}

// Folded returns the folded-input form of w. The tokens are shared, not
// copied; neither form ever writes them.
func (w *Wildcard) Folded() *Folded {
	f := &Folded{shape: shapeGeneral, toks: w.toks}
	n := len(w.toks)
	lits := func(ts []wtok) ([]byte, bool) {
		var b []byte
		for _, t := range ts {
			if t.class != classLiteral {
				return nil, false
			}
			b = utf8.AppendRune(b, t.r)
		}
		return b, true
	}
	isAny := func(i int) bool { return w.toks[i].class == classAny }
	switch {
	case w.plain:
		f.shape, f.lit = shapeExact, []byte(w.exact)
	case n >= 3 && isAny(0) && isAny(n-1):
		if b, ok := lits(w.toks[1 : n-1]); ok {
			f.shape, f.lit = shapeContains, b
		}
	case n >= 2 && isAny(n-1):
		if b, ok := lits(w.toks[:n-1]); ok {
			f.shape, f.lit = shapePrefix, b
		}
	case n >= 2 && isAny(0):
		if b, ok := lits(w.toks[1:]); ok {
			f.shape, f.lit = shapeSuffix, b
		}
	}
	return f
}

// Match reports whether the pattern matches in, which must be the output of
// AppendFold.
func (f *Folded) Match(in []byte) bool {
	switch f.shape {
	case shapeExact:
		return bytes.Equal(in, f.lit)
	case shapePrefix:
		return bytes.HasPrefix(in, f.lit)
	case shapeSuffix:
		return bytes.HasSuffix(in, f.lit)
	case shapeContains:
		return bytes.Contains(in, f.lit)
	}
	toks := f.toks
	ti, si := 0, 0
	starT, starS := -1, 0
	for si < len(in) {
		r, w := utf8.DecodeRune(in[si:])
		switch {
		case ti < len(toks) && toks[ti].class == classOne:
			ti++
			si += w
		case ti < len(toks) && toks[ti].class == classLiteral && toks[ti].r == r:
			ti++
			si += w
		case ti < len(toks) && toks[ti].class == classAny:
			starT, starS = ti, si
			ti++
		case starT >= 0:
			ti = starT + 1
			_, sw := utf8.DecodeRune(in[starS:])
			starS += sw
			si = starS
		default:
			return false
		}
	}
	for ti < len(toks) && toks[ti].class == classAny {
		ti++
	}
	return ti == len(toks)
}
