// Package match implements Sigma value comparison. Wildcards are matched
// directly rather than translated to regex, because Windows command lines
// are full of regex metacharacters and the naive translation of * to .*
// changes the meaning of the pattern.
package match

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type tokenClass uint8

const (
	classLiteral tokenClass = iota
	classAny                // *
	classOne                // ?
)

type wtok struct {
	class tokenClass
	r     rune
}

// Wildcard is a compiled Sigma wildcard pattern.
type Wildcard struct {
	toks []wtok
	// exact is set when the pattern has no wildcards, which is the common
	// case and lets MatchString short circuit to a case-insensitive compare.
	exact string
	plain bool
}

// CompileWildcard parses a Sigma wildcard pattern. Escapes are \*, \?, and
// \\. A backslash before anything else is a literal backslash, which is what
// Windows paths in the rule corpus rely on.
func CompileWildcard(pattern string) *Wildcard {
	w := &Wildcard{plain: true}
	rs := []rune(strings.ToLower(pattern))
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '\\':
			if i+1 < len(rs) && (rs[i+1] == '*' || rs[i+1] == '?' || rs[i+1] == '\\') {
				i++
				w.toks = append(w.toks, wtok{classLiteral, rs[i]})
			} else {
				w.toks = append(w.toks, wtok{classLiteral, '\\'})
			}
		case '*':
			w.plain = false
			w.toks = append(w.toks, wtok{class: classAny})
		case '?':
			w.plain = false
			w.toks = append(w.toks, wtok{class: classOne})
		default:
			w.toks = append(w.toks, wtok{classLiteral, rs[i]})
		}
	}
	if w.plain {
		var b strings.Builder
		for _, t := range w.toks {
			b.WriteRune(t.r)
		}
		w.exact = b.String()
	}
	return w
}

// Literals returns the maximal runs of literal characters between
// wildcards, lowercased, in pattern order. Every string the pattern matches
// contains each run contiguously once folded with AppendFold, because a
// literal token only ever matches the identical rune and * and ? never sit
// inside a run. A compiled engine's prefilter is built on that fact.
func (w *Wildcard) Literals() []string {
	var out []string
	var b strings.Builder
	for _, t := range w.toks {
		if t.class == classLiteral {
			b.WriteRune(t.r)
			continue
		}
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// AppendFold appends strings.ToLower(s) to dst without allocating a
// string: the folded form MatchString compares against. Invalid UTF-8
// folds to U+FFFD, as it does in strings.ToLower, so the result is always
// valid UTF-8 and a substring test on it agrees with a rune comparison.
func AppendFold(dst []byte, s string) []byte {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		for i := 0; i < len(s); i++ {
			c := s[i]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			dst = append(dst, c)
		}
		return dst
	}
	for _, r := range s {
		// range yields U+FFFD for each invalid byte, which is what
		// strings.Map, and so strings.ToLower, writes for it.
		dst = utf8.AppendRune(dst, unicode.ToLower(r))
	}
	return dst
}

// HasWildcard reports whether the pattern contains an unescaped * or ?.
func HasWildcard(pattern string) bool {
	return !CompileWildcard(pattern).plain
}

// MatchString runs the classic backtracking wildcard match over the
// lowercased input. The star pointer makes the worst case
// O(len(input) * longest literal run between stars), never exponential.
// Input length is bounded at ingest, not here.
func (w *Wildcard) MatchString(s string) bool {
	low := strings.ToLower(s)
	if w.plain {
		return low == w.exact
	}
	in := []rune(low)
	ti, si := 0, 0
	starT, starS := -1, 0
	for si < len(in) {
		switch {
		case ti < len(w.toks) && w.toks[ti].class == classOne:
			ti++
			si++
		case ti < len(w.toks) && w.toks[ti].class == classLiteral && w.toks[ti].r == in[si]:
			ti++
			si++
		case ti < len(w.toks) && w.toks[ti].class == classAny:
			starT, starS = ti, si
			ti++
		case starT >= 0:
			ti = starT + 1
			starS++
			si = starS
		default:
			return false
		}
	}
	for ti < len(w.toks) && w.toks[ti].class == classAny {
		ti++
	}
	return ti == len(w.toks)
}
