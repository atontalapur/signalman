package match

import (
	"unicode"
	"unicode/utf8"
)

// Sigma string matching is case-insensitive. Signalman folds with Unicode
// case mappings, so "ДОМ" matches "дом", with one restriction: a fold never
// crosses the ASCII boundary. Go maps U+0130 (dotted capital I) to 'i' and
// U+212A (Kelvin sign) to 'k', and the simple fold orbits pair U+212A with
// 'k' and U+017F (long s) with 's'. Left alone, a rule value "İ" matched
// every 'i' on every event. pySigma and SQLite never pair them either.
//
// Every engine folds through these functions: v1's wildcard matcher,
// v2's AppendFold, and the ClickHouse encoder, so they cannot drift.

// foldRune is unicode.ToLower, except a non-ASCII rune whose lowercase is
// ASCII stays itself.
func foldRune(r rune) rune {
	l := unicode.ToLower(r)
	if r >= utf8.RuneSelf && l < utf8.RuneSelf {
		return r
	}
	return l
}

// Fold is strings.ToLower with foldRune: invalid UTF-8 becomes U+FFFD, as
// in strings.ToLower, so the result is always valid UTF-8.
func Fold(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return string(AppendFold(make([]byte, 0, len(s)), s))
		}
		if 'A' <= s[i] && s[i] <= 'Z' {
			return string(AppendFold(make([]byte, 0, len(s)), s))
		}
	}
	return s
}

// EqualFold is strings.EqualFold, except two runes on opposite sides of the
// ASCII boundary are never equal. Invalid bytes read as U+FFFD, as
// strings.EqualFold reads them.
func EqualFold(a, b string) bool {
	for a != "" && b != "" {
		ra, na := utf8.DecodeRuneInString(a)
		rb, nb := utf8.DecodeRuneInString(b)
		a, b = a[na:], b[nb:]
		if ra == rb {
			continue
		}
		if (ra < utf8.RuneSelf) != (rb < utf8.RuneSelf) || !sameOrbit(ra, rb) {
			return false
		}
	}
	return a == b
}

func sameOrbit(a, b rune) bool {
	for f := unicode.SimpleFold(a); f != a; f = unicode.SimpleFold(f) {
		if f == b {
			return true
		}
	}
	return false
}

// FoldKey is EqualFold's canonical form: each rune replaced by the least
// rune of its simple fold orbit on its own side of the ASCII boundary, with
// invalid bytes read as U+FFFD. Two texts are EqualFold exactly when their
// keys are equal.
func FoldKey(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		b = utf8.AppendRune(b, foldMin(r))
	}
	return string(b)
}

func foldMin(r rune) rune {
	ascii := r < utf8.RuneSelf
	m := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if (f < utf8.RuneSelf) == ascii && f < m {
			m = f
		}
	}
	return m
}
