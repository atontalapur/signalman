package ch

import (
	"encoding/hex"
	"strconv"
)

// quote renders s as a ClickHouse String expression whose value is exactly
// the bytes of s.
//
// Only a closed set of characters is ever written inside quotes, and none of
// them is a quote or a backslash, so the literal cannot end early and no
// escape sequence is ever interpreted. Anything else goes through unhex,
// whose argument is hex digits only. Escapes were rejected: ClickHouse reads
// \xHH as "any number of hex digits", so \x5ccmd would swallow the "c" and
// the "d". This is why a rule value cannot inject SQL: no byte of it reaches
// the query text except as a letter, digit, safe punctuation, or hex.
func quote(s string) string {
	if plain(s) {
		return "'" + s + "'"
	}
	return "unhex('" + hex.EncodeToString([]byte(s)) + "')"
}

func plain(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == ' ', c == '_', c == '.', c == ',', c == ':', c == '/', c == '@',
			c == '+', c == '=', c == '-', c == '%', c == '#', c == '&', c == '(', c == ')':
		default:
			return false
		}
	}
	return true
}

// quoteList renders a ClickHouse array literal of strings.
func quoteList(ss []string) string {
	b := []byte{'['}
	for i, s := range ss {
		if i > 0 {
			b = append(b, ", "...)
		}
		b = append(b, quote(s)...)
	}
	return string(append(b, ']'))
}

// int64Lit renders n through a string parse. A bare -9223372036854775808
// is unary minus on a UInt64 literal, which does not land in Int64.
func int64Lit(n int64) string {
	return "toInt64('" + strconv.FormatInt(n, 10) + "')"
}
