// Package sigma parses Sigma rules into an evaluable AST.
package sigma

import (
	"errors"
	"fmt"
	"strings"
)

// ErrAggregation reports a condition that uses the aggregation pipe. The
// engine cannot evaluate these, and skipping them silently would be a
// missed detection with no signal attached, so loading fails loudly.
var ErrAggregation = errors.New("aggregation is not supported")

type tokenKind uint8

const (
	tokEOF tokenKind = iota
	tokIdent
	tokAnd
	tokOr
	tokNot
	tokOf
	tokLParen
	tokRParen
)

func (k tokenKind) String() string {
	switch k {
	case tokEOF:
		return "end of condition"
	case tokIdent:
		return "identifier"
	case tokAnd:
		return "and"
	case tokOr:
		return "or"
	case tokNot:
		return "not"
	case tokOf:
		return "of"
	case tokLParen:
		return "("
	case tokRParen:
		return ")"
	}
	return "unknown"
}

type token struct {
	kind tokenKind
	text string
	pos  int
}

// isIdentRune accepts selection names and the prefix glob used by
// quantifiers, so "selection_*" lexes as one token.
func isIdentRune(r byte) bool {
	return r == '_' || r == '*' || r == '-' || r == '.' ||
		(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func lex(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			out = append(out, token{tokLParen, "(", i})
			i++
		case c == ')':
			out = append(out, token{tokRParen, ")", i})
			i++
		case c == '|':
			return nil, fmt.Errorf("at offset %d: %w", i, ErrAggregation)
		case isIdentRune(c):
			start := i
			for i < len(s) && isIdentRune(s[i]) {
				i++
			}
			text := s[start:i]
			out = append(out, token{keywordKind(text), text, start})
		default:
			return nil, fmt.Errorf("unexpected character %q at offset %d", string(c), i)
		}
	}
	out = append(out, token{tokEOF, "", len(s)})
	return out, nil
}

func keywordKind(text string) tokenKind {
	switch strings.ToLower(text) {
	case "and":
		return tokAnd
	case "or":
		return tokOr
	case "not":
		return tokNot
	case "of":
		return tokOf
	}
	return tokIdent
}
