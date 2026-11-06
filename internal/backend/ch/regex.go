package ch

import (
	"fmt"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode"
)

// re2Pattern rewrites a Go regexp, as match.Regex compiled it, into an
// equivalent RE2 pattern for ClickHouse's match().
//
// The pattern is re-emitted from Go's parse tree rather than passed through,
// because three of Go's readings do not survive the trip as text:
//
//   - ClickHouse sets RE2's dot_nl, so . matches \n there and not in Go.
//     The output never contains a dot: . becomes [^\n] and (?s). becomes
//     the full rune range.
//   - Case folding and \p classes come from each library's Unicode tables,
//     which are versioned separately. The output contains neither: Go's
//     parser has already expanded every class, folded or not, into rune
//     ranges, and a folded literal is written as the class of its
//     unicode.SimpleFold orbit. RE2 then needs no table to agree with Go.
//   - Captures, named or not, become (?:...). A match test never reads a
//     group, and (?<name>...) is newer syntax than some RE2 builds accept.
//
// Every rune is written as \x{...}, so the pattern is ASCII, has no NUL
// byte (match() forbids one), and has no metacharacter that is not ours.
func re2Pattern(goPattern string) (string, error) {
	re, err := syntax.Parse(goPattern, syntax.Perl)
	if err != nil {
		// match.Regex already compiled this pattern with the same flags.
		return "", fmt.Errorf("re-parse of a compiled regex failed: %w", err)
	}
	var b strings.Builder
	if err := emitRe(&b, re); err != nil {
		return "", err
	}
	return b.String(), nil
}

const (
	anyRune   = `[\x{0}-\x{10ffff}]`
	noRune    = `[^\x{0}-\x{10ffff}]`
	notNLRune = `[^\x{a}]`
)

func emitRe(b *strings.Builder, re *syntax.Regexp) error {
	switch re.Op {
	case syntax.OpNoMatch:
		b.WriteString(noRune)
	case syntax.OpEmptyMatch:
		b.WriteString("(?:)")
	case syntax.OpLiteral:
		b.WriteString("(?:")
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				writeClass(b, foldOrbit(r))
			} else {
				writeRune(b, r)
			}
		}
		b.WriteString(")")
	case syntax.OpCharClass:
		writeClass(b, re.Rune)
	case syntax.OpAnyCharNotNL:
		b.WriteString(notNLRune)
	case syntax.OpAnyChar:
		b.WriteString(anyRune)
	case syntax.OpBeginLine:
		b.WriteString("(?m:^)")
	case syntax.OpEndLine:
		b.WriteString("(?m:$)")
	case syntax.OpBeginText:
		b.WriteString(`\A`)
	case syntax.OpEndText:
		// Go's $ outside (?m) is end of text only, never "before a final
		// newline". \z is that in both.
		b.WriteString(`\z`)
	case syntax.OpWordBoundary:
		b.WriteString(`\b`)
	case syntax.OpNoWordBoundary:
		b.WriteString(`\B`)
	case syntax.OpCapture:
		b.WriteString("(?:")
		if err := emitRe(b, re.Sub[0]); err != nil {
			return err
		}
		b.WriteString(")")
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		b.WriteString("(?:")
		if err := emitRe(b, re.Sub[0]); err != nil {
			return err
		}
		b.WriteString(")")
		switch re.Op {
		case syntax.OpStar:
			b.WriteString("*")
		case syntax.OpPlus:
			b.WriteString("+")
		case syntax.OpQuest:
			b.WriteString("?")
		default:
			b.WriteString("{" + strconv.Itoa(re.Min))
			switch {
			case re.Max == -1:
				b.WriteString(",")
			case re.Max != re.Min:
				b.WriteString("," + strconv.Itoa(re.Max))
			}
			b.WriteString("}")
		}
		if re.Flags&syntax.NonGreedy != 0 {
			b.WriteString("?")
		}
	case syntax.OpConcat, syntax.OpAlternate:
		b.WriteString("(?:")
		for i, sub := range re.Sub {
			if i > 0 && re.Op == syntax.OpAlternate {
				b.WriteString("|")
			}
			if err := emitRe(b, sub); err != nil {
				return err
			}
		}
		b.WriteString(")")
	default:
		return fmt.Errorf("regex operator %v has no RE2 rendering", re.Op)
	}
	return nil
}

// foldOrbit is the set of runes a case-folded literal r matches in Go, as
// sorted [lo, hi] pairs.
func foldOrbit(r rune) []rune {
	rs := []rune{r}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		rs = append(rs, f)
	}
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j] < rs[j-1]; j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
	pairs := make([]rune, 0, 2*len(rs))
	for _, x := range rs {
		pairs = append(pairs, x, x)
	}
	return pairs
}

func writeClass(b *strings.Builder, pairs []rune) {
	if len(pairs) == 0 {
		b.WriteString(noRune)
		return
	}
	b.WriteString("[")
	for i := 0; i+1 < len(pairs); i += 2 {
		writeRune(b, pairs[i])
		if pairs[i+1] != pairs[i] {
			b.WriteString("-")
			writeRune(b, pairs[i+1])
		}
	}
	b.WriteString("]")
}

func writeRune(b *strings.Builder, r rune) {
	b.WriteString(`\x{` + strconv.FormatInt(int64(r), 16) + `}`)
}
