package match

import "strings"

// PartKind is one piece of a compiled wildcard pattern.
type PartKind uint8

const (
	// PartLiteral is a run of literal runes, already lowercased.
	PartLiteral PartKind = iota
	// PartAny is *: zero or more runes. Adjacent stars collapse into one.
	PartAny
	// PartOne is ?: exactly one rune.
	PartOne
)

// WildcardPart is one piece of a pattern as MatchString reads it.
type WildcardPart struct {
	Kind PartKind
	Lit  string // set for PartLiteral
}

// Parts returns the pattern as MatchString sees it: escapes resolved, the
// literal runs folded with Fold and merged, and runs of
// stars collapsed. A backend that compiles a pattern into another language
// reads this rather than re-parsing the Sigma escapes, so the two cannot
// disagree about what \* or a trailing backslash means.
func (w *Wildcard) Parts() []WildcardPart {
	var out []WildcardPart
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			out = append(out, WildcardPart{Kind: PartLiteral, Lit: lit.String()})
			lit.Reset()
		}
	}
	for _, t := range w.toks {
		switch t.class {
		case classLiteral:
			lit.WriteRune(t.r)
		case classAny:
			flush()
			if n := len(out); n > 0 && out[n-1].Kind == PartAny {
				continue
			}
			out = append(out, WildcardPart{Kind: PartAny})
		case classOne:
			flush()
			out = append(out, WildcardPart{Kind: PartOne})
		}
	}
	flush()
	return out
}
