package match

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/atontalapur/signalman/internal/event"
)

// ErrUnsupportedModifier is wrapped by every Build error caused by the
// modifier chain itself: an unknown modifier or an invalid combination.
// The rule loader classifies on it with errors.Is, never on error text.
var ErrUnsupportedModifier = errors.New("unsupported modifier")

// Modifier names as written in a detection key. A comparison is consumed in
// three places: the chain parser above, validateChain, and either buildOne's
// dedicated switch (re, cidr, the numeric operators) or the variant loop that
// follows it.
// ModFieldRef is the fieldref modifier. The rule loader matches on it to
// rename a fieldref target through the taxonomy.
const ModFieldRef = "fieldref"

const (
	modContains   = "contains"
	modStartsWith = "startswith"
	modEndsWith   = "endswith"
	modRe         = "re"
	modAll        = "all"
	modI          = "i"
	modEquals     = "equals" // implicit; no modifier written

	modCidr     = "cidr"
	modFieldRef = ModFieldRef
	modLt       = "lt"
	modLte      = "lte"
	modGt       = "gt"
	modGte      = "gte"

	modBase64       = "base64"
	modBase64Offset = "base64offset"
	modUTF16LE      = "utf16le"
	modUTF16BE      = "utf16be"
	modUTF16        = "utf16"
	modWide         = "wide"
	modWinDash      = "windash"
)

// Build turns one detection entry into a Matcher. mods is the modifier list
// from the key, in written order, with the field name already stripped.
// vals is one or more rule values.
//
// The pipeline is: encoding transforms in written order, then one
// comparison, then the combination across values (Any unless all is
// present). Every transform may fan out into several variants, and any
// variant matching is a match.
//
// Build is Plan followed by Spec.Matcher, so the closure and the plan a
// compiled engine reads can never describe two different tests.
func Build(mods []string, vals []event.Value) (Matcher, error) {
	s, err := Plan(mods, vals)
	if err != nil {
		return nil, err
	}
	return s.Matcher(), nil
}

// Plan validates a detection entry and resolves it into a Spec: every
// modifier applied, every transform expanded, every regex and prefix
// parsed. It fails exactly when Build fails, with the same error.
func Plan(mods []string, vals []event.Value) (Spec, error) {
	var (
		transforms  []transform
		comparison  = modEquals
		comparisons int
		reInsens    bool
		conjoin     bool
		fieldref    bool
		b64         bool
	)

	for _, m := range mods {
		switch m {
		case modContains, modStartsWith, modEndsWith, modRe,
			modCidr, modLt, modLte, modGt, modGte:
			comparison = m
			comparisons++
		case modAll:
			conjoin = true
		case modI:
			reInsens = true
		case modFieldRef:
			fieldref = true
		case modUTF16LE, modWide:
			transforms = append(transforms, pure(UTF16LE))
		case modUTF16BE:
			transforms = append(transforms, pure(UTF16BE))
		case modUTF16:
			transforms = append(transforms, pure(UTF16))
		case modBase64:
			b64 = true
			transforms = append(transforms, pure(Base64))
		case modBase64Offset:
			b64 = true
			transforms = append(transforms, func(s string) ([]string, error) {
				o := Base64Offsets(s)
				return []string{o[0], o[1], o[2]}, nil
			})
		case modWinDash:
			transforms = append(transforms, WinDashVariants)
		default:
			return Spec{}, fmt.Errorf("%w %q", ErrUnsupportedModifier, m)
		}
	}

	if err := validateChain(mods, comparison, comparisons, reInsens, fieldref, len(transforms) > 0); err != nil {
		return Spec{}, err
	}

	if len(vals) == 0 {
		return Spec{}, errors.New("detection entry has no values")
	}
	spec := Spec{All: conjoin, Values: make([]ValueSpec, 0, len(vals))}
	for _, v := range vals {
		if text, ok := v.Text(); ok && b64 && HasWildcard(text) {
			// The encoded bytes of a wildcard are not a wildcard, so the
			// rule would match something other than what it says. pySigma
			// rejects the same entry. An escaped \* is a literal star: Unescape
			// turns it into one before encoding.
			return Spec{}, fmt.Errorf("%w: a wildcard cannot be encoded by base64 in %q (escape it as \\* to match a literal)",
				ErrUnsupportedModifier, mods)
		}
		if text, ok := v.Text(); ok && b64 {
			// The value is plaintext to encode, not a pattern, so its
			// escapes are resolved before the transforms see it.
			v = event.String(Unescape(text))
		}
		vs, err := planOne(v, transforms, comparison, reInsens, fieldref)
		if err != nil {
			return Spec{}, err
		}
		spec.Values = append(spec.Values, vs)
	}
	return spec, nil
}

// transform is one encoding step. It returns every variant of its input,
// because base64offset and windash each produce more than one.
type transform func(string) ([]string, error)

func pure(f func(string) string) transform {
	return func(s string) ([]string, error) { return []string{f(s)}, nil }
}

// validateChain rejects modifier combinations before anything is built, so a
// rule with a nonsensical chain is a load error naming the chain rather than
// a matcher that silently ignores half of it.
func validateChain(mods []string, comparison string, comparisons int, reInsens, fieldref, transformed bool) error {
	if comparisons > 1 {
		return fmt.Errorf("%w: more than one comparison in %q", ErrUnsupportedModifier, mods)
	}
	if reInsens && comparison != modRe {
		return fmt.Errorf("%w: i without re in %q", ErrUnsupportedModifier, mods)
	}
	if transformed {
		switch comparison {
		case modRe, modCidr, modLt, modLte, modGt, modGte:
			return fmt.Errorf("%w: %s cannot take an encoded value in %q",
				ErrUnsupportedModifier, comparison, mods)
		}
		if fieldref {
			return fmt.Errorf("%w: fieldref cannot take an encoded value in %q",
				ErrUnsupportedModifier, mods)
		}
	}
	if fieldref && comparison != modEquals {
		// pySigma allows fieldref beside a comparison. Signalman rejects it
		// rather than picking one silently; the corpus acceptance report
		// carries the count and KNOWN_DIVERGENCES.md carries the reason.
		return fmt.Errorf("%w: fieldref with %s in %q", ErrUnsupportedModifier, comparison, mods)
	}
	return nil
}

func planOne(v event.Value, transforms []transform, comparison string, reInsens, fieldref bool) (ValueSpec, error) {
	if v.Kind == event.KindNull {
		// "field: null" is the only null form. A comparison, a transform, or
		// a field reference on null is a rule error, as it is in pySigma.
		if comparison != modEquals || fieldref || len(transforms) > 0 {
			return ValueSpec{}, fmt.Errorf("%w: a modifier chain on a null value", ErrUnsupportedModifier)
		}
		return ValueSpec{Kind: SpecNull}, nil
	}
	text, ok := v.Text()
	if !ok {
		return ValueSpec{}, fmt.Errorf("a detection value must be a scalar, got %s", v.Kind)
	}

	if fieldref {
		return ValueSpec{Kind: SpecFieldRef, Field: text}, nil
	}

	switch comparison {
	case modRe:
		re, err := compileRegex(text, reInsens)
		if err != nil {
			return ValueSpec{}, err
		}
		return ValueSpec{Kind: SpecRegex, Regex: re}, nil
	case modCidr:
		p, err := parseCIDR(text)
		if err != nil {
			return ValueSpec{}, err
		}
		return ValueSpec{Kind: SpecCIDR, Prefix: p}, nil
	case modLt, modLte, modGt, modGte:
		n, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
		if err != nil {
			return ValueSpec{}, fmt.Errorf("%s modifier needs an integer, got %q", comparison, text)
		}
		return ValueSpec{Kind: SpecCompare, Op: comparison, N: n}, nil
	}

	variants, err := expand(text, transforms)
	if err != nil {
		return ValueSpec{}, err
	}
	pats := make([]string, 0, len(variants))
	for _, s := range variants {
		switch comparison {
		case modContains:
			pats = append(pats, "*"+padTrailingBackslash(s)+"*")
		case modStartsWith:
			pats = append(pats, padTrailingBackslash(s)+"*")
		case modEndsWith:
			pats = append(pats, "*"+padTrailingBackslash(s))
		default:
			pats = append(pats, s)
		}
	}
	if len(pats) == 0 {
		// Every variant was empty, which base64offset can produce for a very
		// short plaintext. An entry that can never match is a rule bug.
		return ValueSpec{}, fmt.Errorf("%w: the modifier chain produced no value to match",
			ErrUnsupportedModifier)
	}
	return ValueSpec{Kind: SpecPattern, Patterns: pats}, nil
}

// maxVariants bounds the whole chain, not one transform. Each transform caps
// its own fan-out, but the counts multiply: windash at its five-position
// limit is 3125 variants, and chaining base64offset makes that 9375, every
// one of them a matcher scanned on every event that does not match. No rule
// in the SigmaHQ corpus chains windash with an encoding, so nothing real is
// rejected here; the budget exists so that a rule that would do it fails at
// load instead of quietly costing the pipeline orders of magnitude.
const maxVariants = 4096

// expand runs the transforms in written order. Order is the contract: the
// utf16 family encodes the text, then base64 encodes those bytes, never the
// other way around.
func expand(text string, transforms []transform) ([]string, error) {
	variants := []string{text}
	for _, tr := range transforms {
		next := make([]string, 0, len(variants))
		for _, s := range variants {
			outs, err := tr(s)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", ErrUnsupportedModifier, err)
			}
			for _, out := range outs {
				if out != "" {
					next = append(next, out)
				}
			}
		}
		if len(next) > maxVariants {
			return nil, fmt.Errorf("%w: the modifier chain expands to %d variants, over the limit of %d",
				ErrUnsupportedModifier, len(next), maxVariants)
		}
		variants = next
	}
	return variants, nil
}
