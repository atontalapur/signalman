package match

import (
	"fmt"
	"net/netip"
	"regexp"
)

// SpecKind is what one rule value tests.
type SpecKind uint8

const (
	// SpecNull matches an absent field or an explicit null.
	SpecNull SpecKind = iota
	// SpecPattern matches when any of Patterns matches the value's text as
	// a Sigma wildcard, case-insensitively.
	SpecPattern
	// SpecRegex matches when Regex matches the value's text.
	SpecRegex
	// SpecCIDR matches an address inside Prefix.
	SpecCIDR
	// SpecCompare compares the value numerically: value Op N.
	SpecCompare
	// SpecFieldRef matches when the value equals, case-insensitively, the
	// value of Field on the same event.
	SpecFieldRef
)

// Spec is a detection entry resolved by Plan: one ValueSpec per rule value,
// combined with AND when All is set and with OR otherwise. It is data, so a
// compiled engine can intern, index, and evaluate it its own way; Matcher
// turns it into the closure v1 evaluates.
type Spec struct {
	All    bool
	Values []ValueSpec
}

// ValueSpec is one rule value after every modifier has been applied. Only
// the fields its Kind names are set.
type ValueSpec struct {
	Kind SpecKind
	// Patterns are wildcard patterns, already carrying the stars that
	// contains, startswith, and endswith add, one per transform variant.
	Patterns []string
	Regex    *regexp.Regexp
	Prefix   netip.Prefix // masked
	Op       string       // lt, lte, gt, or gte
	N        int64
	Field    string
}

// Matcher builds the closure for the spec. The structure mirrors the spec
// one to one: an Any or All across values, and for a pattern value an Any
// across its variants.
func (s Spec) Matcher() Matcher {
	perValue := make([]Matcher, 0, len(s.Values))
	for _, v := range s.Values {
		perValue = append(perValue, v.matcher())
	}
	if s.All {
		return All(perValue)
	}
	return Any(perValue)
}

func (v ValueSpec) matcher() Matcher {
	switch v.Kind {
	case SpecNull:
		return Null()
	case SpecFieldRef:
		return FieldRef(v.Field)
	case SpecRegex:
		return regexMatcher(v.Regex)
	case SpecCIDR:
		return cidrMatcher(v.Prefix)
	case SpecCompare:
		m, err := Compare(v.Op, v.N)
		if err != nil {
			// Plan only produces the four operators Compare accepts.
			panic(fmt.Sprintf("match: %v", err))
		}
		return m
	}
	ms := make([]Matcher, 0, len(v.Patterns))
	for _, p := range v.Patterns {
		ms = append(ms, Equals(p))
	}
	return Any(ms)
}
