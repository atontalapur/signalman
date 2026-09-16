package match

import (
	"regexp"
	"strings"

	"github.com/atontalapur/signalman/internal/event"
)

// Matcher is the value test at a leaf predicate. It has the same method set
// as ast.Matcher, which it satisfies structurally, so this package does not
// import ast.
type Matcher interface {
	Match(v event.Value, ev *event.Event) bool
}

type funcMatcher struct {
	f func(v event.Value, ev *event.Event) bool
}

func (m funcMatcher) Match(v event.Value, ev *event.Event) bool { return m.f(v, ev) }

// onText lifts a string test into a Matcher. Null values have no text form
// and never match a string test. A list matches when any element does.
func onText(f func(s string) bool) Matcher {
	return funcMatcher{func(v event.Value, _ *event.Event) bool {
		if v.Kind == event.KindList {
			for _, item := range v.L {
				if s, ok := item.Text(); ok && f(s) {
					return true
				}
			}
			return false
		}
		s, ok := v.Text()
		return ok && f(s)
	}}
}

// Equals is Sigma's plain "field: value". It honors wildcards, because an
// unmodified value containing * is a wildcard match in the specification.
func Equals(pattern string) Matcher {
	w := CompileWildcard(pattern)
	return onText(w.MatchString)
}

// Contains is "field|contains: value".
func Contains(sub string) Matcher { return Equals("*" + padTrailingBackslash(sub) + "*") }

// StartsWith is "field|startswith: value".
func StartsWith(pre string) Matcher { return Equals(padTrailingBackslash(pre) + "*") }

// EndsWith is "field|endswith: value".
func EndsWith(suf string) Matcher { return Equals("*" + padTrailingBackslash(suf)) }

// padTrailingBackslash makes a trailing run of backslashes even. It does not
// escape anything else: Sigma allows the author's own * and ? inside contains
// values. An odd run would escape the star the modifier is about to append.
func padTrailingBackslash(s string) string {
	n := len(s) - len(strings.TrimRight(s, `\`))
	if n%2 == 1 {
		return s + `\`
	}
	return s
}

// Regex is case sensitive unless the |i modifier was present. This is the
// one string modifier whose default differs from the rest of Sigma.
func Regex(pattern string, caseInsensitive bool) (Matcher, error) {
	if caseInsensitive {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return onText(re.MatchString), nil
}

// Null matches an absent field or a field present with a null value. It does
// not match an empty string.
func Null() Matcher {
	return funcMatcher{func(v event.Value, _ *event.Event) bool {
		return v.Kind == event.KindNull
	}}
}

// Any is the OR that "field: [a, b]" means.
func Any(ms []Matcher) Matcher {
	if len(ms) == 1 {
		return ms[0]
	}
	return funcMatcher{func(v event.Value, ev *event.Event) bool {
		for _, m := range ms {
			if m.Match(v, ev) {
				return true
			}
		}
		return false
	}}
}

// All is the AND that "field|all: [a, b]" means. The modifier applies to the
// list, not to the value.
func All(ms []Matcher) Matcher {
	if len(ms) == 1 {
		return ms[0]
	}
	return funcMatcher{func(v event.Value, ev *event.Event) bool {
		for _, m := range ms {
			if !m.Match(v, ev) {
				return false
			}
		}
		return true
	}}
}
