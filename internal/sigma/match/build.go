package match

import (
	"errors"
	"fmt"

	"github.com/atontalapur/signalman/internal/event"
)

// ErrUnsupportedModifier is wrapped by every Build error caused by the
// modifier chain itself: an unknown modifier or an invalid combination.
// The rule loader classifies on it with errors.Is, never on error text.
var ErrUnsupportedModifier = errors.New("unsupported modifier")

// Build turns one detection entry into a Matcher. mods is the modifier list
// from the key, in written order, with the field name already stripped.
// vals is one or more rule values.
//
// The pipeline is: one comparison, then the combination across values (Any
// unless all is present). Encoding transforms arrive in a later story and
// slot in before the comparison.
func Build(mods []string, vals []event.Value) (Matcher, error) {
	var (
		comparison  = "equals"
		comparisons int
		reInsens    bool
		conjoin     bool
	)

	for _, m := range mods {
		switch m {
		case "contains", "startswith", "endswith", "re":
			comparison = m
			comparisons++
		case "all":
			conjoin = true
		case "i":
			reInsens = true
		default:
			return nil, fmt.Errorf("%w %q", ErrUnsupportedModifier, m)
		}
	}
	if comparisons > 1 {
		return nil, fmt.Errorf("%w: more than one comparison in %q", ErrUnsupportedModifier, mods)
	}
	if reInsens && comparison != "re" {
		return nil, fmt.Errorf("%w: i without re in %q", ErrUnsupportedModifier, mods)
	}

	if len(vals) == 0 {
		return nil, errors.New("detection entry has no values")
	}
	perValue := make([]Matcher, 0, len(vals))
	for _, v := range vals {
		m, err := buildOne(v, comparison, reInsens)
		if err != nil {
			return nil, err
		}
		perValue = append(perValue, m)
	}
	if conjoin {
		return All(perValue), nil
	}
	return Any(perValue), nil
}

func buildOne(v event.Value, comparison string, reInsens bool) (Matcher, error) {
	if v.Kind == event.KindNull {
		return Null(), nil
	}
	text, ok := v.Text()
	if !ok {
		return nil, fmt.Errorf("a detection value must be a scalar, got kind %d", v.Kind)
	}
	switch comparison {
	case "contains":
		return Contains(text), nil
	case "startswith":
		return StartsWith(text), nil
	case "endswith":
		return EndsWith(text), nil
	case "re":
		return Regex(text, reInsens)
	default:
		return Equals(text), nil
	}
}
