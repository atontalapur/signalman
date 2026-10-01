package fuzz

import (
	"strings"
	"testing"
)

func TestReSafe(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    bool
	}{
		{"plain anchor, no groups", "^Power", true},
		{"quantifier with no group at all", "a+b*c", true},
		{"quantifier nested inside a group", "(a+)+$", false},
		{"quantifier after a closing paren still flagged", "(abc)d+", false},
		{"over the length cap", strings.Repeat("a", 65), false},
		{"at the length cap", strings.Repeat("a", 64), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := reSafe(c.pattern); got != c.want {
				t.Fatalf("reSafe(%q) = %v, want %v", c.pattern, got, c.want)
			}
		})
	}
}

// buildRule's condition shapes drive which extra detection blocks appear in
// the rendered rule. Two of the seven shapes ("selection or filter" and "all
// of sel*") are never reached by FuzzAgainstPySigma's seed corpus, so they
// have no coverage unless exercised directly.
func TestBuildRuleConditionShapes(t *testing.T) {
	for condSel, shape := range condShapes {
		t.Run(shape, func(t *testing.T) {
			yamlOut, ev, err := buildRule(0, 0, uint8(condSel), "needle", "other", "eventval")
			if err != nil {
				t.Fatalf("buildRule: %v", err)
			}
			if !strings.Contains(yamlOut, "condition: "+shape) {
				t.Fatalf("rule does not declare condition %q:\n%s", shape, yamlOut)
			}
			wantFilter := strings.Contains(shape, "filter")
			if strings.Contains(yamlOut, "filter:") != wantFilter {
				t.Fatalf("filter block presence = %v, want %v, for shape %q:\n%s",
					strings.Contains(yamlOut, "filter:"), wantFilter, shape, yamlOut)
			}
			wantQuantifier := strings.Contains(shape, "sel*")
			hasSelIdentifiers := strings.Contains(yamlOut, "sel1:") && strings.Contains(yamlOut, "sel2:")
			if hasSelIdentifiers != wantQuantifier {
				t.Fatalf("sel1/sel2 identifiers presence = %v, want %v, for shape %q:\n%s",
					hasSelIdentifiers, wantQuantifier, shape, yamlOut)
			}
			if _, ok := ev["Image"]; !ok {
				t.Fatalf("event must always carry the fixed Image field, got %v", ev)
			}
		})
	}
}

// The "all" and "all|contains" modifier chains render the rule value as a
// YAML sequence instead of a scalar. Neither is reached by the seed corpus
// (which only ever selects modSel values landing on the other 13 chains
// under go test's default, non-fuzzing run), so the sequence branch has no
// coverage without a direct test.
func TestBuildRuleAllModifierProducesSequence(t *testing.T) {
	allIdx := -1
	for i, m := range modChains {
		if m == "all" {
			allIdx = i
		}
	}
	if allIdx < 0 {
		t.Fatal("modChains no longer has a bare \"all\" entry; update the test")
	}

	yamlOut, _, err := buildRule(0, uint8(allIdx), 0, "alpha", "beta", "eventval")
	if err != nil {
		t.Fatalf("buildRule: %v", err)
	}
	if !strings.Contains(yamlOut, "Image|all:") {
		t.Fatalf("key should carry the all modifier, got:\n%s", yamlOut)
	}
	if !strings.Contains(yamlOut, `"alpha"`) || !strings.Contains(yamlOut, `"beta"`) {
		t.Fatalf("all needs both values rendered as a sequence, got:\n%s", yamlOut)
	}
}

func TestBuildRuleKeyIncludesModifierChain(t *testing.T) {
	bare, _, err := buildRule(0, 0, 0, "x", "y", "z")
	if err != nil {
		t.Fatalf("buildRule: %v", err)
	}
	if !strings.Contains(bare, "Image:") || strings.Contains(bare, "Image|") {
		t.Fatalf("an empty modifier chain must leave a bare field key, got:\n%s", bare)
	}

	containsIdx := -1
	for i, m := range modChains {
		if m == "contains" {
			containsIdx = i
		}
	}
	withMod, _, err := buildRule(0, uint8(containsIdx), 0, "x", "y", "z")
	if err != nil {
		t.Fatalf("buildRule: %v", err)
	}
	if !strings.Contains(withMod, "Image|contains:") {
		t.Fatalf("a non-empty modifier chain must be appended to the field key, got:\n%s", withMod)
	}
}

// The high bits of fieldSel pick the chosen field's event type: string,
// integer when the fuzzed value parses as one, or null. The other fields
// stay strings, so only the chosen one varies.
func TestBuildRuleEventKinds(t *testing.T) {
	n := uint8(len(fuzzFields))
	cases := []struct {
		name     string
		fieldSel uint8
		eventVal string
		want     any
	}{
		{"string", 0, "443", "443"},
		{"int", n, "443", int64(443)},
		{"int falls back to string", n, "abc", "abc"},
		{"negative int", n, "-7", int64(-7)},
		{"null", 2 * n, "anything", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ev, err := buildRule(c.fieldSel, 0, 0, "x", "y", c.eventVal)
			if err != nil {
				t.Fatal(err)
			}
			field := fuzzFields[int(c.fieldSel)%len(fuzzFields)]
			got, ok := ev[field]
			if !ok {
				t.Fatalf("event lost field %s", field)
			}
			if got != c.want {
				t.Fatalf("ev[%s] = %#v, want %#v", field, got, c.want)
			}
			for _, f := range fuzzFields {
				if _, isStr := ev[f].(string); f != field && !isStr {
					t.Fatalf("unchosen field %s = %#v, want a string", f, ev[f])
				}
			}
		})
	}
}
