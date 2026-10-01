package fuzz

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// A free-text fuzz over rule YAML produces almost nothing both engines will
// accept: the first counter run over it reached 684,594 executions with zero
// verdict comparisons, because every mutation broke the YAML or the rule. So
// the mutator drives values, a modifier chain, a field, and a condition
// shape into a rule skeleton that is always valid, and the pressure lands
// where the risk is: the matcher and the modifier expansion.
//
// The cost is that rule-level acceptance divergences are no longer reachable
// from here. Those are pinned by TestKnownAcceptanceDivergences instead,
// which is a better place for them: they are a closed set, not a search.

// fuzzFields are four fields both process_creation bindings map. The
// event carries all of them, so a rule never reads an absent field and the
// SQL three-valued-logic gap stays out of the comparison.
var fuzzFields = []string{"Image", "CommandLine", "ParentImage", "User"}

// modChains are the chains the oracle answers faithfully. Chains it declines
// (cidr, the numeric comparisons, fieldref) are listed in UNSUPPORTED in
// pysigma_eval.py with a section in KNOWN_DIVERGENCES.md; generating them
// here would only produce suppressed cases.
var modChains = []string{
	"",
	"contains",
	"startswith",
	"endswith",
	"re",
	"base64|contains",
	"base64offset|contains",
	"windash|contains",
	"wide|base64|contains",
	"wide|base64offset|contains",
	"utf16|base64|contains",
	"utf16be|base64|contains",
	"all|contains",
	"all",
	"re|i",
}

// condShapes are the condition forms. Each one exercises a different part of
// the parser and the tree walker, and the negated forms are where the two
// engines' treatment of a failed match differs if it differs anywhere.
var condShapes = []string{
	"selection",
	"not selection",
	"selection and filter",
	"selection and not filter",
	"selection or filter",
	"1 of sel*",
	"all of sel*",
}

const fuzzRuleID = "00000000-0000-4000-8000-00000000000a"

// buildRule renders a rule from the mutator's choices. It returns the YAML
// and the event, both keyed by the field names the rule writes, which is
// what the oracle understands. EvalOnce renames them for Signalman.
func buildRule(fieldSel, modSel, condSel uint8, ruleVal, ruleVal2, eventVal string) (string, Fields, error) {
	field := fuzzFields[int(fieldSel)%len(fuzzFields)]
	kind := eventKinds[int(fieldSel)/len(fuzzFields)%len(eventKinds)]
	mods := modChains[int(modSel)%len(modChains)]
	cond := condShapes[int(condSel)%len(condShapes)]

	key := field
	if mods != "" {
		key = field + "|" + mods
	}

	// all needs more than one value to mean anything, so an all chain gets a
	// two-value list and every other chain a scalar.
	value := quoted(ruleVal)
	if strings.HasPrefix(mods, "all") {
		value = sequence(ruleVal, ruleVal2)
	}

	detection := map[string]any{
		"selection": map[string]any{key: value},
		"condition": cond,
	}
	if strings.Contains(cond, "filter") {
		detection["filter"] = map[string]any{"User": quoted(ruleVal2)}
	}
	if strings.Contains(cond, "sel*") {
		// Quantifier expansion needs more than one matching identifier, and
		// selection alone does not match sel* in a way that proves anything.
		detection["sel1"] = map[string]any{key: value}
		detection["sel2"] = map[string]any{"ParentImage|contains": quoted(ruleVal2)}
	}

	doc := map[string]any{
		"title":     "fuzz",
		"id":        fuzzRuleID,
		"logsource": map[string]any{"product": "windows", "category": "process_creation"},
		"detection": detection,
	}

	// Marshalled rather than templated: the mutator produces arbitrary
	// strings, and yaml.Marshal is the only thing that reliably quotes them.
	// A hand-built template would report divergences that are really just
	// rules one side failed to parse.
	b, err := yaml.Marshal(doc)
	if err != nil {
		return "", nil, err
	}

	// The event carries every mapped field. The chosen one gets the
	// mutator's value in the chosen kind; the rest get fixed strings so the
	// rule shape, not the field set, is what varies.
	ev := Fields{
		"Image":       `C:\Windows\System32\rundll32.exe`,
		"CommandLine": `rundll32.exe -sta foo.dll,Entry`,
		"ParentImage": `C:\Windows\explorer.exe`,
		"User":        `CORP\alice`,
		field:         eventValue(kind, eventVal),
	}
	return string(b), ev, nil
}

// eventKinds are the value types the chosen field can carry. Rule values
// stay strings: what varies is how a string rule compares against a typed
// event value, which is where an engine's coercion rules show.
var eventKinds = []string{"string", "int", "null"}

// eventValue renders the mutator's value in a kind. An int that does not
// parse stays a string rather than becoming a made-up number, so the int
// kind is only exercised by digit strings the mutator actually produced.
func eventValue(kind, s string) any {
	switch kind {
	case "int":
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i
		}
		return s
	case "null":
		return nil
	default:
		return s
	}
}

// quoted renders a value as a double-quoted YAML scalar. Left to itself,
// yaml.Marshal emits the shortest form it can, and the shortest form of "="
// is a bare = , which PyYAML reads as the yaml.org 2002:value tag and
// refuses. Those are differences between two YAML libraries, not between two
// Sigma engines, and every one of them would surface as a false divergence.
// Double quoting is the one style both parsers read back as the same string.
func quoted(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: s}
}

func sequence(vals ...string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode}
	for _, v := range vals {
		n.Content = append(n.Content, quoted(v))
	}
	return n
}

// reSafe reports whether a pattern is safe to hand to both regex engines.
// Go's RE2 has no backtracking and Python's engine does, so a pattern like
// (a+)+$ answers in microseconds on one side and runs for minutes on the
// other. A timeout there is measured as an unevaluated case, not a
// divergence, but generating them on purpose wastes most of a fuzz run.
func reSafe(pattern string) bool {
	if len(pattern) > 64 {
		return false
	}
	nested := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '(':
			nested++
		case '*', '+', '{':
			if nested > 0 {
				return false
			}
		}
	}
	return true
}

func init() {
	// Catches a typo in a chain table entry at test start rather than as a
	// wall of suppressed cases.
	for _, m := range modChains {
		for _, part := range strings.Split(m, "|") {
			if part == "" {
				continue
			}
			if strings.ContainsAny(part, " \t") {
				panic(fmt.Sprintf("modifier chain %q has whitespace", m))
			}
		}
	}
}
