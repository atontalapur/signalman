package match

import (
	"errors"
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

func build(t *testing.T, mods string, vals ...string) Matcher {
	t.Helper()
	var vs []event.Value
	for _, v := range vals {
		vs = append(vs, event.String(v))
	}
	var ms []string
	if mods != "" {
		ms = strings.Split(mods, "|")
	}
	m, err := Build(ms, vs)
	if err != nil {
		t.Fatalf("Build(%q): %v", mods, err)
	}
	return m
}

func TestBuildPlainIsEquals(t *testing.T) {
	m := build(t, "", "cmd.exe")
	if !hit(t, m, event.String("CMD.EXE")) || hit(t, m, event.String("cmd.exe.bak")) {
		t.Fatal("no modifier is a case-insensitive equals")
	}
}

func TestBuildListIsOr(t *testing.T) {
	m := build(t, "contains", "alpha", "beta")
	if !hit(t, m, event.String("xxbetaxx")) {
		t.Fatal("a value list is an OR")
	}
}

func TestBuildAllIsAnd(t *testing.T) {
	m := build(t, "contains|all", "alpha", "beta")
	if hit(t, m, event.String("xxbetaxx")) {
		t.Fatal("all requires every value")
	}
	if !hit(t, m, event.String("alpha beta")) {
		t.Fatal("all matches when every value is present")
	}
}

func TestBuildStartsEndsWith(t *testing.T) {
	if !hit(t, build(t, "startswith", `C:\Win`), event.String(`c:\windows`)) {
		t.Fatal("startswith")
	}
	if !hit(t, build(t, "endswith", `\cmd.exe`), event.String(`C:\CMD.EXE`)) {
		t.Fatal("endswith")
	}
}

func TestBuildRegexDefaultsCaseSensitive(t *testing.T) {
	m := build(t, "re", "^Power")
	if hit(t, m, event.String("powershell")) {
		t.Fatal("re is case sensitive by default")
	}
	mi := build(t, "re|i", "^Power")
	if !hit(t, mi, event.String("powershell")) {
		t.Fatal("re|i folds case")
	}
}

func TestBuildRejectsUnknownModifier(t *testing.T) {
	_, err := Build([]string{"expandvar"}, []event.Value{event.String("x")})
	if err == nil || !strings.Contains(err.Error(), "expandvar") {
		t.Fatalf("expected an error naming the modifier, got %v", err)
	}
	if !errors.Is(err, ErrUnsupportedModifier) {
		t.Fatalf("error must wrap ErrUnsupportedModifier, got %v", err)
	}
}

func TestBuildRejectsBadChains(t *testing.T) {
	cases := []string{
		"contains|startswith", // two comparisons
		"re|contains",         // two comparisons
		"i",                   // i without re
		"contains|i",          // i without re
		"base64|re",           // a transform cannot feed a regex
		"base64|cidr",         // nor a cidr prefix
		"utf16le|gt",          // nor a numeric comparison
		"windash|fieldref",    // nor a field reference
		"fieldref|contains",   // a field reference has no comparison to pick
		"lt|gt",               // two numeric comparisons
		"cidr|contains",       // cidr is itself the comparison
	}
	for _, mods := range cases {
		_, err := Build(strings.Split(mods, "|"), []event.Value{event.String("x")})
		if err == nil {
			t.Errorf("Build(%q): expected an error", mods)
			continue
		}
		if !errors.Is(err, ErrUnsupportedModifier) {
			t.Errorf("Build(%q): error must wrap ErrUnsupportedModifier, got %v", mods, err)
		}
	}
}

func TestBuildRejectsInvalidRegex(t *testing.T) {
	if _, err := Build([]string{"re"}, []event.Value{event.String("(")}); err == nil {
		t.Fatal("an invalid regex must be an error")
	}
}

func TestBuildRejectsNoValuesAndListValues(t *testing.T) {
	if _, err := Build(nil, nil); err == nil {
		t.Fatal("no values must be an error")
	}
	if _, err := Build(nil, []event.Value{event.List(event.String("a"))}); err == nil {
		t.Fatal("a list is not a scalar detection value")
	}
}

func TestBuildNullValue(t *testing.T) {
	m, err := Build(nil, []event.Value{event.Null()})
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, m, event.Null()) {
		t.Fatal("a null value builds a null matcher")
	}
	if hit(t, m, event.String("")) {
		t.Fatal("null does not match an empty string")
	}
}

func TestBuildIntValueComparesAsText(t *testing.T) {
	m, err := Build(nil, []event.Value{event.Int(4688)})
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, m, event.String("4688")) || !hit(t, m, event.Int(4688)) {
		t.Fatal("an int rule value compares by its decimal text")
	}
}

func TestBuildAllWithSingleValue(t *testing.T) {
	m := build(t, "contains|all", "alpha")
	if !hit(t, m, event.String("xxalphaxx")) || hit(t, m, event.String("beta")) {
		t.Fatal("all over one value is a plain contains")
	}
}

func TestBuildAllWithoutComparison(t *testing.T) {
	m := build(t, "all", "a", "b")
	if hit(t, m, event.String("a")) {
		t.Fatal("all with equals over a scalar cannot satisfy two different values")
	}
	if !hit(t, m, event.List(event.String("a"), event.String("b"))) {
		t.Fatal("all with equals is satisfied by a list holding every value")
	}
}

func TestBuildModifierOrderDoesNotMatter(t *testing.T) {
	a := build(t, "contains|all", "alpha", "beta")
	b := build(t, "all|contains", "alpha", "beta")
	c := build(t, "i|re", "^alpha")
	for _, in := range []string{"alpha beta", "beta", "ALPHA"} {
		if hit(t, a, event.String(in)) != hit(t, b, event.String(in)) {
			t.Fatalf("contains|all and all|contains differ on %q", in)
		}
	}
	if !hit(t, c, event.String("ALPHA")) {
		t.Fatal("i|re is the same as re|i")
	}
}

func TestBuildRegexInList(t *testing.T) {
	m := build(t, "re", "^a", "b$")
	if !hit(t, m, event.String("xb")) || hit(t, m, event.String("xbx")) {
		t.Fatal("a regex list is an OR of compiled patterns")
	}
	if _, err := Build([]string{"re"}, []event.Value{event.String("ok"), event.String("(")}); err == nil {
		t.Fatal("an invalid regex anywhere in the list must be an error")
	}
}

func TestBuildBoolValueComparesAsText(t *testing.T) {
	m, err := Build(nil, []event.Value{event.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, m, event.String("TRUE")) || !hit(t, m, event.Bool(true)) || hit(t, m, event.Bool(false)) {
		t.Fatal("a bool rule value compares by its text")
	}
}

func TestBuildRejectsNullWithComparison(t *testing.T) {
	for _, mods := range []string{"contains", "startswith", "endswith", "re"} {
		_, err := Build([]string{mods}, []event.Value{event.Null()})
		if err == nil || !errors.Is(err, ErrUnsupportedModifier) {
			t.Errorf("Build(%q, null): want ErrUnsupportedModifier, got %v", mods, err)
		}
	}
}

func TestBuildListValueErrorNamesKind(t *testing.T) {
	_, err := Build(nil, []event.Value{event.List()})
	if err == nil || !strings.Contains(err.Error(), "list") {
		t.Fatalf("want an error naming the kind, got %v", err)
	}
}

func TestBuildBase64OffsetContains(t *testing.T) {
	m := build(t, "base64offset|contains", "MiniDump")
	if !hit(t, m, event.String(Base64("cmd /c MiniDump 624"))) {
		t.Fatal("base64offset|contains must find the encoded plaintext")
	}
	if hit(t, m, event.String(Base64("cmd /c whoami"))) {
		t.Fatal("an unrelated command must not match")
	}
}

func TestBuildBase64OffsetAtEveryAlignment(t *testing.T) {
	m := build(t, "base64offset|contains", "MiniDump")
	for _, pad := range []string{"", "x", "xx", "xxx"} {
		if !hit(t, m, event.String(Base64(pad+"MiniDump tail"))) {
			t.Fatalf("alignment %q missed", pad)
		}
	}
}

func TestBuildPlainBase64IsEquals(t *testing.T) {
	m := build(t, "base64", "whoami")
	if !hit(t, m, event.String(Base64("whoami"))) {
		t.Fatal("base64 with no comparison is an equals on the encoded form")
	}
	if hit(t, m, event.String("whoami")) {
		t.Fatal("the plaintext itself must not match a base64 rule value")
	}
}

func TestBuildUTF16ThenBase64OrderMatters(t *testing.T) {
	m := build(t, "utf16le|base64offset|contains", "IEX")
	encoded := Base64(UTF16LE("xIEX payload"))
	if !hit(t, m, event.String(encoded)) {
		t.Fatal("utf16le is applied before base64 when chained")
	}
	if hit(t, m, event.String(Base64("IEX payload"))) {
		t.Fatal("the plain ASCII encoding must not match a utf16le rule value")
	}
}

func TestBuildWideIsUTF16LE(t *testing.T) {
	a := build(t, "wide|base64offset|contains", "IEX")
	b := build(t, "utf16le|base64offset|contains", "IEX")
	in := event.String(Base64(UTF16LE("xIEX payload")))
	if hit(t, a, in) != hit(t, b, in) || !hit(t, a, in) {
		t.Fatal("wide is an alias for utf16le")
	}
}

func TestBuildUTF16BEAndBOM(t *testing.T) {
	be := build(t, "utf16be|base64offset|contains", "IEX")
	if !hit(t, be, event.String(Base64(UTF16BE("xIEX payload")))) {
		t.Fatal("utf16be")
	}
	bom := build(t, "utf16|base64|contains", "IEX")
	if !hit(t, bom, event.String(Base64(UTF16("IEX")))) {
		t.Fatal("utf16 carries a BOM and still matches its own encoding")
	}
}

func TestBuildWindash(t *testing.T) {
	m := build(t, "contains|windash", "-encodedcommand")
	if !hit(t, m, event.String("powershell –EncodedCommand SQBFAFgA")) {
		t.Fatal("windash must accept an en dash")
	}
	if !hit(t, m, event.String("powershell /encodedcommand SQBFAFgA")) {
		t.Fatal("windash must accept a slash")
	}
	if !hit(t, m, event.String("powershell -EncodedCommand SQBFAFgA")) {
		t.Fatal("windash must still accept the written hyphen")
	}
	if hit(t, m, event.String("powershell encodedcommand")) {
		t.Fatal("the dash is not optional, only variable")
	}
}

func TestBuildWindashOverCapIsAModifierError(t *testing.T) {
	_, err := Build([]string{"windash", "contains"},
		[]event.Value{event.String("-a -b -c -d -e -f")})
	if err == nil || !errors.Is(err, ErrUnsupportedModifier) {
		t.Fatalf("want ErrUnsupportedModifier for an over-cap windash, got %v", err)
	}
}

func TestBuildNumericComparison(t *testing.T) {
	m := build(t, "gte", "1024")
	if !hit(t, m, event.Int(8080)) || hit(t, m, event.Int(80)) {
		t.Fatal("gte on a port field")
	}
	if _, err := Build([]string{"lt"}, []event.Value{event.String("many")}); err == nil {
		t.Fatal("a non-numeric rule value for lt must be a load error")
	}
}

func TestBuildCIDR(t *testing.T) {
	m := build(t, "cidr", "10.0.0.0/8")
	if !hit(t, m, event.String("10.9.9.9")) || hit(t, m, event.String("192.168.1.1")) {
		t.Fatal("cidr")
	}
	if _, err := Build([]string{"cidr"}, []event.Value{event.String("10.0.0.0/33")}); err == nil {
		t.Fatal("a bad prefix must be a load error")
	}
}

func TestBuildFieldRef(t *testing.T) {
	m, err := Build([]string{"fieldref"}, []event.Value{event.String("ParentUser")})
	if err != nil {
		t.Fatal(err)
	}
	ev := &event.Event{Fields: map[string]event.Value{
		"User":       event.String("SYSTEM"),
		"ParentUser": event.String("system"),
	}}
	if !m.Match(ev.Field("User"), ev) {
		t.Fatal("fieldref through Build")
	}
}

func TestBuildTransformsAreDeterministic(t *testing.T) {
	// Same chain, same values, same matcher behavior on twenty builds. The
	// transforms fan out into a list of variants, and that list must not
	// depend on map iteration or anything else that moves. The chain is
	// written in the order a real rule writes it: dash variants first, then
	// the encodings, because each transform feeds the next.
	in := event.String(Base64(UTF16LE("x-EncodedCommand y")))
	for i := 0; i < 20; i++ {
		m := build(t, "windash|utf16le|base64offset|contains", "-EncodedCommand")
		if !hit(t, m, in) {
			t.Fatalf("build %d disagreed with build 0", i)
		}
	}
}

func TestBuildEncodedValuesAreCaseSensitiveInPractice(t *testing.T) {
	// Sigma string matching is case insensitive, and that fold is applied to
	// the encoded text. Encoding happens before the fold, so a rule value
	// written in the wrong case encodes to different base64 characters and
	// does not match. Rule authors must write the case the attacker used.
	// This is a property of the encoding, not a choice made here.
	m := build(t, "base64offset|contains", "MINIDUMP")
	if hit(t, m, event.String(Base64("cmd /c MiniDump 624"))) {
		t.Fatal("an encoded value in the wrong case must not match")
	}
}

func TestBuildEmptyValueUnderAnEncodingIsALoadError(t *testing.T) {
	// base64offset of an empty plaintext yields three empty variants, which
	// expand drops. An entry with nothing left to match could never fire, so
	// it fails at load rather than silently never matching.
	for _, mods := range []string{"base64offset", "utf16le", "base64offset|contains"} {
		_, err := Build(strings.Split(mods, "|"), []event.Value{event.String("")})
		if err == nil || !errors.Is(err, ErrUnsupportedModifier) {
			t.Errorf("Build(%q, \"\"): want ErrUnsupportedModifier, got %v", mods, err)
		}
	}
}

func TestBuildRejectsNullWithFieldRefOrTransform(t *testing.T) {
	// Both disjuncts of the null guard, not just the comparison one.
	for _, mods := range []string{"fieldref", "base64", "utf16le", "windash"} {
		_, err := Build([]string{mods}, []event.Value{event.Null()})
		if err == nil || !errors.Is(err, ErrUnsupportedModifier) {
			t.Errorf("Build(%q, null): want ErrUnsupportedModifier, got %v", mods, err)
		}
	}
}

func TestBuildStartsAndEndsWithUnderATransform(t *testing.T) {
	// Every other encoding test pairs with contains. startswith and endswith
	// run the same fan-out through a different comparison.
	pre := build(t, "utf16le|startswith", "IEX")
	if !hit(t, pre, event.String(UTF16LE("IEX payload"))) {
		t.Fatal("utf16le|startswith")
	}
	if hit(t, pre, event.String(UTF16LE("payload IEX"))) {
		t.Fatal("startswith must still anchor at the start")
	}
	suf := build(t, "utf16le|endswith", "IEX")
	if !hit(t, suf, event.String(UTF16LE("payload IEX"))) {
		t.Fatal("utf16le|endswith")
	}
	if hit(t, suf, event.String(UTF16LE("IEX payload"))) {
		t.Fatal("endswith must still anchor at the end")
	}
}

func TestBuildRejectsEveryNumericComparisonUnderATransform(t *testing.T) {
	// The validateChain switch lists four numeric operators; only gt was
	// exercised, so the other three arms were unproven.
	for _, op := range []string{"lt", "lte", "gt", "gte"} {
		_, err := Build([]string{"utf16le", op}, []event.Value{event.String("5")})
		if err == nil || !errors.Is(err, ErrUnsupportedModifier) {
			t.Errorf("Build(utf16le|%s): want ErrUnsupportedModifier, got %v", op, err)
		}
	}
}

func TestBuildThreadsEveryNumericComparison(t *testing.T) {
	cases := []struct {
		mods string
		in   int64
		want bool
	}{
		{"lt", 4, true}, {"lt", 5, false},
		{"lte", 5, true}, {"lte", 6, false},
		{"gt", 6, true}, {"gt", 5, false},
		{"gte", 5, true}, {"gte", 4, false},
	}
	for _, c := range cases {
		m := build(t, c.mods, "5")
		if got := hit(t, m, event.Int(c.in)); got != c.want {
			t.Errorf("Build(%q) on %d = %v, want %v", c.mods, c.in, got, c.want)
		}
	}
}

func TestBuildCapsTheCombinedTransformFanOut(t *testing.T) {
	// windash alone is capped at five dash positions, 3125 variants. Chaining
	// another transform multiplies that, and the per-transform cap cannot see
	// it. A chain that would build thousands of matchers, each scanned on
	// every event, is rejected at load with the count in the message.
	_, err := Build([]string{"windash", "base64offset", "contains"},
		[]event.Value{event.String("-a -b -c -d -e")})
	if err == nil || !errors.Is(err, ErrUnsupportedModifier) {
		t.Fatalf("want ErrUnsupportedModifier for an over-budget chain, got %v", err)
	}
	if !strings.Contains(err.Error(), "variant") {
		t.Fatalf("the error must say what blew the budget: %v", err)
	}
}

func TestBuildAllowsRealisticChainsUnderTheBudget(t *testing.T) {
	// The corpus chains windash with contains and nothing else, and pairs
	// base64offset only with contains. Neither may be rejected.
	m := build(t, "windash|contains", "-a -b -c -d -e")
	if !hit(t, m, event.String("cmd /a /b /c /d /e")) {
		t.Fatal("five dash positions alone is 3125 variants and stays legal")
	}
	enc := build(t, "utf16le|base64offset|contains", "IEX")
	if !hit(t, enc, event.String(Base64(UTF16LE("xIEX payload")))) {
		t.Fatal("a two-transform encoding chain stays legal")
	}
}

// A wildcard cannot survive base64: the encoded bytes of '*' are not a
// wildcard, so an author who writes one gets a rule that matches something
// other than what it says. pySigma rejects the same rules.
func TestBuildRejectsAWildcardUnderBase64(t *testing.T) {
	cases := []struct{ mods, val string }{
		{"base64|contains", "*foo*"},
		{"base64", "foo?"},
		{"base64offset|contains", "a*b"},
		{"utf16le|base64offset|contains", "IEX*"},
		{"windash|base64|contains", "-e *"},
	}
	for _, c := range cases {
		_, err := Build(strings.Split(c.mods, "|"), []event.Value{event.String(c.val)})
		if err == nil {
			t.Errorf("Build(%q, %q): expected an error", c.mods, c.val)
			continue
		}
		if !errors.Is(err, ErrUnsupportedModifier) {
			t.Errorf("Build(%q, %q): error must wrap ErrUnsupportedModifier, got %v", c.mods, c.val, err)
		}
	}
}

// An escaped star is a literal, not a wildcard, so it encodes like any other
// byte. A wildcard under a transform that keeps it (wide, windash) is not
// affected.
func TestBuildAllowsLiteralStarsAndOtherTransforms(t *testing.T) {
	cases := []struct{ mods, val string }{
		{"base64|contains", `a\*b`},
		{"wide|contains", "a*b"},
		{"windash|contains", "-e *"},
	}
	for _, c := range cases {
		if _, err := Build(strings.Split(c.mods, "|"), []event.Value{event.String(c.val)}); err != nil {
			t.Errorf("Build(%q, %q): %v", c.mods, c.val, err)
		}
	}
}

// Under base64 the value is plaintext to encode, so Sigma's escapes are
// resolved first, as the wildcard matcher resolves them: \* and \? are a
// literal star and question mark, \\ is one backslash, and any other
// backslash is itself. pySigma encodes the same bytes.
func TestBuildBase64EncodesTheUnescapedPlaintext(t *testing.T) {
	cases := []struct{ val, plain, notPlain string }{
		{`a\*b`, "a*b", `a\*b`},
		{`a\?b`, "a?b", `a\?b`},
		{`a\\b`, `a\b`, `a\\b`},
		{`a\b`, `a\b`, "ab"},
	}
	for _, c := range cases {
		m := build(t, "base64", c.val)
		if !hit(t, m, event.String(Base64(c.plain))) {
			t.Errorf("base64 %q must match the encoding of %q", c.val, c.plain)
		}
		if hit(t, m, event.String(Base64(c.notPlain))) {
			t.Errorf("base64 %q must not match the encoding of %q", c.val, c.notPlain)
		}
	}
}

// Both load-time fan-out budgets wrap ErrFanOut, so the differential
// fuzzer can recognize the documented divergence by type.
func TestFanOutBudgetsWrapErrFanOut(t *testing.T) {
	for _, c := range []struct{ mods, val string }{
		{"windash|contains", "-a -b -c -d -e -f"},
		{"windash|base64offset|contains", "-a -b -c -d -e"},
	} {
		_, err := Build(strings.Split(c.mods, "|"), []event.Value{event.String(c.val)})
		if !errors.Is(err, ErrFanOut) || !errors.Is(err, ErrUnsupportedModifier) {
			t.Errorf("Build(%q, %q) = %v, want ErrFanOut and ErrUnsupportedModifier", c.mods, c.val, err)
		}
	}
}
