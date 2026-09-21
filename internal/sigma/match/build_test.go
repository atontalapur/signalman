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
