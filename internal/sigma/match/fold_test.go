package match

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/atontalapur/signalman/internal/event"
)

// Case folding never turns a non-ASCII rune into an ASCII one. Go's
// unicode.ToLower maps U+0130 (dotted capital I) to 'i' and U+212A (Kelvin
// sign) to 'k', so a rule value "İ" used to match every 'i'. The pySigma
// differential fuzzer found it (inputs 6c2f3783bbcc1257, af3c814fc5bfa650).
func TestFoldNeverMapsNonASCIIToASCII(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		f := foldRune(r)
		if (r < utf8.RuneSelf) != (f < utf8.RuneSelf) {
			t.Fatalf("foldRune(%U) = %U crosses the ASCII boundary", r, f)
		}
		if r >= utf8.RuneSelf && f != unicode.ToLower(r) && f != r {
			t.Fatalf("foldRune(%U) = %U, want ToLower or itself", r, f)
		}
		if r < utf8.RuneSelf && f != unicode.ToLower(r) {
			t.Fatalf("ASCII %U must fold as before", r)
		}
	}
}

// The fieldref comparison follows the same rule: two runes are equal under
// folding only on the same side of the ASCII boundary.
func TestEqualFoldNeverPairsASCIIWithNonASCII(t *testing.T) {
	for r := rune(utf8.RuneSelf); r <= unicode.MaxRune; r++ {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < utf8.RuneSelf && EqualFold(string(r), string(f)) {
				t.Fatalf("EqualFold(%U, %U) is true across the ASCII boundary", r, f)
			}
		}
	}
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"ABC", "abc", true},
		{"Äb", "äB", true},
		{"ДОМ", "дом", true},
		{"\u212a", "k", false},
		{"\u017f", "s", false},
		{"\u212a", "\u212a", true},
		{"ab", "abc", false},
		{"a\xffb", "a\xfeb", true}, // both read as U+FFFD, as strings.EqualFold reads them
	} {
		if got := EqualFold(c.a, c.b); got != c.want {
			t.Errorf("EqualFold(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
		if strings.ContainsAny(c.a+c.b, "\u212a\u017f") {
			continue
		}
		if got := strings.EqualFold(c.a, c.b); got != c.want {
			t.Errorf("strings.EqualFold(%q, %q) = %v: outside the boundary cases EqualFold must agree", c.a, c.b, got)
		}
	}
}

func TestDottedCapitalIMatchesOnlyItself(t *testing.T) {
	cases := []struct {
		mods, val, text string
		want            bool
	}{
		{"contains", "İ", `C:\Windows\explorer.exe`, false},
		{"contains", "I", "İ", false},
		{"contains", "İ", "xİy", true},
		{"", "İ", "İ", true},
		{"", "\u212a", "k", false},
		{"", "K", "\u212a", false},
		{"", "É", "é", true},
		{"contains", "ДОМ", "мой дом", true},
	}
	for _, c := range cases {
		var mods []string
		if c.mods != "" {
			mods = strings.Split(c.mods, "|")
		}
		m, err := Build(mods, []event.Value{event.String(c.val)})
		if err != nil {
			t.Fatal(err)
		}
		if got := hit(t, m, event.String(c.text)); got != c.want {
			t.Errorf("%s %q against %q = %v, want %v", c.mods, c.val, c.text, got, c.want)
		}
		if got := string(AppendFold(nil, c.text)) == Fold(c.text); !got {
			t.Errorf("AppendFold and Fold disagree on %q", c.text)
		}
	}
}
