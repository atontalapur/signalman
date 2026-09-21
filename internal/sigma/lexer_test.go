package sigma

import (
	"errors"
	"testing"
)

func kinds(ts []token) []tokenKind {
	out := make([]tokenKind, len(ts))
	for i, t := range ts {
		out[i] = t.kind
	}
	return out
}

func TestLexBasic(t *testing.T) {
	got, err := lex("selection and not (filter1 or filter2)")
	if err != nil {
		t.Fatalf("lex: %v", err)
	}
	want := []tokenKind{
		tokIdent, tokAnd, tokNot, tokLParen,
		tokIdent, tokOr, tokIdent, tokRParen, tokEOF,
	}
	g := kinds(got)
	if len(g) != len(want) {
		t.Fatalf("got %v want %v", g, want)
	}
	for i := range want {
		if g[i] != want[i] {
			t.Fatalf("token %d: got %v want %v", i, g[i], want[i])
		}
	}
}

func TestLexQuantifierAndGlob(t *testing.T) {
	got, err := lex("1 of selection_* and all of them")
	if err != nil {
		t.Fatalf("lex: %v", err)
	}
	want := []tokenKind{
		tokIdent, tokOf, tokIdent, tokAnd, tokIdent, tokOf, tokIdent, tokEOF,
	}
	g := kinds(got)
	if len(g) != len(want) {
		t.Fatalf("got %v want %v", g, want)
	}
	for i := range want {
		if g[i] != want[i] {
			t.Fatalf("token %d: got %v want %v", i, g[i], want[i])
		}
	}
	if got[2].text != "selection_*" {
		t.Fatalf("glob text = %q want selection_*", got[2].text)
	}
}

func TestLexKeywordsAreCaseInsensitive(t *testing.T) {
	got, err := lex("a AND b OR NOT c")
	if err != nil {
		t.Fatalf("lex: %v", err)
	}
	want := []tokenKind{tokIdent, tokAnd, tokIdent, tokOr, tokNot, tokIdent, tokEOF}
	g := kinds(got)
	if len(g) != len(want) {
		t.Fatalf("got %v want %v", g, want)
	}
	for i := range want {
		if g[i] != want[i] {
			t.Fatalf("token %d: got %v want %v", i, g[i], want[i])
		}
	}
}

func TestLexPipeIsAggregation(t *testing.T) {
	_, err := lex("selection | count() > 5 by User")
	if !errors.Is(err, ErrAggregation) {
		t.Fatalf("err = %v want ErrAggregation", err)
	}
}

func TestLexRejectsUnknownRune(t *testing.T) {
	if _, err := lex("selection & filter"); err == nil {
		t.Fatal("expected error on '&'")
	}
}
