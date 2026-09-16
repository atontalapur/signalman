package event

import (
	"math"
	"testing"
)

func TestValueText(t *testing.T) {
	cases := []struct {
		name string
		in   Value
		want string
		ok   bool
	}{
		{"string", String("abc"), "abc", true},
		{"empty string", String(""), "", true},
		{"int", Int(1234), "1234", true},
		{"negative int", Int(-7), "-7", true},
		{"bool true", Bool(true), "true", true},
		{"bool false", Bool(false), "false", true},
		{"int min", Int(math.MinInt64), "-9223372036854775808", true},
		{"int max", Int(math.MaxInt64), "9223372036854775807", true},
		{"null has no text", Null(), "", false},
		{"zero value is null", Value{}, "", false},
		{"unknown kind has no text", Value{Kind: KindList + 1, S: "x"}, "", false},
		{"list has no text", List(String("a")), "", false},
		{"empty list has no text", List(), "", false},
		{"nested list has no text", List(List(Int(1)), Null()), "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := c.in.Text()
			if ok != c.ok || got != c.want {
				t.Fatalf("Text() = %q,%v want %q,%v", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestNullIsDistinctFromEmptyString(t *testing.T) {
	if Null().Kind == String("").Kind {
		t.Fatal("null and empty string must have different kinds")
	}
}

func TestListKeepsElementsInOrder(t *testing.T) {
	l := List(String("a"), Int(2), Bool(true))
	if l.Kind != KindList || len(l.L) != 3 {
		t.Fatalf("List() = %+v, want KindList with 3 elements", l)
	}
	if l.L[0].Kind != KindString || l.L[1].Kind != KindInt || l.L[2].Kind != KindBool {
		t.Fatalf("List() element kinds = %v %v %v", l.L[0].Kind, l.L[1].Kind, l.L[2].Kind)
	}
	if e := List(); e.Kind != KindList || len(e.L) != 0 {
		t.Fatalf("List() with no args = %+v, want empty KindList", e)
	}
}

func TestEventFieldAbsentIsNull(t *testing.T) {
	ev := &Event{Fields: map[string]Value{"present": String("x")}}
	if got := ev.Field("present"); got.Kind != KindString || got.S != "x" {
		t.Fatalf("Field(present) = %+v, want string x", got)
	}
	if got := ev.Field("missing"); got.Kind != KindNull {
		t.Fatalf("Field(missing).Kind = %v, want KindNull", got.Kind)
	}
}

func TestEventFieldNilMapIsNull(t *testing.T) {
	ev := &Event{}
	if got := ev.Field("anything"); got.Kind != KindNull {
		t.Fatalf("Field on nil Fields = %+v, want KindNull", got)
	}
}

func TestEventFieldExplicitNullIsNull(t *testing.T) {
	ev := &Event{Fields: map[string]Value{"n": Null()}}
	got := ev.Field("n")
	if got.Kind != KindNull {
		t.Fatalf("Field(n) = %+v, want KindNull", got)
	}
	if _, ok := got.Text(); ok {
		t.Fatal("explicit null must have no text")
	}
}
