package event

import "testing"

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
		{"null has no text", Null(), "", false},
		{"list has no text", List(String("a")), "", false},
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

func TestEventFieldAbsentIsNull(t *testing.T) {
	ev := &Event{Fields: map[string]Value{"present": String("x")}}
	if got := ev.Field("present"); got.Kind != KindString || got.S != "x" {
		t.Fatalf("Field(present) = %+v, want string x", got)
	}
	if got := ev.Field("missing"); got.Kind != KindNull {
		t.Fatalf("Field(missing).Kind = %v, want KindNull", got.Kind)
	}
}
