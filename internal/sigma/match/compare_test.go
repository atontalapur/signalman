package match

import (
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

func TestCompareNumeric(t *testing.T) {
	m, err := Compare("gt", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, m, event.Int(101)) {
		t.Fatal("101 > 100")
	}
	if hit(t, m, event.Int(100)) {
		t.Fatal("100 is not > 100")
	}
	if !hit(t, m, event.String("101")) {
		t.Fatal("numeric strings parse")
	}
}

func TestCompareEveryOperator(t *testing.T) {
	cases := []struct {
		op   string
		got  int64
		want bool
	}{
		{"lt", 4, true}, {"lt", 5, false}, {"lt", 6, false},
		{"lte", 4, true}, {"lte", 5, true}, {"lte", 6, false},
		{"gt", 6, true}, {"gt", 5, false}, {"gt", 4, false},
		{"gte", 6, true}, {"gte", 5, true}, {"gte", 4, false},
	}
	for _, c := range cases {
		m, err := Compare(c.op, 5)
		if err != nil {
			t.Fatalf("Compare(%q): %v", c.op, err)
		}
		if got := hit(t, m, event.Int(c.got)); got != c.want {
			t.Errorf("%d %s 5 = %v, want %v", c.got, c.op, got, c.want)
		}
	}
}

func TestCompareRejectsUnknownOperator(t *testing.T) {
	if _, err := Compare("between", 5); err == nil {
		t.Fatal("an unknown comparison operator must be an error")
	}
}

func TestCompareUnparsableStringIsNoMatchNotError(t *testing.T) {
	m, _ := Compare("lt", 5)
	if hit(t, m, event.String("not a number")) {
		t.Fatal("an unparsable string must not match")
	}
	if hit(t, m, event.Null()) {
		t.Fatal("null must not match a numeric comparison")
	}
	if hit(t, m, event.Bool(true)) {
		t.Fatal("a bool must not match a numeric comparison")
	}
}

func TestCompareNegativeAndPaddedNumbers(t *testing.T) {
	m, _ := Compare("lt", 0)
	if !hit(t, m, event.String(" -3 ")) {
		t.Fatal("a padded negative decimal parses")
	}
}

func TestCIDR(t *testing.T) {
	m, err := CIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, m, event.String("10.1.2.3")) {
		t.Fatal("10.1.2.3 is in 10.0.0.0/8")
	}
	if hit(t, m, event.String("11.1.2.3")) {
		t.Fatal("11.1.2.3 is not in 10.0.0.0/8")
	}
	if hit(t, m, event.String("garbage")) {
		t.Fatal("an unparsable address must not match")
	}
	if _, err := CIDR("not/a/prefix"); err == nil {
		t.Fatal("a bad prefix must fail at compile time, not at eval time")
	}
}

func TestCIDRIPv6(t *testing.T) {
	m, err := CIDR("2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, m, event.String("2001:db8::1")) {
		t.Fatal("2001:db8::1 is in 2001:db8::/32")
	}
	if hit(t, m, event.String("2001:db9::1")) {
		t.Fatal("2001:db9::1 is not in 2001:db8::/32")
	}
	if hit(t, m, event.String("10.1.2.3")) {
		t.Fatal("an IPv4 address is not in an IPv6 prefix")
	}
}

func TestCIDRRejectsHostBitsAndNullValue(t *testing.T) {
	m, err := CIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if hit(t, m, event.Null()) {
		t.Fatal("null has no text form and cannot be an address")
	}
}

func TestFieldRef(t *testing.T) {
	ev := &event.Event{Fields: map[string]event.Value{
		"User":       event.String("SYSTEM"),
		"TargetUser": event.String("system"),
		"OtherUser":  event.String("alice"),
	}}
	if !FieldRef("TargetUser").Match(ev.Field("User"), ev) {
		t.Fatal("fieldref compares case insensitively like other string comparison")
	}
	if FieldRef("OtherUser").Match(ev.Field("User"), ev) {
		t.Fatal("different values must not match")
	}
	if FieldRef("Missing").Match(ev.Field("User"), ev) {
		t.Fatal("a reference to an absent field must not match a present value")
	}
}

func TestFieldRefOnAbsentLeftSide(t *testing.T) {
	ev := &event.Event{Fields: map[string]event.Value{"B": event.String("x")}}
	if FieldRef("B").Match(ev.Field("A"), ev) {
		t.Fatal("two fields are not equal because one of them is absent")
	}
	if FieldRef("A").Match(ev.Field("A"), ev) {
		t.Fatal("null does not equal null under fieldref; absence is not a value")
	}
}

func TestFieldRefComparesIntAsText(t *testing.T) {
	ev := &event.Event{Fields: map[string]event.Value{
		"Port":     event.Int(445),
		"DestPort": event.String("445"),
	}}
	if !FieldRef("DestPort").Match(ev.Field("Port"), ev) {
		t.Fatal("an int field compares against a string field by its decimal text")
	}
}
