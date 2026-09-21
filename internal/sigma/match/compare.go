package match

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/atontalapur/signalman/internal/event"
)

// Compare implements lt, lte, gt, and gte. A field whose value is a string
// that does not parse as a number is not a match and not an error, which is
// the behavior the data contract fixes: one dirty event must not stop the
// pipeline.
func Compare(op string, want int64) (Matcher, error) {
	var test func(got int64) bool
	switch op {
	case modLt:
		test = func(got int64) bool { return got < want }
	case modLte:
		test = func(got int64) bool { return got <= want }
	case modGt:
		test = func(got int64) bool { return got > want }
	case modGte:
		test = func(got int64) bool { return got >= want }
	default:
		return nil, fmt.Errorf("unknown comparison modifier %q", op)
	}
	return funcMatcher{func(v event.Value, _ *event.Event) bool {
		switch v.Kind {
		case event.KindInt:
			return test(v.I)
		case event.KindString:
			n, err := strconv.ParseInt(strings.TrimSpace(v.S), 10, 64)
			return err == nil && test(n)
		default:
			return false
		}
	}}, nil
}

// CIDR parses the prefix once, at compile time, never per event.
func CIDR(prefix string) (Matcher, error) {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("cidr %q: %w", prefix, err)
	}
	p = p.Masked()
	return funcMatcher{func(v event.Value, _ *event.Event) bool {
		s, ok := v.Text()
		if !ok {
			return false
		}
		addr, err := netip.ParseAddr(s)
		return err == nil && p.Contains(addr)
	}}, nil
}

// FieldRef compares the value against another field on the same event. It
// breaks the assumption that a leaf predicate has a constant right side,
// which is why Matcher takes the event.
func FieldRef(otherField string) Matcher {
	return funcMatcher{func(v event.Value, ev *event.Event) bool {
		got, ok := v.Text()
		if !ok {
			return false
		}
		want, ok := ev.Field(otherField).Text()
		if !ok {
			return false
		}
		return strings.EqualFold(got, want)
	}}
}
