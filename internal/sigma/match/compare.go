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
		return anyValue(v, func(item event.Value) bool {
			switch item.Kind {
			case event.KindInt:
				return test(item.I)
			case event.KindString:
				n, err := strconv.ParseInt(strings.TrimSpace(item.S), 10, 64)
				return err == nil && test(n)
			default:
				return false
			}
		})
	}}, nil
}

// CIDR parses the prefix once, at compile time, never per event.
func CIDR(prefix string) (Matcher, error) {
	p, err := parseCIDR(prefix)
	if err != nil {
		return nil, err
	}
	return cidrMatcher(p), nil
}

func parseCIDR(prefix string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("cidr %q: %w", prefix, err)
	}
	return p.Masked(), nil
}

// cidrMatcher tests a parsed, masked prefix.
func cidrMatcher(p netip.Prefix) Matcher {
	return funcMatcher{func(v event.Value, _ *event.Event) bool {
		return anyValue(v, func(item event.Value) bool {
			s, ok := item.Text()
			if !ok {
				return false
			}
			addr, err := netip.ParseAddr(s)
			return err == nil && p.Contains(addr)
		})
	}}
}

// anyValue applies f to v, or to each element of a list, and reports whether
// any application held. A list is an OR everywhere else in Sigma, and a
// comparison that skipped list elements would read as a clean no-match while
// silently never firing on a multi-valued field.
func anyValue(v event.Value, f func(event.Value) bool) bool {
	if v.Kind == event.KindList {
		for _, item := range v.L {
			if f(item) {
				return true
			}
		}
		return false
	}
	return f(v)
}

// FieldRef compares the value against another field on the same event. It
// breaks the assumption that a leaf predicate has a constant right side,
// which is why Matcher takes the event.
func FieldRef(otherField string) Matcher {
	return funcMatcher{func(v event.Value, ev *event.Event) bool {
		other := ev.Field(otherField)
		return anyValue(v, func(left event.Value) bool {
			got, ok := left.Text()
			if !ok {
				return false
			}
			return anyValue(other, func(right event.Value) bool {
				want, ok := right.Text()
				return ok && strings.EqualFold(got, want)
			})
		})
	}}
}
