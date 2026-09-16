package event

import (
	"fmt"
	"strconv"
)

// ValueKind tags which payload slot of a Value is live.
type ValueKind uint8

// The closed set of kinds. Sigma comparison branches on these.
const (
	KindNull ValueKind = iota
	KindString
	KindInt
	KindBool
	KindList
)

// String names the kind for error messages.
func (k ValueKind) String() string {
	switch k {
	case KindNull:
		return "null"
	case KindString:
		return "string"
	case KindInt:
		return "int"
	case KindBool:
		return "bool"
	case KindList:
		return "list"
	default:
		return fmt.Sprintf("kind(%d)", uint8(k))
	}
}

// Value is a closed sum type. Sigma comparison semantics differ per kind,
// so the kind is carried explicitly rather than inferred.
type Value struct {
	Kind ValueKind
	S    string
	I    int64
	B    bool
	L    []Value
}

// String returns a string Value. The empty string is a string, not null.
func String(s string) Value { return Value{Kind: KindString, S: s} }

// Int returns an integer Value.
func Int(i int64) Value { return Value{Kind: KindInt, I: i} }

// Bool returns a boolean Value.
func Bool(b bool) Value { return Value{Kind: KindBool, B: b} }

// Null returns the null Value. It is also what an absent field reads as.
func Null() Value { return Value{Kind: KindNull} }

// List returns a list Value holding vs. The slice is used as given, not copied.
func List(vs ...Value) Value { return Value{Kind: KindList, L: vs} }

// Text returns the canonical string form used for Sigma string comparison.
// Null and list values have no such form and report false.
func (v Value) Text() (string, bool) {
	switch v.Kind {
	case KindString:
		return v.S, true
	case KindInt:
		return strconv.FormatInt(v.I, 10), true
	case KindBool:
		return strconv.FormatBool(v.B), true
	default:
		return "", false
	}
}
