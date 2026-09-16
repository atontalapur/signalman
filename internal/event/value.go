// Package event defines the unit of work that flows through the pipeline
// and the verdict that every engine emits for it.
package event

import "strconv"

type ValueKind uint8

const (
	KindNull ValueKind = iota
	KindString
	KindInt
	KindBool
	KindList
)

// Value is a closed sum type. Sigma comparison semantics differ per kind,
// so the kind is carried explicitly rather than inferred.
type Value struct {
	Kind ValueKind
	S    string
	I    int64
	B    bool
	L    []Value
}

func String(s string) Value  { return Value{Kind: KindString, S: s} }
func Int(i int64) Value      { return Value{Kind: KindInt, I: i} }
func Bool(b bool) Value      { return Value{Kind: KindBool, B: b} }
func Null() Value            { return Value{Kind: KindNull} }
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
