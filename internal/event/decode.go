package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
)

// DecodeJSON builds an Event from one JSON object. It is the decoder the
// author tools use for event files and corpus lines; the pipeline's ingest
// decoder is Plan C's and makes its own limits decisions.
//
// Numbers that are integers become Int, exactly, with no float64 round trip.
// Any other number keeps its JSON text as a String. Nested objects are
// flattened into dotted field names. A list holds scalars only; a list of
// lists or of objects is an error rather than a value that can never match.
//
// A key given twice in one object is an error: encoding/json would keep the
// last one silently, and which copy a rule sees should not be a decoder
// accident. An empty object has no leaves, so it contributes no fields: a
// rule that tests {"a": {}} sees a as absent.
func DecodeJSON(b []byte) (*Event, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim('{') {
		return nil, errors.New("event is not a JSON object")
	}
	m, err := decodeObject(dec, "")
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the event object")
	}
	ev, err := FromMap(m)
	if err != nil {
		return nil, err
	}
	ev.Raw = append([]byte(nil), b...)
	return ev, nil
}

// decodeObject reads the members of an object whose opening brace has been
// consumed, through its closing brace. prefix is the dotted path, for errors.
func decodeObject(dec *json.Decoder, prefix string) (map[string]any, error) {
	m := map[string]any{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("object key is %T, not a string", tok)
		}
		name := k
		if prefix != "" {
			name = prefix + "." + k
		}
		if _, dup := m[k]; dup {
			return nil, fmt.Errorf("field %q is given twice in one object", name)
		}
		v, err := decodeValue(dec, name)
		if err != nil {
			return nil, err
		}
		m[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return m, nil
}

func decodeValue(dec *json.Decoder, name string) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch tok {
	case json.Delim('{'):
		return decodeObject(dec, name)
	case json.Delim('['):
		list := []any{}
		for dec.More() {
			v, err := decodeValue(dec, name)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return list, nil
	}
	return tok, nil
}

// FromMap builds an Event from a decoded map, as produced by encoding/json
// with UseNumber or by a YAML decoder. Keys are walked in sorted order, so a
// flattened-name collision is reported the same way on every run.
func FromMap(m map[string]any) (*Event, error) {
	fields := make(map[string]Value, len(m))
	if err := flatten("", m, fields); err != nil {
		return nil, err
	}
	return &Event{Fields: fields}, nil
}

func flatten(prefix string, m map[string]any, out map[string]Value) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name := k
		if prefix != "" {
			name = prefix + "." + k
		}
		if sub, ok := m[k].(map[string]any); ok {
			if err := flatten(name, sub, out); err != nil {
				return err
			}
			continue
		}
		v, err := scalarOrList(m[k])
		if err != nil {
			return fmt.Errorf("field %q: %w", name, err)
		}
		if _, dup := out[name]; dup {
			return fmt.Errorf("field %q is given twice once nested objects are flattened", name)
		}
		out[name] = v
	}
	return nil
}

func scalarOrList(x any) (Value, error) {
	if list, ok := x.([]any); ok {
		vs := make([]Value, 0, len(list))
		for i, item := range list {
			switch item.(type) {
			case []any, map[string]any:
				return Value{}, fmt.Errorf("list item %d is nested; only lists of scalars are supported", i)
			}
			v, err := scalar(item)
			if err != nil {
				return Value{}, fmt.Errorf("list item %d: %w", i, err)
			}
			vs = append(vs, v)
		}
		return List(vs...), nil
	}
	return scalar(x)
}

func scalar(x any) (Value, error) {
	switch v := x.(type) {
	case nil:
		return Null(), nil
	case string:
		return String(v), nil
	case bool:
		return Bool(v), nil
	case json.Number:
		if i, err := strconv.ParseInt(string(v), 10, 64); err == nil {
			return Int(i), nil
		}
		return String(string(v)), nil
	case int:
		return Int(int64(v)), nil
	case int64:
		return Int(v), nil
	case uint64:
		// Above MaxInt64 there is no Int for it; keep the exact digits as
		// text, as DecodeJSON does for an out-of-range JSON integer.
		if v > math.MaxInt64 {
			return String(strconv.FormatUint(v, 10)), nil
		}
		return Int(int64(v)), nil
	case float64:
		// YAML has no way to write 1 that differs from 1.0, so an integral
		// float is an integer, matching the rule loader's reading. Only
		// inside [-2^63, 2^63): converting a float outside int64's range is
		// implementation-defined in Go and differs between platforms.
		if v >= -(1<<63) && v < 1<<63 && v == math.Trunc(v) {
			return Int(int64(v)), nil
		}
		return String(strconv.FormatFloat(v, 'g', -1, 64)), nil
	}
	return Value{}, fmt.Errorf("unsupported value type %T", x)
}
