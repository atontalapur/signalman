package event

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestDecodeJSONMapsEachKind(t *testing.T) {
	ev, err := DecodeJSON([]byte(`{
		"channel": "Security",
		"event_id": 4688,
		"elevated": true,
		"parent": null,
		"ratio": 1.5,
		"tags": ["a", 2],
		"winlog": {"event_data": {"Image": "C:\\x.exe"}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Value{
		"channel":                 String("Security"),
		"event_id":                Int(4688),
		"elevated":                Bool(true),
		"parent":                  Null(),
		"ratio":                   String("1.5"),
		"tags":                    List(String("a"), Int(2)),
		"winlog.event_data.Image": String(`C:\x.exe`),
	}
	if !reflect.DeepEqual(ev.Fields, want) {
		t.Fatalf("got %#v\nwant %#v", ev.Fields, want)
	}
	if string(ev.Raw) == "" {
		t.Fatal("Raw should keep the source bytes")
	}
}

func TestDecodeJSONKeepsLargeIntegersExact(t *testing.T) {
	ev, err := DecodeJSON([]byte(`{"n": 9007199254740993}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := ev.Fields["n"]; !reflect.DeepEqual(got, Int(9007199254740993)) {
		t.Fatalf("got %#v", got)
	}
}

func TestDecodeJSONRejectsNonObjects(t *testing.T) {
	for _, src := range []string{`[1,2]`, `"x"`, `{"a":1} {"b":2}`, `{"a": [[1]]}`, `{"a": [{"b": 1}]}`, `{`} {
		if _, err := DecodeJSON([]byte(src)); err == nil {
			t.Errorf("DecodeJSON(%s) should fail", src)
		}
	}
}

func TestFromMapTakesYAMLScalars(t *testing.T) {
	ev, err := FromMap(map[string]any{
		"event_id": 1,
		"big":      uint64(7),
		"i64":      int64(-3),
		"f":        2.0,
		"s":        "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Value{
		"event_id": Int(1),
		"big":      Int(7),
		"i64":      Int(-3),
		"f":        Int(2),
		"s":        String("x"),
	}
	if !reflect.DeepEqual(ev.Fields, want) {
		t.Fatalf("got %#v", ev.Fields)
	}
}

func TestFromMapRejectsAFlattenedKeyCollision(t *testing.T) {
	_, err := FromMap(map[string]any{
		"a.b": "x",
		"a":   map[string]any{"b": "y"},
	})
	if err == nil {
		t.Fatal("two sources for one flattened field must not be resolved by map order")
	}
}

func TestFromMapKeepsOutOfRangeNumbersAsText(t *testing.T) {
	ev, err := FromMap(map[string]any{
		"umax":   uint64(math.MaxUint64),
		"uedge":  uint64(math.MaxInt64),
		"fbig":   9.3e18,
		"ftwo63": 9223372036854775808.0,
		"fmin":   -9223372036854775808.0,
		"finf":   math.Inf(1),
		"fnan":   math.NaN(),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Value{
		"umax":   String("18446744073709551615"),
		"uedge":  Int(math.MaxInt64),
		"fbig":   String("9.3e+18"),
		"ftwo63": String("9.223372036854776e+18"),
		"fmin":   Int(math.MinInt64),
		"finf":   String("+Inf"),
		"fnan":   String("NaN"),
	}
	if !reflect.DeepEqual(ev.Fields, want) {
		t.Fatalf("got %#v\nwant %#v", ev.Fields, want)
	}
}

func TestDecodeJSONRejectsDuplicateKeys(t *testing.T) {
	for _, src := range []string{
		`{"a": 1, "a": 2}`,
		`{"x": {"a": 1, "a": 2}}`,
		`{"x": {"a": 1}, "x": {"b": 2}}`,
	} {
		if _, err := DecodeJSON([]byte(src)); err == nil || !strings.Contains(err.Error(), "given twice") {
			t.Errorf("DecodeJSON(%s) = %v, want a duplicate key error", src, err)
		}
	}
}

func TestDecodeJSONReadsAnEmptyObjectAsAbsent(t *testing.T) {
	ev, err := DecodeJSON([]byte(`{"a": {}, "b": {"c": {}}, "d": 1}`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Value{"d": Int(1)}
	if !reflect.DeepEqual(ev.Fields, want) {
		t.Fatalf("an object with no leaves contributes no fields: got %#v", ev.Fields)
	}
}
