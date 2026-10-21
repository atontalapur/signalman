package event

import (
	"reflect"
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
