package pipe

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	taxonomyDir = "../../config/taxonomy"
	rulesDir    = "../engine/v1/testdata/rules"
	dumpRuleID  = "1f1a1f1a-0001-4000-8000-000000000001"
)

func loadTaxonomy(t testing.TB) *sigma.Taxonomy {
	t.Helper()
	tax, err := sigma.LoadTaxonomy(taxonomyDir)
	if err != nil {
		t.Fatal(err)
	}
	return tax
}

func newNormalizer(t testing.TB) (*Normalizer, *obs.Metrics) {
	t.Helper()
	m := obs.New(prometheus.NewRegistry())
	return NewNormalizer(loadTaxonomy(t), NormalizeConfig{}, m), m
}

func item(source, body string) *Item {
	in := NewIngest(obs.New(prometheus.NewRegistry()))
	r := rawRecord("host-1", source, body)
	r.Partition, r.Offset = 3, 17
	return in.Admit(r)
}

const sysmonDump = `{
	"Channel": "Microsoft-Windows-Sysmon/Operational",
	"EVENT_ID": 1,
	"Image": "C:\\Windows\\System32\\rundll32.exe",
	"CommandLine": "rundll32.exe comsvcs.dll, MiniDump 624 C:\\t.dmp full",
	"ParentImage": "C:\\Windows\\explorer.exe",
	"event_time": "2026-10-01T12:00:00.250Z",
	"Score": 1.5,
	"Elevated": true,
	"Parent": {"Pid": 4, "Tags": ["a", "b"]},
	"Note": null
}`

func TestNormalizeMapsFieldsOntoTaxonomySpelling(t *testing.T) {
	n, _ := newNormalizer(t)
	it := item("sysmon", sysmonDump)
	n.Normalize(it)
	if it.Drop != nil {
		t.Fatalf("dropped: %+v", it.Drop)
	}
	f := it.Event.Fields
	want := map[string]event.Value{
		// The taxonomy spells these channel and event_id; a source that
		// capitalizes them must not silently fall outside every logsource.
		"channel":     event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id":    event.Int(1),
		"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
		"Elevated":    event.Bool(true),
		"Score":       event.String("1.5"),
		"Parent.Pid":  event.Int(4),
		"Parent.Tags": event.List(event.String("a"), event.String("b")),
		"Note":        event.Null(),
	}
	for k, v := range want {
		got, ok := f[k]
		if !ok {
			t.Fatalf("field %q missing from %v", k, f)
		}
		if got.Kind != v.Kind || got.S != v.S || got.I != v.I || got.B != v.B || len(got.L) != len(v.L) {
			t.Fatalf("%s = %+v, want %+v", k, got, v)
		}
	}
	if _, ok := f["Channel"]; ok {
		t.Fatal("the source spelling must be replaced, not kept beside the taxonomy spelling")
	}
	wantTime := time.Date(2026, 10, 1, 12, 0, 0, 250e6, time.UTC)
	if !it.Event.EventTime.Equal(wantTime) {
		t.Fatalf("event time = %v, want %v", it.Event.EventTime, wantTime)
	}
}

func TestNormalizedEventMatchesTheRuleV1Binds(t *testing.T) {
	tax := loadTaxonomy(t)
	rs, errs, err := sigma.LoadRuleSet(rulesDir, tax)
	if err != nil || len(errs) != 0 {
		t.Fatal(err, errs)
	}
	n := NewNormalizer(tax, NormalizeConfig{}, obs.New(prometheus.NewRegistry()))
	it := item("sysmon", sysmonDump)
	n.Normalize(it)
	for _, v := range v1.New(rs).Evaluate(it.Event) {
		if v.RuleID == dumpRuleID && !v.Matched {
			t.Fatal("the normalized raw record must match the rule it was written for")
		}
	}
}

func TestNormalizeEpochMillisEventTime(t *testing.T) {
	n, _ := newNormalizer(t)
	it := item("sysmon", `{"event_time": 1790000000123}`)
	n.Normalize(it)
	if it.Drop != nil {
		t.Fatal(it.Drop)
	}
	if got := it.Event.EventTime.UnixMilli(); got != 1790000000123 {
		t.Fatalf("event time = %d", got)
	}
}

func TestNormalizeDropReasons(t *testing.T) {
	long := `{"event_time": 1, "x": "` + strings.Repeat("a", 70*1024) + `"}`
	cases := []struct {
		name, source, body, reason string
	}{
		{"not json", "sysmon", `{"a":`, ReasonParse},
		{"not an object", "sysmon", `[1,2]`, ReasonParse},
		{"trailing data", "sysmon", `{"event_time":1} {}`, ReasonParse},
		{"invalid utf8", "sysmon", "{\"event_time\":1,\"a\":\"\xff\"}", ReasonInvalidUTF8},
		{"value too long", "sysmon", long, ReasonValueTooLong},
		{"list in list", "sysmon", `{"event_time":1,"a":[[1]]}`, ReasonNestedValue},
		{"object in list", "sysmon", `{"event_time":1,"a":[{"b":1}]}`, ReasonNestedValue},
		{"too deep", "sysmon", `{"event_time":1,"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":1}}}}}}}}}`, ReasonNestedValue},
		{"duplicate key", "sysmon", `{"event_time":1,"a":1,"a":2}`, ReasonDuplicateField},
		{"duplicate after mapping", "sysmon", `{"event_time":1,"channel":"x","Channel":"y"}`, ReasonDuplicateField},
		{"no source", "", `{"event_time":1}`, ReasonMissingSource},
		{"no event time", "sysmon", `{"a":1}`, ReasonEventTime},
		{"bad event time", "sysmon", `{"event_time":"yesterday"}`, ReasonEventTime},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, m := newNormalizer(t)
			it := item(c.source, c.body)
			n.Normalize(it)
			if it.Drop == nil {
				t.Fatalf("not dropped; fields %v", it.Event.Fields)
			}
			if it.Drop.Reason != c.reason {
				t.Fatalf("reason %q (%s), want %q", it.Drop.Reason, it.Drop.Detail, c.reason)
			}
			if !bytes.Equal(it.Event.Raw, []byte(c.body)) {
				t.Fatal("a drop keeps the raw bytes untouched")
			}
			src := c.source
			if src == "" {
				src = SourceUnknown
			}
			if got := testutil.ToFloat64(m.EventsDropped.WithLabelValues(c.reason, src)); got != 1 {
				t.Fatalf("signalman_events_dropped_total{reason=%q,source=%q} = %v", c.reason, src, got)
			}
		})
	}
}

func TestPoisonRecordIsDroppedAndDoesNotWedgeThePartition(t *testing.T) {
	n, m := newNormalizer(t)
	real := n.decode
	n.decode = func(raw []byte) (map[string]event.Value, *Drop) {
		if bytes.Contains(raw, []byte("poison")) {
			var none []byte
			_ = none[len(raw)] // a genuine runtime panic, not a stand-in for one
		}
		return real(raw)
	}
	poison := item("sysmon", `{"event_time":1,"x":"poison"}`)
	n.Normalize(poison)
	if poison.Drop == nil || poison.Drop.Reason != ReasonPanic {
		t.Fatalf("poison record = %+v", poison.Drop)
	}
	if !strings.Contains(poison.Drop.Detail, "index out of range") {
		t.Fatalf("the panic value is kept for the ledger: %q", poison.Drop.Detail)
	}
	if poison.Event.Fields != nil {
		t.Fatal("a dropped event carries no half-built fields")
	}
	// The same normalizer, the same partition, the next record.
	next := item("sysmon", sysmonDump)
	n.Normalize(next)
	if next.Drop != nil {
		t.Fatalf("the record after a poison record was dropped: %+v", next.Drop)
	}
	if got := testutil.ToFloat64(m.EventsDropped.WithLabelValues(ReasonPanic, "sysmon")); got != 1 {
		t.Fatalf("panic drops counted %v", got)
	}
}

func TestSetFaultPanicsInsideTheRecovery(t *testing.T) {
	n, m := newNormalizer(t)
	n.SetFault(func(raw []byte) {
		if bytes.Contains(raw, []byte("poison")) {
			panic("injected")
		}
	})
	poison := item("sysmon", `{"event_time":1,"x":"poison"}`)
	n.Normalize(poison)
	if poison.Drop == nil || poison.Drop.Reason != ReasonPanic || poison.Drop.Detail != "injected" {
		t.Fatalf("poison record = %+v", poison.Drop)
	}
	next := item("sysmon", sysmonDump)
	n.Normalize(next)
	if next.Drop != nil {
		t.Fatalf("a fault that does not panic changed the outcome: %+v", next.Drop)
	}
	n.SetFault(nil)
	again := item("sysmon", `{"event_time":1,"x":"poison"}`)
	n.Normalize(again)
	if again.Drop != nil {
		t.Fatalf("SetFault(nil) left the fault installed: %+v", again.Drop)
	}
	if got := testutil.ToFloat64(m.EventsDropped.WithLabelValues(ReasonPanic, "sysmon")); got != 1 {
		t.Fatalf("panic drops counted %v", got)
	}
}

func TestDropRecordCarriesRawBytesAndIdentity(t *testing.T) {
	n, _ := newNormalizer(t)
	body := "{\"a\":\"\xff\"}"
	it := item("sysmon", body)
	n.Normalize(it)
	rec := DropRecord(it)
	if rec.Topic != TopicDrops || string(rec.Key) != "host-1" || rec.Partition != broker.AnyPartition {
		t.Fatalf("drop record routing %+v", rec)
	}
	var d DropEntry
	if err := json.Unmarshal(rec.Value, &d); err != nil {
		t.Fatal(err)
	}
	if d.Partition != 3 || d.Seq != 17 || d.Offset != 17 || d.HostID != "host-1" || d.Source != "sysmon" || d.Reason != ReasonInvalidUTF8 {
		t.Fatalf("drop entry %+v", d)
	}
	if !bytes.Equal(d.Raw, []byte(body)) {
		t.Fatal("the ledger keeps the exact raw bytes, invalid UTF-8 included")
	}
}

func TestNormRecordRoundTripsTypedFields(t *testing.T) {
	n, _ := newNormalizer(t)
	it := item("sysmon", sysmonDump)
	n.Normalize(it)
	rec := NormRecord(it)
	if rec.Topic != TopicEventsNorm || string(rec.Key) != "host-1" {
		t.Fatalf("norm record routing %+v", rec)
	}
	var got NormEvent
	if err := json.Unmarshal(rec.Value, &got); err != nil {
		t.Fatal(err)
	}
	if got.Seq != 17 || got.Partition != 3 || got.Source != "sysmon" || !got.EventTime.Equal(it.Event.EventTime) {
		t.Fatalf("norm event %+v", got)
	}
	ev := got.Event()
	for k, v := range it.Event.Fields {
		w := ev.Fields[k]
		if w.Kind != v.Kind || w.S != v.S || w.I != v.I || w.B != v.B || len(w.L) != len(v.L) {
			t.Fatalf("%s round-tripped as %+v, was %+v", k, w, v)
		}
	}
	again, _ := json.Marshal(got)
	if !bytes.Equal(again, rec.Value) {
		t.Fatal("encoding is deterministic: fields are written in sorted order")
	}
}
