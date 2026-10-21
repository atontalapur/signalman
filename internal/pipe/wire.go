package pipe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

// WireValue is an event.Value in JSON. Each Value kind maps to exactly one
// JSON type (string, integer number, boolean, null, array), so the encoding
// is lossless without a kind tag.
type WireValue event.Value

func (v WireValue) MarshalJSON() ([]byte, error) {
	switch v.Kind {
	case event.KindString:
		return json.Marshal(v.S)
	case event.KindInt:
		return json.Marshal(v.I)
	case event.KindBool:
		return json.Marshal(v.B)
	case event.KindNull:
		return []byte("null"), nil
	case event.KindList:
		l := make([]WireValue, len(v.L))
		for i, e := range v.L {
			l[i] = WireValue(e)
		}
		return json.Marshal(l)
	default:
		return nil, fmt.Errorf("value of kind %s has no wire form", v.Kind)
	}
}

func (v *WireValue) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	val, err := fromJSON(raw)
	if err != nil {
		return err
	}
	*v = WireValue(val)
	return nil
}

func fromJSON(raw any) (event.Value, error) {
	switch x := raw.(type) {
	case nil:
		return event.Null(), nil
	case string:
		return event.String(x), nil
	case bool:
		return event.Bool(x), nil
	case json.Number:
		return number(x), nil
	case []any:
		l := make([]event.Value, len(x))
		for i, e := range x {
			v, err := fromJSON(e)
			if err != nil {
				return event.Value{}, err
			}
			l[i] = v
		}
		return event.List(l...), nil
	default:
		return event.Value{}, fmt.Errorf("no event value for JSON %T", raw)
	}
}

// number is an integer Value when the literal is an int64, and otherwise a
// string Value holding the literal as written. Value has no float kind, and
// Sigma's numeric modifiers compare integers.
func number(n json.Number) event.Value {
	if i, err := n.Int64(); err == nil {
		return event.Int(i)
	}
	return event.String(n.String())
}

// NormEvent is the events.norm record body: the normalized event, with Seq
// assigned, keyed by host_id.
type NormEvent struct {
	Seq       uint64               `json:"seq"`
	Partition int32                `json:"partition"`
	HostID    string               `json:"host_id"`
	Source    string               `json:"source"`
	EventTime time.Time            `json:"event_time"`
	IngestAt  time.Time            `json:"ingest_at"`
	Fields    map[string]WireValue `json:"fields"`
	Raw       []byte               `json:"raw"`
}

// Event rebuilds the event.Event a consumer of events.norm evaluates.
func (n NormEvent) Event() *event.Event {
	f := make(map[string]event.Value, len(n.Fields))
	for k, v := range n.Fields {
		f[k] = event.Value(v)
	}
	return &event.Event{
		Seq:       n.Seq,
		Partition: n.Partition,
		Source:    n.Source,
		EventTime: n.EventTime,
		IngestAt:  n.IngestAt,
		Fields:    f,
		Raw:       n.Raw,
	}
}

// NormRecord is the events.norm record for a normalized item. encoding/json
// writes map keys sorted, so the bytes are a function of the event.
func NormRecord(it *Item) broker.Record {
	ev := it.Event
	f := make(map[string]WireValue, len(ev.Fields))
	for k, v := range ev.Fields {
		f[k] = WireValue(v)
	}
	b, err := json.Marshal(NormEvent{
		Seq:       ev.Seq,
		Partition: ev.Partition,
		HostID:    it.HostID,
		Source:    ev.Source,
		EventTime: ev.EventTime,
		IngestAt:  ev.IngestAt,
		Fields:    f,
		Raw:       ev.Raw,
	})
	if err != nil {
		// The normalizer only builds kinds WireValue encodes.
		panic(err)
	}
	return broker.Record{Topic: TopicEventsNorm, Partition: broker.AnyPartition, Key: []byte(it.HostID), Value: b}
}

// Alert is the alerts topic record body, one per matched verdict. Its
// fields follow the ClickHouse alert table in the spec (phase 04), so the
// sink can insert it as it stands. The table dedups on (partition, seq,
// rule_id), which is what makes a redelivered batch harmless.
type Alert struct {
	Partition  int32             `json:"partition"`
	Seq        uint64            `json:"seq"`
	RuleID     string            `json:"rule_id"`
	RuleTitle  string            `json:"rule_title"`
	Severity   string            `json:"severity"`
	EventTime  time.Time         `json:"event_time"`
	IngestTime time.Time         `json:"ingest_time"`
	HostID     string            `json:"host_id"`
	Source     string            `json:"source"`
	Fields     map[string]string `json:"fields"`
	// Raw is a string: a normalized record is valid UTF-8 by construction.
	Raw string `json:"raw"`
}

// AlertRecord is the alerts topic record for one match, keyed by rule_id.
func AlertRecord(r *sigma.Rule, it *Item) broker.Record {
	ev := it.Event
	f := make(map[string]string, len(ev.Fields))
	for k, v := range ev.Fields {
		f[k] = flat(v)
	}
	b, err := json.Marshal(Alert{
		Partition:  ev.Partition,
		Seq:        ev.Seq,
		RuleID:     r.ID,
		RuleTitle:  r.Title,
		Severity:   r.Level,
		EventTime:  ev.EventTime,
		IngestTime: ev.IngestAt,
		HostID:     it.HostID,
		Source:     ev.Source,
		Fields:     f,
		Raw:        string(ev.Raw),
	})
	if err != nil {
		panic(err)
	}
	return broker.Record{Topic: TopicAlerts, Partition: broker.AnyPartition, Key: []byte(r.ID), Value: b}
}

// flat renders a value for the alert table's Map(String, String): scalars
// as their Sigma text, null as empty, a list as its JSON array.
func flat(v event.Value) string {
	if s, ok := v.Text(); ok {
		return s
	}
	if v.Kind == event.KindList {
		b, err := json.Marshal(WireValue(v))
		if err == nil {
			return string(b)
		}
	}
	return ""
}

// EventVerdicts is a verdict topic record body: every verdict for one event,
// from one engine under one rule set. One record per event rather than one
// per verdict keeps the topic at events times one, not events times rules,
// and keeps an event's verdicts atomic: they are written, or redelivered,
// together.
type EventVerdicts struct {
	Partition int32         `json:"partition"`
	Seq       uint64        `json:"seq"`
	Engine    string        `json:"engine"`
	RuleSetV  string        `json:"ruleset_v"`
	TaxonomyV string        `json:"taxonomy_v"`
	Verdicts  []RuleVerdict `json:"verdicts"`
}

// RuleVerdict is one rule's result inside EventVerdicts.
type RuleVerdict struct {
	RuleID  string `json:"rule_id"`
	Matched bool   `json:"matched"`
}

// Expand returns the record as data contract verdicts, in the order written.
func (e EventVerdicts) Expand() []event.Verdict {
	out := make([]event.Verdict, len(e.Verdicts))
	for i, v := range e.Verdicts {
		out[i] = event.Verdict{
			Seq:       e.Seq,
			Partition: e.Partition,
			RuleID:    v.RuleID,
			Matched:   v.Matched,
			Engine:    e.Engine,
			RuleSetV:  e.RuleSetV,
			TaxonomyV: e.TaxonomyV,
		}
	}
	return out
}

// VerdictRecord is the verdict topic record for an evaluated item, under
// the engine that produced it. It is pinned to the event's own partition and
// keyed by it, so a partition's verdicts stay one ordered stream for the
// digest and the differ.
func VerdictRecord(eng Engine, it *Item) broker.Record {
	ev := it.Event
	rs := eng.RuleSet()
	rec := EventVerdicts{
		Partition: ev.Partition,
		Seq:       ev.Seq,
		Engine:    eng.Name(),
		RuleSetV:  rs.Version,
		TaxonomyV: rs.TaxonomyV,
		Verdicts:  make([]RuleVerdict, len(it.Verdicts)),
	}
	for i, v := range it.Verdicts {
		rec.Verdicts[i] = RuleVerdict{RuleID: v.RuleID, Matched: v.Matched}
	}
	b, err := json.Marshal(rec)
	if err != nil {
		panic(err)
	}
	return broker.Record{
		Topic:     VerdictTopic(eng),
		Partition: ev.Partition,
		Key:       []byte(strconv.Itoa(int(ev.Partition))),
		Value:     b,
	}
}
