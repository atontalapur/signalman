package pipe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
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
