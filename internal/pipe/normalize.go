package pipe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/sigma"
)

// NormalizeConfig sets the decode limits. Zero values take the defaults.
type NormalizeConfig struct {
	// TimeField is the raw field holding the event time: an RFC 3339 string
	// or integer epoch milliseconds. Default "event_time".
	TimeField string
	// MaxValueLen caps a string value in bytes. Default 64 KiB.
	MaxValueLen int
	// MaxDepth caps object nesting. Default 8.
	MaxDepth int
	// MaxRecordBytes caps key, value, and headers together. Default
	// DefaultMaxRecordBytes, which is also the most it may be: above it a
	// drop entry may not fit MaxOutputRecordBytes.
	MaxRecordBytes int
}

func (c NormalizeConfig) withDefaults() NormalizeConfig {
	if c.TimeField == "" {
		c.TimeField = "event_time"
	}
	if c.MaxValueLen == 0 {
		c.MaxValueLen = 64 << 10
	}
	if c.MaxDepth == 0 {
		c.MaxDepth = 8
	}
	if c.MaxRecordBytes == 0 {
		c.MaxRecordBytes = DefaultMaxRecordBytes
	}
	return c
}

// Normalizer turns a raw record into event fields, or into a drop.
//
// The record is a JSON object. Nested objects flatten to dotted names
// ("Parent.Pid"). A field whose name equals one of the taxonomy's concrete
// names ignoring case is renamed to the taxonomy's spelling, because a
// bound rule reads Fields by exact name: a source that writes "Channel"
// where the taxonomy says "channel" would otherwise fall outside every
// logsource and produce nothing but false verdicts, with no error anywhere.
// Other names pass through unchanged. There is no enrichment.
//
// Normalization is a pure function of the record bytes and the taxonomy.
type Normalizer struct {
	cfg   NormalizeConfig
	canon map[string]string // lowercased name -> taxonomy spelling
	m     *obs.Metrics
	// decode is a field so a test can make it panic on a chosen record.
	decode func(raw []byte) (map[string]event.Value, *Drop)
	// fault, when set, sees every record that reaches decode. See SetFault.
	fault func(raw []byte)
}

// SetFault installs f, which is called with the bytes of each record that
// passed the size and source checks, before it is decoded, inside the
// normalizer's panic recovery. It exists for failure
// injection: the load harness's poison record experiment makes f panic on a
// marked record, which must cost one ReasonPanic drop and nothing else. Set
// it before the pipeline runs; nil removes it.
func (n *Normalizer) SetFault(f func(raw []byte)) { n.fault = f }

// NewNormalizer builds a normalizer for tax.
func NewNormalizer(tax *sigma.Taxonomy, cfg NormalizeConfig, m *obs.Metrics) *Normalizer {
	n := &Normalizer{cfg: cfg.withDefaults(), canon: map[string]string{}, m: m}
	if n.cfg.MaxRecordBytes > DefaultMaxRecordBytes {
		panic(fmt.Sprintf("pipe: MaxRecordBytes %d is over %d; drop entries would not fit the output limit", n.cfg.MaxRecordBytes, DefaultMaxRecordBytes))
	}
	for _, name := range tax.FieldNames() {
		// Two taxonomy names differing only in case would make the mapping
		// ambiguous. The first in sorted order wins, which is at least
		// stable; a taxonomy that does this has a bug of its own.
		if _, dup := n.canon[strings.ToLower(name)]; !dup {
			n.canon[strings.ToLower(name)] = name
		}
	}
	n.decode = n.decodeFields
	return n
}

// Normalize fills it.Event.Fields and EventTime, or sets it.Drop. It never
// panics: a panic while decoding becomes a drop with ReasonPanic, so one
// poison record costs one ledger entry, not a wedged partition.
func (n *Normalizer) Normalize(it *Item) {
	defer func() {
		if r := recover(); r != nil {
			it.Event.Fields = nil
			n.drop(it, ReasonPanic, fmt.Sprint(r))
		}
	}()
	if sz := broker.RecordSize(it.Rec); sz > n.cfg.MaxRecordBytes {
		n.drop(it, ReasonRecordTooLarge, fmt.Sprintf("%d bytes, limit %d", sz, n.cfg.MaxRecordBytes))
		return
	}
	if it.Event.Source == "" {
		n.drop(it, ReasonMissingSource, "no "+HeaderSource+" header")
		return
	}
	if !knownSource(it.Event.Source) {
		n.drop(it, ReasonUnknownSource, fmt.Sprintf("%s %q is not one of %s", HeaderSource, cut(it.Event.Source, 64), strings.Join(Sources, ", ")))
		return
	}
	if n.fault != nil {
		n.fault(it.Event.Raw)
	}
	fields, d := n.decode(it.Event.Raw)
	if d != nil {
		n.drop(it, d.Reason, d.Detail)
		return
	}
	t, err := eventTime(fields[n.cfg.TimeField])
	if err != nil {
		n.drop(it, ReasonEventTime, fmt.Sprintf("%s: %v", n.cfg.TimeField, err))
		return
	}
	it.Event.Fields = fields
	it.Event.EventTime = t
}

func (n *Normalizer) drop(it *Item, reason, detail string) {
	it.Drop = &Drop{Reason: reason, Detail: detail}
	n.m.EventsDropped.WithLabelValues(reason, sourceLabel(it.Event.Source)).Inc()
}

func eventTime(v event.Value) (time.Time, error) {
	switch v.Kind {
	case event.KindString:
		t, err := time.Parse(time.RFC3339Nano, v.S)
		if err != nil {
			return time.Time{}, err
		}
		return t.UTC(), nil
	case event.KindInt:
		return time.UnixMilli(v.I).UTC(), nil
	case event.KindNull:
		return time.Time{}, errors.New("absent")
	default:
		return time.Time{}, fmt.Errorf("a %s is not a time", v.Kind)
	}
}

type decodeError struct{ Drop }

func (e *decodeError) Error() string { return e.Reason + ": " + e.Detail }

func fail(reason, format string, args ...any) error {
	return &decodeError{Drop{Reason: reason, Detail: fmt.Sprintf(format, args...)}}
}

// decodeFields walks the JSON token stream rather than unmarshalling into a
// map, because a map silently keeps the last of two duplicate keys.
func (n *Normalizer) decodeFields(raw []byte) (map[string]event.Value, *Drop) {
	if !utf8.Valid(raw) {
		return nil, &Drop{Reason: ReasonInvalidUTF8, Detail: "record is not valid UTF-8"}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, &Drop{Reason: ReasonParse, Detail: err.Error()}
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, &Drop{Reason: ReasonParse, Detail: "record is not a JSON object"}
	}
	fields := map[string]event.Value{}
	if err := n.object(dec, "", 1, fields); err != nil {
		var de *decodeError
		if errors.As(err, &de) {
			return nil, &de.Drop
		}
		return nil, &Drop{Reason: ReasonParse, Detail: err.Error()}
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, &Drop{Reason: ReasonParse, Detail: "data after the record object"}
	}
	return fields, nil
}

// object reads the members of an object whose '{' has been consumed.
func (n *Normalizer) object(dec *json.Decoder, prefix string, depth int, out map[string]event.Value) error {
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("object key %v is not a string", tok)
		}
		name := prefix + key
		tok, err = dec.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				if depth >= n.cfg.MaxDepth {
					return fail(ReasonNestedValue, "%s: objects nested deeper than %d", name, n.cfg.MaxDepth)
				}
				if err := n.object(dec, name+".", depth+1, out); err != nil {
					return err
				}
			case '[':
				l, err := n.list(dec, name)
				if err != nil {
					return err
				}
				if err := n.put(out, name, event.List(l...)); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unexpected %v", t)
			}
		default:
			v, err := n.scalar(name, tok)
			if err != nil {
				return err
			}
			if err := n.put(out, name, v); err != nil {
				return err
			}
		}
	}
	_, err := dec.Token() // the closing '}'
	return err
}

// list reads a list of scalars whose '[' has been consumed.
func (n *Normalizer) list(dec *json.Decoder, name string) ([]event.Value, error) {
	var l []event.Value
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if _, ok := tok.(json.Delim); ok {
			return nil, fail(ReasonNestedValue, "%s: a list may hold only scalars", name)
		}
		v, err := n.scalar(name, tok)
		if err != nil {
			return nil, err
		}
		l = append(l, v)
	}
	_, err := dec.Token() // the closing ']'
	return l, err
}

func (n *Normalizer) scalar(name string, tok json.Token) (event.Value, error) {
	switch t := tok.(type) {
	case string:
		if len(t) > n.cfg.MaxValueLen {
			return event.Value{}, fail(ReasonValueTooLong, "%s: %d bytes, limit %d", name, len(t), n.cfg.MaxValueLen)
		}
		return event.String(t), nil
	case json.Number:
		return number(t), nil
	case bool:
		return event.Bool(t), nil
	case nil:
		return event.Null(), nil
	default:
		return event.Value{}, fmt.Errorf("%s: unexpected token %v", name, tok)
	}
}

func (n *Normalizer) put(out map[string]event.Value, name string, v event.Value) error {
	if c, ok := n.canon[strings.ToLower(name)]; ok {
		name = c
	}
	if _, dup := out[name]; dup {
		return fail(ReasonDuplicateField, "%s appears twice", name)
	}
	out[name] = v
	return nil
}
