package event

import "time"

// Event is the unit of work. Seq is assigned once, at ingest, and is
// monotonic within a partition. Everything downstream is keyed on it.
type Event struct {
	Seq       uint64
	Partition int32
	Source    string
	EventTime time.Time
	IngestAt  time.Time
	Fields    map[string]Value
	Raw       []byte
}

// Field returns the named field. An absent field reads as null, which is
// what makes "field: null" match both absence and an explicit null.
func (e *Event) Field(name string) Value {
	if v, ok := e.Fields[name]; ok {
		return v
	}
	return Null()
}

// Verdict is the equivalence unit. One per (event, enabled rule).
type Verdict struct {
	Seq       uint64
	Partition int32
	RuleID    string
	Matched   bool
	Engine    string
	RuleSetV  string
	TaxonomyV string
}
