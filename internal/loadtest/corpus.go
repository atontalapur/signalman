package loadtest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus"
)

// Corpus is the ordered list of events.raw records a replay cycles
// through. Each record carries a host_id key, a source header, and the raw
// JSON body; Partition and Offset are left for the broker to assign.
type Corpus struct {
	Records []broker.Record
	// Excluded counts generated records left out because the normalizer
	// would drop them (for example a list inside a list). A load corpus that
	// contains drops by construction could not show that overload never
	// drops.
	Excluded int
}

// Hosts is how many distinct host_id keys generated records spread over.
// It is a constant so partition assignment is reproducible.
const Hosts = 64

// SourceLoadgen is the source header on generated records. It has to be
// one of pipe.Sources, or the normalizer drops every record as
// unknown-source; sysmon is the source most shipped rules are written for.
const SourceLoadgen = "sysmon"

// eventTimeBase is the first generated event_time (epoch milliseconds).
// Record i gets eventTimeBase + i, so event time is part of the record, not
// the wall clock.
const eventTimeBase = 1790000000000

func rawRecord(host, source string, body []byte) broker.Record {
	return broker.Record{
		Topic:     pipe.TopicEventsRaw,
		Partition: broker.AnyPartition,
		Key:       []byte(host),
		Value:     body,
		Headers:   []broker.Header{{Key: pipe.HeaderSource, Value: []byte(source)}},
	}
}

func hostKey(i int) string { return fmt.Sprintf("host-%02d", i%Hosts) }

// FromRules generates a corpus aimed at rs (see AimedFields) and keeps only
// the records tax's normalizer admits without a drop.
func FromRules(rs *sigma.RuleSet, tax *sigma.Taxonomy, perRule int, seed int64) (*Corpus, error) {
	if len(rs.Rules) == 0 {
		return nil, errors.New("loadtest: rule set is empty")
	}
	norm := pipe.NewNormalizer(tax, pipe.NormalizeConfig{}, obs.New(prometheus.NewRegistry()))
	in := pipe.NewIngest(obs.New(prometheus.NewRegistry()))
	c := &Corpus{}
	for i, f := range AimedFields(rs, perRule, seed) {
		body, err := encodeFields(f, int64(eventTimeBase+i))
		if err != nil {
			return nil, err
		}
		rec := rawRecord(hostKey(i), SourceLoadgen, body)
		if !admits(norm, in, rec) {
			c.Excluded++
			continue
		}
		c.Records = append(c.Records, rec)
	}
	if len(c.Records) == 0 {
		return nil, errors.New("loadtest: every generated record would be dropped")
	}
	return c, nil
}

// encodeFields is the raw JSON body for one generated event. encoding/json
// writes map keys sorted, so the bytes are a function of the fields.
func encodeFields(f map[string]event.Value, eventTime int64) ([]byte, error) {
	w := make(map[string]any, len(f)+1)
	for k, v := range f {
		w[k] = pipe.WireValue(v)
	}
	w["event_time"] = eventTime
	return json.Marshal(w)
}

func admits(norm *pipe.Normalizer, in *pipe.Ingest, rec broker.Record) bool {
	it := in.Admit(rec)
	norm.Normalize(it)
	return it.Drop == nil
}

// Drops reports how many of the corpus's records tax's normalizer would
// drop. Replaying a corpus with drops is allowed (the poison experiment
// does it on purpose); this says how many ledger entries to expect.
func (c *Corpus) Drops(tax *sigma.Taxonomy) int {
	norm := pipe.NewNormalizer(tax, pipe.NormalizeConfig{}, obs.New(prometheus.NewRegistry()))
	in := pipe.NewIngest(obs.New(prometheus.NewRegistry()))
	n := 0
	for _, r := range c.Records {
		if !admits(norm, in, r) {
			n++
		}
	}
	return n
}

// Inject returns a copy of c with recs[k % len(recs)] inserted after every
// every-th record. The original is unchanged.
func (c *Corpus) Inject(every int, recs []broker.Record) *Corpus {
	out := &Corpus{Excluded: c.Excluded}
	k := 0
	for i, r := range c.Records {
		out.Records = append(out.Records, r)
		if every > 0 && len(recs) > 0 && (i+1)%every == 0 {
			out.Records = append(out.Records, recs[k%len(recs)])
			k++
		}
	}
	return out
}

// maxLine bounds one corpus line, as in cmd/signalman.
const maxLine = 16 << 20

// ReadNDJSON reads every .ndjson and .jsonl file under dir, in sorted path
// order, one JSON object per line, blank lines skipped. Each line becomes
// one record exactly as written. The key is the line's host_id field when
// it has a string one, and a generated host otherwise; the source header is
// the line's source field when it has a string one, and source otherwise.
// A line that is not JSON is kept: what the pipeline does with it is part
// of what a replay measures, and Drops says how many to expect.
func ReadNDJSON(dir, source string) (*Corpus, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			if ext := filepath.Ext(p); ext == ".ndjson" || ext == ".jsonl" {
				files = append(files, p)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	c := &Corpus{}
	for _, f := range files {
		if err := c.readFile(f, source); err != nil {
			return nil, err
		}
	}
	if len(c.Records) == 0 {
		return nil, fmt.Errorf("no events in .ndjson or .jsonl files under %s", dir)
	}
	return c, nil
}

func (c *Corpus) readFile(path, source string) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var id struct {
			HostID any `json:"host_id"`
			Source any `json:"source"`
		}
		_ = json.Unmarshal(b, &id)
		host, ok := id.HostID.(string)
		if !ok || host == "" {
			host = hostKey(len(c.Records))
		}
		src, ok := id.Source.(string)
		if !ok || src == "" {
			src = source
		}
		c.Records = append(c.Records, rawRecord(host, src, bytes.Clone(b)))
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s:%d: %w", path, line+1, err)
	}
	return nil
}

// poisonMarker marks a poison record. No generated or SigmaHQ-aimed field
// uses the name.
var poisonMarker = []byte(`"signalman_poison"`)

// PoisonRecord is a well-formed record that PoisonFault makes the
// normalizer panic on.
func PoisonRecord(host string) broker.Record {
	return rawRecord(host, SourceLoadgen, []byte(`{"event_time":1790000000000,"signalman_poison":true}`))
}

// PoisonFault is a pipe.Normalizer fault (SetFault) that panics on a poison
// record and does nothing otherwise.
func PoisonFault(raw []byte) {
	if bytes.Contains(raw, poisonMarker) {
		panic("loadtest: poison record")
	}
}

// MalformedRecords is one record per decode drop reason, keyed to host:
// every way a record from a real source can fail to normalize.
func MalformedRecords(host string) map[string]broker.Record {
	noSource := rawRecord(host, "", []byte(`{"event_time":1}`))
	noSource.Headers = nil
	return map[string]broker.Record{
		pipe.ReasonParse:          rawRecord(host, SourceLoadgen, []byte(`{"event_time":1,`)),
		pipe.ReasonInvalidUTF8:    rawRecord(host, SourceLoadgen, []byte("{\"event_time\":1,\"x\":\"\xff\"}")),
		pipe.ReasonValueTooLong:   rawRecord(host, SourceLoadgen, []byte(`{"event_time":1,"x":"`+strings.Repeat("a", 64<<10+1)+`"}`)),
		pipe.ReasonNestedValue:    rawRecord(host, SourceLoadgen, []byte(`{"event_time":1,"x":[[1]]}`)),
		pipe.ReasonDuplicateField: rawRecord(host, SourceLoadgen, []byte(`{"event_time":1,"x":1,"x":2}`)),
		pipe.ReasonMissingSource:  noSource,
		pipe.ReasonUnknownSource:  rawRecord(host, "loadgen", []byte(`{"event_time":1}`)),
		pipe.ReasonEventTime:      rawRecord(host, SourceLoadgen, []byte(`{"x":1}`)),
	}
}
