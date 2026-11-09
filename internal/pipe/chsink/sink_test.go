package chsink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const group = "signalman-sink-test"

// counting wraps a broker so a test can see how many polls returned records.
type counting struct {
	broker.Broker
	polls atomic.Int64
}

func (c *counting) Consume(group string, topics []string) (broker.Consumer, error) {
	cons, err := c.Broker.Consume(group, topics)
	if err != nil {
		return nil, err
	}
	return &countingConsumer{Consumer: cons, n: &c.polls}, nil
}

type countingConsumer struct {
	broker.Consumer
	n *atomic.Int64
}

// Owned passes ownership through, so lag accounting sees what the wrapped
// consumer owns.
func (c *countingConsumer) Owned() []broker.TopicPartition {
	if o, ok := c.Consumer.(broker.Owner); ok {
		return o.Owned()
	}
	return nil
}

func (c *countingConsumer) Poll(ctx context.Context) (broker.Fetch, error) {
	f, err := c.Consumer.Poll(ctx)
	if err == nil {
		c.n.Add(1)
	}
	return f, err
}

func newBroker(maxPoll int) *counting {
	return &counting{Broker: broker.NewMemory(map[string]int32{pipe.TopicAlerts: 3, pipe.TopicAlertsDead: 2, pipe.TopicEventsRaw: 4}, broker.WithMaxPoll(maxPoll))}
}

// readTopic returns every record in topic.
func readTopic(t *testing.T, b broker.Broker, topic string) []broker.Record {
	t.Helper()
	ctx := context.Background()
	end, err := b.EndOffsets(ctx, topic)
	if err != nil {
		t.Fatal(err)
	}
	var out []broker.Record
	for p, n := range end {
		if n == 0 {
			continue
		}
		c, err := b.ReadFrom(map[broker.TopicPartition]int64{{Topic: topic, Partition: p}: 0})
		if err != nil {
			t.Fatal(err)
		}
		for got := int64(0); got < n; {
			pctx, cancel := context.WithTimeout(ctx, time.Second)
			f, err := c.Poll(pctx)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, f.Records...)
			got += int64(len(f.Records))
		}
		c.Close()
	}
	return out
}

func alertRecord(t *testing.T, a pipe.Alert) broker.Record {
	t.Helper()
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return broker.Record{Topic: pipe.TopicAlerts, Partition: broker.AnyPartition, Key: []byte(a.RuleID), Value: b}
}

// produceAlerts writes n distinct alerts and returns them.
func produceAlerts(t *testing.T, b broker.Broker, n int) []pipe.Alert {
	t.Helper()
	var as []pipe.Alert
	var recs []broker.Record
	for i := range n {
		a := genAlert(int32(i%4), uint64(i), i%len(ruleIDs))
		as = append(as, a)
		recs = append(recs, alertRecord(t, a))
	}
	if err := b.Produce(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	return as
}

func testConfig() Config {
	return Config{Group: group, BatchRows: 10, FlushInterval: 20 * time.Millisecond, RetryBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}
}

func committedAll(t *testing.T, b broker.Broker) bool {
	t.Helper()
	ctx := context.Background()
	end, err := b.EndOffsets(ctx, pipe.TopicAlerts)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.CommittedOffsets(ctx, group, pipe.TopicAlerts)
	if err != nil {
		t.Fatal(err)
	}
	for p, off := range end {
		if off > 0 && got[p] != off {
			return false
		}
	}
	return true
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func start(t *testing.T, s *Sink) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx) }()
	return func() error {
		cancel()
		return <-errc
	}
}

func sameKeys(t *testing.T, want []pipe.Alert, got []pipe.Alert) {
	t.Helper()
	ref := &replacingTable{}
	_ = ref.Insert(context.Background(), want)
	exp := ref.final()
	if len(exp) != len(got) {
		t.Fatalf("table has %d rows, want %d", len(got), len(exp))
	}
	for i := range exp {
		if keyOf(exp[i]) != keyOf(got[i]) {
			t.Fatalf("row %d is %v, want %v", i, keyOf(got[i]), keyOf(exp[i]))
		}
	}
}

func TestSinkInsertsEveryAlertAndCommits(t *testing.T) {
	b := newBroker(7)
	want := produceAlerts(t, b, 95)
	tbl := &replacingTable{}
	reg := prometheus.NewRegistry()
	s, err := New(testConfig(), b, tbl, obs.New(reg), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := start(t, s)
	waitFor(t, "every offset committed", func() bool { return committedAll(t, b) })
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	sameKeys(t, want, tbl.final())
	if tbl.rawRows() != len(want) {
		t.Fatalf("%d rows inserted for %d alerts with no redelivery", tbl.rawRows(), len(want))
	}
	for _, part := range tbl.parts {
		if len(part) > 10+7 {
			t.Fatalf("an insert of %d rows exceeds BatchRows plus one poll", len(part))
		}
	}
	for p := range 3 {
		if v := testutil.ToFloat64(s.m.ConsumerLag.WithLabelValues(pipe.TopicAlerts, strconv.Itoa(p))); v != 0 {
			t.Fatalf("partition %d lag %v after everything committed", p, v)
		}
	}
}

// A partial batch is flushed after FlushInterval, not held until BatchRows.
func TestSinkFlushesAPartialBatchOnInterval(t *testing.T) {
	b := newBroker(500)
	want := produceAlerts(t, b, 3)
	tbl := &replacingTable{}
	cfg := testConfig()
	cfg.BatchRows = 1000
	s, err := New(cfg, b, tbl, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := start(t, s)
	waitFor(t, "the partial batch committed", func() bool { return committedAll(t, b) })
	_ = stop()
	sameKeys(t, want, tbl.final())
}

// TestSinkBackpressuresDuringOutage is the S-40 outage case. While
// ClickHouse refuses inserts the sink keeps retrying one batch, commits
// nothing, and stops polling; when it comes back every alert lands.
func TestSinkBackpressuresDuringOutage(t *testing.T) {
	b := newBroker(10)
	want := produceAlerts(t, b, 50)
	ch := &flaky{tbl: &replacingTable{}, down: true}
	s, err := New(testConfig(), b, ch, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := start(t, s)

	waitFor(t, "repeated insert attempts", func() bool { return ch.attemptCount() >= 20 })
	polls := b.polls.Load()
	waitFor(t, "more insert attempts", func() bool { return ch.attemptCount() >= 40 })
	if got := b.polls.Load(); got != polls || got != 1 {
		t.Fatalf("sink polled %d times (then %d) during the outage; it must stop at the first batch", polls, got)
	}
	got, err := b.CommittedOffsets(context.Background(), group, pipe.TopicAlerts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("offsets committed during the outage: %v", got)
	}
	if n := ch.tbl.rawRows(); n != 0 {
		t.Fatalf("%d rows written while down", n)
	}

	ch.setDown(false)
	waitFor(t, "every offset committed after recovery", func() bool { return committedAll(t, b) })
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	sameKeys(t, want, ch.tbl.final())
}

// While an insert is retried the sink does not poll, so the high watermarks
// a poll returns go stale. The lag gauge must still count what arrives
// during the outage: it is the backlog an operator looks for. The ClickHouse
// outage on Redpanda (docs/load.md, "ClickHouse unavailable") showed it
// frozen at 1,043 while the backlog was 1.2 million.
func TestSinkLagGrowsDuringOutage(t *testing.T) {
	b := newBroker(10)
	first := produceAlerts(t, b, 30)
	ch := &flaky{tbl: &replacingTable{}, down: true}
	reg := prometheus.NewRegistry()
	cfg := testConfig()
	cfg.LagRefreshInterval = time.Millisecond
	s, err := New(cfg, b, ch, obs.New(reg), nil)
	if err != nil {
		t.Fatal(err)
	}
	lag := func() float64 {
		var sum float64
		for p := range 3 {
			sum += testutil.ToFloat64(s.m.ConsumerLag.WithLabelValues(pipe.TopicAlerts, strconv.Itoa(p)))
		}
		return sum
	}
	stop := start(t, s)
	waitFor(t, "the first insert attempts", func() bool { return ch.attemptCount() >= 3 })
	later := produceAlerts(t, b, 60)
	waitFor(t, "lag counting the alerts produced during the outage", func() bool {
		return lag() == float64(len(first)+len(later))
	})
	ch.setDown(false)
	waitFor(t, "every offset committed after recovery", func() bool { return committedAll(t, b) })
	waitFor(t, "lag back to zero", func() bool { return lag() == 0 })
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
}

// A crash after the insert and before the commit redelivers the batch. The
// table after the second run, merged, is the table a single delivery leaves.
func TestSinkRedeliveryCollapses(t *testing.T) {
	b := newBroker(500)
	want := produceAlerts(t, b, 40)
	cfg := testConfig()
	cfg.BatchRows = 1000

	ch := &flaky{tbl: &replacingTable{}}
	ctx, cancel := context.WithCancel(context.Background())
	ch.onInsert = cancel // the process dies the moment the insert lands
	s, err := New(cfg, b, ch, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	if committedAll(t, b) {
		t.Fatal("offsets were committed; the test needs a crash before the commit")
	}
	once := ch.tbl.final()

	ch.onInsert = nil
	s2, err := New(cfg, b, ch, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := start(t, s2)
	waitFor(t, "the redelivered batch committed", func() bool { return committedAll(t, b) })
	_ = stop()

	if ch.tbl.rawRows() != 2*len(want) {
		t.Fatalf("%d raw rows; the redelivery should have inserted every alert twice", ch.tbl.rawRows())
	}
	ch.tbl.optimize()
	if got := ch.tbl.final(); len(got) != len(once) || ch.tbl.rawRows() != len(want) {
		t.Fatalf("after merge %d rows, single delivery had %d", len(got), len(once))
	}
	sameKeys(t, want, ch.tbl.final())
}

// badRecords are alerts records the table cannot hold, each as it would be
// produced.
func badRecords(t *testing.T) map[string]broker.Record {
	t.Helper()
	cases := map[string]func(*pipe.Alert) []byte{
		"not json":            func(*pipe.Alert) []byte { return []byte("{") },
		"rule_id not uuid":    func(a *pipe.Alert) []byte { a.RuleID = "proc_dump"; return nil },
		"empty severity":      func(a *pipe.Alert) []byte { a.Severity = ""; return nil },
		"unknown severity":    func(a *pipe.Alert) []byte { a.Severity = "severe"; return nil },
		"event_time too late": func(a *pipe.Alert) []byte { a.EventTime = time.Date(2400, 1, 1, 0, 0, 0, 0, time.UTC); return nil },
		"empty engine":        func(a *pipe.Alert) []byte { a.Engine = ""; return nil },
		"unknown engine":      func(a *pipe.Alert) []byte { a.Engine = "v3"; return nil },
	}
	out := map[string]broker.Record{}
	for name, mut := range cases {
		bad := genAlert(0, 99, 0)
		raw := mut(&bad)
		rec := alertRecord(t, bad)
		if raw != nil {
			rec.Value = raw
		}
		out[name] = rec
	}
	return out
}

// A record the table cannot hold goes to alerts.dead with its position and
// the reason, is counted, and the sink carries on: one bad record must not
// stop alert storage for every partition. Its offset is committed only
// with the batch around it, after the dead-letter write.
func TestSinkDeadLettersAnUninsertableRecord(t *testing.T) {
	for name, rec := range badRecords(t) {
		t.Run(name, func(t *testing.T) {
			b := newBroker(500)
			want := produceAlerts(t, b, 5)
			if err := b.Produce(context.Background(), []broker.Record{rec}); err != nil {
				t.Fatal(err)
			}
			want = append(want, produceAlerts(t, b, 5)...)
			tbl := &replacingTable{}
			reg := prometheus.NewRegistry()
			s, err := New(testConfig(), b, tbl, obs.New(reg), nil)
			if err != nil {
				t.Fatal(err)
			}
			stop := start(t, s)
			waitFor(t, "every offset committed", func() bool { return committedAll(t, b) })
			if err := stop(); !errors.Is(err, context.Canceled) {
				t.Fatalf("Run returned %v", err)
			}
			sameKeys(t, want, tbl.final())

			dead := readTopic(t, b, pipe.TopicAlertsDead)
			if len(dead) != 1 {
				t.Fatalf("%d dead-letter records, want 1", len(dead))
			}
			d := dead[0]
			if string(d.Value) != string(rec.Value) || string(d.Key) != string(rec.Key) {
				t.Fatalf("dead-letter record %q does not carry the original %q", d.Value, rec.Value)
			}
			if string(d.Header(HeaderDeadTopic)) != pipe.TopicAlerts || len(d.Header(HeaderDeadPartition)) == 0 ||
				len(d.Header(HeaderDeadOffset)) == 0 || len(d.Header(HeaderDeadReason)) == 0 {
				t.Fatalf("dead-letter headers %v do not name the position and reason", d.Headers)
			}
			if v := testutil.ToFloat64(s.m.SinkDeadLetters); v != 1 {
				t.Fatalf("signalman_sink_dead_letters_total = %v, want 1", v)
			}
		})
	}
}

// A poll holding only a bad record still commits, so the sink does not
// redeliver it forever.
func TestSinkCommitsADeadLetterOnlyBatch(t *testing.T) {
	b := newBroker(500)
	if err := b.Produce(context.Background(), []broker.Record{badRecords(t)["not json"]}); err != nil {
		t.Fatal(err)
	}
	s, err := New(testConfig(), b, &replacingTable{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := start(t, s)
	waitFor(t, "the dead-lettered offset committed", func() bool { return committedAll(t, b) })
	_ = stop()
	if n := len(readTopic(t, b, pipe.TopicAlertsDead)); n != 1 {
		t.Fatalf("%d dead-letter records", n)
	}
}

// failingDead fails produces to alerts.dead while fail is set.
type failingDead struct {
	*counting
	mu   sync.Mutex
	fail error
	hits int
}

func (f *failingDead) Produce(ctx context.Context, recs []broker.Record) error {
	f.mu.Lock()
	err := f.fail
	if err != nil {
		f.hits++
	}
	f.mu.Unlock()
	if err != nil && len(recs) > 0 && recs[0].Topic == pipe.TopicAlertsDead {
		return err
	}
	return f.counting.Produce(ctx, recs)
}

func (f *failingDead) set(err error) {
	f.mu.Lock()
	f.fail = err
	f.mu.Unlock()
}

func (f *failingDead) hitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits
}

// While the dead-letter write fails, the sink retries it and commits
// nothing; the offset is committed only once the record is durable there.
func TestSinkCommitsOnlyAfterTheDeadLetterWrite(t *testing.T) {
	b := &failingDead{counting: newBroker(500)}
	produceAlerts(t, b.counting, 5)
	if err := b.counting.Produce(context.Background(), []broker.Record{badRecords(t)["not json"]}); err != nil {
		t.Fatal(err)
	}
	b.set(errors.New("redpanda: not leader for partition"))
	s, err := New(testConfig(), b, &replacingTable{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := start(t, s)
	waitFor(t, "repeated dead-letter attempts", func() bool { return b.hitCount() >= 10 })
	if got, _ := b.CommittedOffsets(context.Background(), group, pipe.TopicAlerts); len(got) != 0 {
		t.Fatalf("committed %v before the dead-letter write landed", got)
	}
	b.set(nil)
	waitFor(t, "every offset committed", func() bool { return committedAll(t, b) })
	_ = stop()
	if n := len(readTopic(t, b, pipe.TopicAlertsDead)); n != 1 {
		t.Fatalf("%d dead-letter records", n)
	}
}

// A dead-letter write that cannot succeed stops the sink with the record's
// position and commits nothing.
func TestSinkStopsOnAPermanentDeadLetterError(t *testing.T) {
	b := &failingDead{counting: newBroker(500)}
	if err := b.counting.Produce(context.Background(), []broker.Record{badRecords(t)["not json"]}); err != nil {
		t.Fatal(err)
	}
	b.set(fmt.Errorf("%w: produce: record too large", broker.ErrPermanent))
	s, err := New(testConfig(), b, &replacingTable{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = s.Run(ctx)
	if !errors.Is(err, broker.ErrPermanent) || !strings.Contains(err.Error(), "alerts/") || !strings.Contains(err.Error(), "offset") {
		t.Fatalf("Run returned %v; want a permanent error naming the record", err)
	}
	if got, _ := b.CommittedOffsets(context.Background(), group, pipe.TopicAlerts); len(got) != 0 {
		t.Fatalf("committed %v", got)
	}
}

// Without alerts.dead the sink would find out at the first bad record; it
// refuses to start instead.
func TestSinkRefusesToStartWithoutTheDeadLetterTopic(t *testing.T) {
	b := broker.NewMemory(map[string]int32{pipe.TopicAlerts: 3})
	s, err := New(testConfig(), b, &replacingTable{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Run(ctx); err == nil || !strings.Contains(err.Error(), pipe.TopicAlertsDead) {
		t.Fatalf("Run returned %v; want an error naming %s", err, pipe.TopicAlertsDead)
	}
}

// The canary age is tracked per events.raw partition, so the sink needs to
// list them; without the topic it refuses to start rather than export no
// age, which only absent() would catch.
func TestSinkRefusesToStartWithoutEventsRaw(t *testing.T) {
	b := broker.NewMemory(map[string]int32{pipe.TopicAlerts: 3, pipe.TopicAlertsDead: 2})
	s, err := New(testConfig(), b, &replacingTable{}, obs.New(prometheus.NewRegistry()), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Run(ctx); err == nil || !strings.Contains(err.Error(), pipe.TopicEventsRaw) {
		t.Fatalf("Run returned %v; want an error naming %s", err, pipe.TopicEventsRaw)
	}
}

// A dead-letter record fits the topic's size limit even when the original
// was at the limit: the value is cut and the cut is recorded.
func TestDeadLetterRecordFitsTheLimit(t *testing.T) {
	r := broker.Record{Topic: pipe.TopicAlerts, Partition: 2, Offset: 7, Key: []byte("k"), Value: make([]byte, broker.MaxMessageBytes-1)}
	d := deadRecord(pipe.TopicAlertsDead, r, errors.New(strings.Repeat("x", 10_000)))
	if n := broker.RecordSize(d); n > broker.MaxMessageBytes {
		t.Fatalf("dead-letter record is %d bytes, limit %d", n, broker.MaxMessageBytes)
	}
	if string(d.Header(HeaderDeadTruncated)) != strconv.Itoa(len(r.Value)) {
		t.Fatalf("truncation not recorded: %v", d.Header(HeaderDeadTruncated))
	}
	small := deadRecord(pipe.TopicAlertsDead, broker.Record{Topic: pipe.TopicAlerts, Value: []byte("{")}, errors.New("bad"))
	if small.Header(HeaderDeadTruncated) != nil || string(small.Value) != "{" {
		t.Fatal("a small record must be carried whole")
	}
}

func TestConfigRejectsZeroSizes(t *testing.T) {
	b := newBroker(1)
	if _, err := New(Config{}, b, &replacingTable{}, nil, nil); err == nil {
		t.Fatal("a zero config must be rejected")
	}
	cfg := testConfig()
	cfg.FlushInterval = 0
	if _, err := New(cfg, b, &replacingTable{}, nil, nil); err == nil {
		t.Fatal("FlushInterval is required")
	}
}

// Decode refuses a time the insert would store as a different time. For
// event_time that is the DateTime64(3) range cut at 2262-04-11, where the
// driver's UnixNano encoding overflows. ingest_time also feeds the TTL
// toDateTime(ingest_time) + INTERVAL 90 DAY, so it must stay in DateTime's
// 1970 to 2106 range with 90 days to spare.
func TestDecodeRejectsTimesOutsideDateTime64(t *testing.T) {
	cases := []struct {
		field   string
		ok, bad []time.Time
	}{
		{"event_time",
			[]time.Time{
				time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC),
				time.Unix(0, math.MaxInt64).UTC(),
			},
			[]time.Time{
				{},
				time.Date(1899, 12, 31, 23, 59, 59, 0, time.UTC),
				time.Unix(0, math.MaxInt64).Add(time.Nanosecond),
				time.Date(2262, 4, 12, 0, 0, 0, 0, time.UTC),
				time.Date(2290, 1, 1, 0, 0, 0, 0, time.UTC),
				time.Date(2299, 12, 31, 23, 59, 59, 999e6, time.UTC),
				time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC),
			}},
		{"ingest_time",
			[]time.Time{
				time.Unix(0, 0).UTC(),
				time.Date(2105, 11, 9, 6, 28, 15, 999e6, time.UTC),
			},
			[]time.Time{
				{},
				time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC),
				time.Unix(0, -1).UTC(),
				time.Date(2105, 11, 9, 6, 28, 16, 0, time.UTC),
				time.Date(2106, 2, 7, 6, 28, 15, 0, time.UTC),
				time.Date(2262, 4, 12, 0, 0, 0, 0, time.UTC),
				time.Date(2290, 1, 1, 0, 0, 0, 0, time.UTC),
			}},
	}
	for _, c := range cases {
		set := func(a *pipe.Alert, ts time.Time) {
			if c.field == "event_time" {
				a.EventTime = ts
			} else {
				a.IngestTime = ts
			}
		}
		for _, ts := range c.ok {
			a := genAlert(0, 1, 0)
			set(&a, ts)
			if _, err := Decode(alertRecord(t, a)); err != nil {
				t.Errorf("%s %v rejected: %v", c.field, ts, err)
			}
		}
		for _, ts := range c.bad {
			a := genAlert(0, 1, 0)
			set(&a, ts)
			_, err := Decode(alertRecord(t, a))
			if err == nil || !strings.Contains(err.Error(), c.field) {
				t.Errorf("%s %v: got %v, want an error naming %s", c.field, ts, err, c.field)
			}
		}
	}
}

// The bounds Decode accepts are times the driver encodes exactly. This
// appends them through clickhouse-go's own DateTime64(3) column, the path
// Insert takes, and reads them back.
func TestAcceptedTimeBoundsRoundTripThroughTheDriver(t *testing.T) {
	col, err := column.Type("DateTime64(3)").Column("event_time", &column.ServerContext{Timezone: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	// The first two bound event_time, the last two ingest_time.
	want := []time.Time{
		time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Unix(0, math.MaxInt64).UTC().Truncate(time.Millisecond),
		time.Unix(0, 0).UTC(),
		time.Date(2105, 11, 9, 6, 28, 15, 999e6, time.UTC),
	}
	for i, ts := range want {
		a := genAlert(0, 1, 0)
		if i < 2 {
			a.EventTime = ts
		} else {
			a.IngestTime = ts
		}
		if _, err := Decode(alertRecord(t, a)); err != nil {
			t.Fatalf("%v rejected: %v", ts, err)
		}
		if err := col.AppendRow(ts); err != nil {
			t.Fatal(err)
		}
	}
	for i, ts := range want {
		if got := col.Row(i, false).(time.Time); !got.Equal(ts) {
			t.Errorf("%v stored as %v", ts, got)
		}
	}
	// The case the old 2299 bound let through: stored as a time in 1705.
	if err := col.AppendRow(time.Date(2290, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if got := col.Row(len(want), false).(time.Time); got.Year() == 2290 {
		t.Errorf("2290 encoded as %v; the driver no longer overflows, so the bound can widen", got)
	}
}

func TestDecodeRoundTripsThePipelineAlert(t *testing.T) {
	a := genAlert(3, 17, 2)
	got, err := Decode(alertRecord(t, a))
	if err != nil {
		t.Fatal(err)
	}
	if keyOf(got) != keyOf(a) || got.Raw != a.Raw || got.Engine != a.Engine || got.Fields["Image"] != a.Fields["Image"] || !got.EventTime.Equal(a.EventTime) {
		t.Fatalf("decoded %+v from %+v", got, a)
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func sinkCanaryAges(t *testing.T, m *obs.Metrics) map[int32]float64 {
	t.Helper()
	out := map[int32]float64{}
	for p := range int32(4) {
		a, ok := m.SinkCanaryAge.Age(p)
		if !ok {
			t.Fatalf("events.raw partition %d has no sink canary age", p)
		}
		out[p] = a.Seconds()
	}
	return out
}

// The end-to-end canary: the sink's age for a partition resets only once a
// canary alert from it is stored in the table. Every events.raw partition
// is tracked from startup, so one whose canary never lands climbs. A failed
// insert and other rules' alerts reset nothing.
func TestSinkResetsCanaryAgeOnlyAfterTheCanaryAlertIsStored(t *testing.T) {
	b := newBroker(500)
	canary := genAlert(1, 7, 0)
	canary.RuleID, canary.RuleTitle, canary.Severity = pipe.CanaryRuleID, "signalman canary", "informational"
	other := genAlert(2, 8, 1)
	if err := b.Produce(context.Background(), []broker.Record{alertRecord(t, canary), alertRecord(t, other)}); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Unix(1790000000, 0)}
	m := obs.NewWithClock(prometheus.NewRegistry(), clk.Now)
	ch := &flaky{tbl: &replacingTable{}, down: true}
	s, err := New(testConfig(), b, ch, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := start(t, s)
	defer func() { _ = stop() }()

	waitFor(t, "failed insert attempts", func() bool { return ch.attemptCount() >= 5 })
	clk.Add(40 * time.Second)
	for p, a := range sinkCanaryAges(t, m) {
		if a != 40 {
			t.Fatalf("partition %d sink canary age %vs while ClickHouse is down, want 40", p, a)
		}
	}

	ch.setDown(false)
	waitFor(t, "the batch committed", func() bool { return committedAll(t, b) })
	clk.Add(10 * time.Second)
	want := map[int32]float64{0: 50, 1: 10, 2: 50, 3: 50}
	for p, a := range sinkCanaryAges(t, m) {
		if a != want[p] {
			t.Fatalf("partition %d sink canary age %vs after the insert, want %v", p, a, want[p])
		}
	}
	// signalmand owns signalman_canary_age_seconds; the sink never sets it.
	if _, ok := m.CanaryAge.Age(1); ok {
		t.Fatal("the sink set signalmand's canary age")
	}
}

// The pipeline empties Fields and sets fields_omitted when an alert would
// not fit the output limit. The sink must still accept that record and
// store it with an empty fields map, raw intact.
func TestDecodeAcceptsAnAlertWithFieldsOmitted(t *testing.T) {
	a := genAlert(3, 18, 2)
	a.Fields, a.FieldsOmitted = map[string]string{}, true
	got, err := Decode(alertRecord(t, a))
	if err != nil {
		t.Fatal(err)
	}
	if !got.FieldsOmitted || len(got.Fields) != 0 || got.Raw != a.Raw {
		t.Fatalf("decoded %+v from %+v", got, a)
	}
}
