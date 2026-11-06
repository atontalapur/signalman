package loadtest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
)

// fakeClock advances only when slept on, or when a produce costs time.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	c.advance(d)
	return true
}

// recorder is a broker that records when each Produce happened and can
// make each call cost clock time or fail.
type recorder struct {
	broker.Broker
	clock *fakeClock
	cost  time.Duration
	fail  int
	// partial is how many records of a failing call are written anyway,
	// as a Kafka ProduceSync may do before it returns an error.
	partial int
	failErr error
	at      []time.Duration
	sizes   []int
	recs    []broker.Record
	t0      time.Time
}

func (r *recorder) Produce(ctx context.Context, recs []broker.Record) error {
	if r.fail > 0 {
		r.fail--
		r.recs = append(r.recs, recs[:min(r.partial, len(recs))]...)
		if r.failErr != nil {
			return r.failErr
		}
		return errors.New("injected")
	}
	r.at = append(r.at, r.clock.Now().Sub(r.t0))
	r.sizes = append(r.sizes, len(recs))
	r.recs = append(r.recs, recs...)
	r.clock.advance(r.cost)
	return nil
}

func tinyCorpus(n int) *Corpus {
	c := &Corpus{}
	for i := range n {
		c.Records = append(c.Records, rawRecord(hostKey(i), SourceLoadgen, []byte{byte('a' + i)}))
	}
	return c
}

func TestReplaySendsTheProfileOnSchedule(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := &recorder{clock: clk, t0: clk.Now()}
	st, err := Replay(context.Background(), r, tinyCorpus(7), ReplayConfig{
		Phases: []Phase{{Rate: 1000, For: time.Second}, {Rate: 0, For: 500 * time.Millisecond}, {Rate: 200, For: time.Second}},
		Batch:  100,
		Clock:  clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Sent != 1200 || len(r.recs) != 1200 {
		t.Fatalf("sent %d (recorded %d), want 1000 + 0 + 200", st.Sent, len(r.recs))
	}
	// 10 batches of 100 at 100ms steps, then 2 at 1.5s and 2.0s.
	want := []time.Duration{0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1500, 2000}
	if len(r.at) != len(want) {
		t.Fatalf("%d batches at %v", len(r.at), r.at)
	}
	for i, w := range want {
		if r.at[i] != w*time.Millisecond {
			t.Fatalf("batch %d at %v, want %vms (all %v)", i, r.at[i], w, r.at)
		}
	}
	if st.Elapsed != 2500*time.Millisecond {
		t.Fatalf("elapsed %v, want the profile's 2.5s", st.Elapsed)
	}
	// Records cycle through the corpus in order.
	for i, rec := range r.recs {
		if rec.Value[0] != byte('a'+i%7) {
			t.Fatalf("record %d is %q, want corpus record %d", i, rec.Value, i%7)
		}
	}
}

func TestReplayThatFallsBehindNeverSkipsOrBursts(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	// Each batch costs 250ms against a schedule of one per 100ms.
	r := &recorder{clock: clk, t0: clk.Now(), cost: 250 * time.Millisecond}
	st, err := Replay(context.Background(), r, tinyCorpus(3), ReplayConfig{
		Phases: []Phase{{Rate: 1000, For: time.Second}},
		Batch:  100,
		Clock:  clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Sent != 1000 {
		t.Fatalf("sent %d, want every record of the profile", st.Sent)
	}
	for i, n := range r.sizes {
		if n != 100 {
			t.Fatalf("batch %d had %d records; catching up must not grow batches", i, n)
		}
	}
	if st.MaxBehind < time.Second {
		t.Fatalf("MaxBehind %v; a broker 2.5x too slow must show as lateness", st.MaxBehind)
	}
}

func TestReplayRetriesAFailedProduceWithTheSameRecords(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := &recorder{clock: clk, t0: clk.Now(), fail: 3}
	st, err := Replay(context.Background(), r, tinyCorpus(5), ReplayConfig{
		Phases: []Phase{{Rate: 100, For: time.Second}},
		Batch:  10,
		Clock:  clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Retries != 3 || st.Sent != 100 || len(r.recs) != 100 {
		t.Fatalf("retries %d sent %d recorded %d", st.Retries, st.Sent, len(r.recs))
	}
	if r.recs[0].Value[0] != 'a' {
		t.Fatal("the failed batch was skipped instead of retried")
	}
}

func TestReplayStartContinuesTheCorpus(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := &recorder{clock: clk, t0: clk.Now()}
	if _, err := Replay(context.Background(), r, tinyCorpus(5), ReplayConfig{
		Phases: []Phase{{Rate: 10, For: time.Second}}, Start: 3, Clock: clk,
	}); err != nil {
		t.Fatal(err)
	}
	if r.recs[0].Value[0] != 'd' {
		t.Fatalf("first record %q, want corpus record 3", r.recs[0].Value)
	}
}

func TestPhaseCount(t *testing.T) {
	for _, c := range []struct {
		p    Phase
		want int
	}{
		{Phase{Rate: 2500, For: 1500 * time.Millisecond}, 3750},
		{Phase{Rate: 0, For: time.Hour}, 0},
		{Phase{Rate: 3.3, For: time.Second}, 3},
	} {
		if got := c.p.Count(); got != c.want {
			t.Fatalf("%+v.Count() = %d, want %d", c.p, got, c.want)
		}
	}
}

func TestReplayCountsRecordsResentAfterAPartialFailure(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := &recorder{clock: clk, t0: clk.Now(), fail: 2, partial: 4}
	st, err := Replay(context.Background(), r, tinyCorpus(5), ReplayConfig{
		Phases: []Phase{{Rate: 100, For: time.Second}},
		Batch:  10,
		Clock:  clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Two failed calls of 10 records, each resent whole: 20 resent, of which
	// the 8 written before the failures are duplicates in the log.
	if st.Sent != 100 || st.Retries != 2 || st.Resent != 20 || len(r.recs) != 108 {
		t.Fatalf("sent %d retries %d resent %d recorded %d", st.Sent, st.Retries, st.Resent, len(r.recs))
	}
}

func TestReplayStopsOnAPermanentProduceError(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	r := &recorder{clock: clk, t0: clk.Now(), fail: 1000, failErr: fmt.Errorf("%w: too large", broker.ErrPermanent)}
	st, err := Replay(context.Background(), r, tinyCorpus(5), ReplayConfig{
		Phases: []Phase{{Rate: 100, For: time.Second}},
		Batch:  10,
		Clock:  clk,
	})
	if !errors.Is(err, broker.ErrPermanent) {
		t.Fatalf("err %v, want ErrPermanent", err)
	}
	if st.Retries != 0 || st.Sent != 0 {
		t.Fatalf("retries %d sent %d after a permanent error", st.Retries, st.Sent)
	}
}
