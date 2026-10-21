package chsink

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/atontalapur/signalman/internal/pipe"
)

func TestClassifyInsertError(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		permanent bool
	}{
		{"type mismatch", &clickhouse.Exception{Code: 53, Message: "Type mismatch"}, true},
		{"unknown table", &clickhouse.Exception{Code: 60, Message: "Table signalman.alerts does not exist"}, true},
		{"enum element", &clickhouse.Exception{Code: 691, Message: "Unknown element 'x' for enum"}, true},
		{"wrapped", fmt.Errorf("send: %w", &clickhouse.Exception{Code: 321, Message: "out of range"}), true},
		{"partitions per block", &clickhouse.Exception{Code: 252, Message: "Too many partitions for single INSERT block (more than 100)"}, true},
		{"parts behind merges", &clickhouse.Exception{Code: 252, Message: "Too many parts (3000). Merges are processing significantly slower than inserts"}, false},
		{"memory limit", &clickhouse.Exception{Code: 241, Message: "Memory limit exceeded"}, false},
		{"network", errors.New("dial tcp 127.0.0.1:9000: connect: connection refused"), false},
	}
	for _, c := range cases {
		got := classify(c.err)
		if errors.Is(got, ErrPermanent) != c.permanent {
			t.Errorf("%s: classify(%v) = %v, permanent want %v", c.name, c.err, got, c.permanent)
		}
		if !errors.Is(got, c.err) {
			t.Errorf("%s: classify dropped the cause: %v", c.name, got)
		}
	}
	if classify(nil) != nil {
		t.Error("classify(nil) must be nil")
	}
}

// refusing is a ClickHouse that refuses every insert with the same error.
type refusing struct {
	err      error
	attempts int
}

func (r *refusing) Insert(context.Context, []pipe.Alert) error {
	r.attempts++
	return r.err
}

// A permanent insert error would fail the same way on every retry, so the
// sink stops at once, names the offsets it holds, and commits nothing.
func TestSinkStopsOnAPermanentInsertError(t *testing.T) {
	b := newBroker(500)
	produceAlerts(t, b, 20)
	ins := &refusing{err: fmt.Errorf("%w: code: 53, message: Type mismatch", ErrPermanent)}
	cfg := testConfig()
	cfg.BatchRows = 1000
	s, err := New(cfg, b, ins, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = s.Run(ctx)
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("Run returned %v; want a permanent insert error", err)
	}
	if ins.attempts != 1 {
		t.Fatalf("%d insert attempts; a permanent error must not be retried", ins.attempts)
	}
	end, _ := b.EndOffsets(context.Background(), pipe.TopicAlerts)
	for p, off := range end {
		if off == 0 {
			continue
		}
		if want := fmt.Sprintf("alerts/%d offsets 0-%d", p, off-1); !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err, want)
		}
	}
	if got, _ := b.CommittedOffsets(context.Background(), group, pipe.TopicAlerts); len(got) != 0 {
		t.Fatalf("committed %v after a permanent error", got)
	}
}

// The sink commits an offset once Insert returns, so Insert must not return
// before the part is on disk.
func TestInsertAsksForFsync(t *testing.T) {
	if v, ok := insertSettings["fsync_after_insert"]; !ok || v != 1 {
		t.Fatalf("insert settings %v; want fsync_after_insert=1", insertSettings)
	}
}
