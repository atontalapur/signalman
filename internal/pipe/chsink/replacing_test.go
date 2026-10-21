package chsink

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/pipe"
)

// replacingTable models the parts of a ClickHouse ReplacingMergeTree that
// the sink's idempotence rests on. Each insert is a new part. A merge
// collapses rows with equal sorting key into the last one inserted, but only
// within a PARTITION BY partition: rows in different days never meet. FINAL
// is a merge at read time.
type replacingTable struct {
	mu    sync.Mutex
	parts [][]pipe.Alert
}

func (t *replacingTable) Insert(_ context.Context, rows []pipe.Alert) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.parts = append(t.parts, slices.Clone(rows))
	return nil
}

type sortKey struct {
	day       string // toYYYYMMDD(ingest_time)
	partition int32
	seq       uint64
	ruleID    string
}

func keyOf(a pipe.Alert) sortKey {
	return sortKey{a.IngestTime.UTC().Format("20060102"), a.Partition, a.Seq, a.RuleID}
}

// final returns the merged rows in (day, ORDER BY) order without merging
// the stored parts, like SELECT ... FINAL.
func (t *replacingTable) final() []pipe.Alert {
	t.mu.Lock()
	defer t.mu.Unlock()
	return collapse(t.parts)
}

// optimize merges every part into one, like OPTIMIZE TABLE ... FINAL.
func (t *replacingTable) optimize() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.parts = [][]pipe.Alert{collapse(t.parts)}
}

// rawRows is every stored row, duplicates included, like a SELECT without
// FINAL before any merge.
func (t *replacingTable) rawRows() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, p := range t.parts {
		n += len(p)
	}
	return n
}

func collapse(parts [][]pipe.Alert) []pipe.Alert {
	last := map[sortKey]pipe.Alert{}
	for _, p := range parts {
		for _, r := range p {
			last[keyOf(r)] = r
		}
	}
	keys := slices.SortedFunc(maps.Keys(last), func(a, b sortKey) int {
		return cmp.Or(cmp.Compare(a.day, b.day), cmp.Compare(a.partition, b.partition),
			cmp.Compare(a.seq, b.seq), cmp.Compare(a.ruleID, b.ruleID))
	})
	out := make([]pipe.Alert, len(keys))
	for i, k := range keys {
		out[i] = last[k]
	}
	return out
}

var ruleIDs = []string{
	"c63673f9-e75c-4103-9a9c-465b14613393",
	"aad57149-4ecc-4a95-ab46-b4675f5151df",
	"35b87878-bbdd-4cbf-89e0-b956b945d034",
}

var base = time.Date(2026, 10, 1, 23, 59, 0, 0, time.UTC)

// genAlert builds the alert the pipeline would write for (partition, seq,
// rule). Everything is a function of those three, as it is in the pipeline,
// where the alert is a function of the event and the rule.
func genAlert(partition int32, seq uint64, rule int) pipe.Alert {
	et := base.Add(time.Duration(seq) * 7 * time.Second)
	return pipe.Alert{
		Partition:  partition,
		Seq:        seq,
		RuleID:     ruleIDs[rule],
		RuleTitle:  fmt.Sprintf("rule %d", rule),
		Severity:   []string{"low", "medium", "high"}[rule],
		EventTime:  et,
		IngestTime: et.Add(time.Second),
		HostID:     fmt.Sprintf("host-%d", partition),
		Source:     "sysmon",
		Fields:     map[string]string{"Image": fmt.Sprintf(`C:\p%d.exe`, seq)},
		Raw:        fmt.Sprintf(`{"seq":%d}`, seq),
		Engine:     []string{"v1", "v2"}[rule%2],
	}
}

func genBatch(r *rand.Rand) []pipe.Alert {
	n := 1 + r.IntN(60)
	out := make([]pipe.Alert, 0, n)
	for range n {
		out = append(out, genAlert(int32(r.IntN(4)), uint64(r.IntN(40)), r.IntN(len(ruleIDs))))
	}
	return out
}

// TestModelReingestChangesNoRow checks the S-40 property against
// replacingTable, a model of the merge written for this test: inserting an
// identical batch again, whole or in part, changes no row after merge. It
// shows the sink's redelivery pattern is safe if ClickHouse merges the way
// the model does; it is not evidence that it does.
// TestReingestCollapsesInClickHouse (integration) is that evidence.
func TestModelReingestChangesNoRow(t *testing.T) {
	for seed := range uint64(500) {
		r := rand.New(rand.NewPCG(seed, 40))
		tbl := &replacingTable{}
		ctx := context.Background()
		// Some history the redelivery lands on top of.
		for range r.IntN(3) {
			_ = tbl.Insert(ctx, genBatch(r))
		}
		batch := genBatch(r)
		_ = tbl.Insert(ctx, batch)
		before := tbl.final()

		// Redeliver the whole batch, then a prefix of it, the shape a crash
		// mid-insert leaves behind.
		_ = tbl.Insert(ctx, batch)
		_ = tbl.Insert(ctx, batch[:r.IntN(len(batch)+1)])
		if after := tbl.final(); !reflect.DeepEqual(before, after) {
			t.Fatalf("seed %d: FINAL changed after reingest\nbefore %v\nafter  %v", seed, before, after)
		}
		tbl.optimize()
		if after := tbl.final(); !reflect.DeepEqual(before, after) {
			t.Fatalf("seed %d: rows changed after OPTIMIZE FINAL", seed)
		}
		if tbl.rawRows() != len(before) {
			t.Fatalf("seed %d: %d rows after OPTIMIZE FINAL, %d distinct keys", seed, tbl.rawRows(), len(before))
		}
	}
}

// The property above would hold for a table that keeps nothing. These pin
// that the model collapses on the key and only on the key.
func TestReplacingModelCollapsesOnKeyOnly(t *testing.T) {
	tbl := &replacingTable{}
	ctx := context.Background()
	a := genAlert(1, 5, 0)
	_ = tbl.Insert(ctx, []pipe.Alert{a, genAlert(1, 5, 1), genAlert(2, 5, 0), genAlert(1, 6, 0)})
	if got := len(tbl.final()); got != 4 {
		t.Fatalf("%d rows; distinct keys must all survive", got)
	}
	changed := a
	changed.RuleTitle = "renamed"
	_ = tbl.Insert(ctx, []pipe.Alert{changed})
	rows := tbl.final()
	i := slices.IndexFunc(rows, func(r pipe.Alert) bool { return keyOf(r) == keyOf(a) })
	if len(rows) != 4 || i < 0 || rows[i].RuleTitle != "renamed" {
		t.Fatalf("same key must collapse to the last insert: %v", rows)
	}
	// The same key on another day sits in another PARTITION BY partition.
	other := a
	other.IngestTime = a.IngestTime.Add(24 * time.Hour)
	_ = tbl.Insert(ctx, []pipe.Alert{other})
	if got := len(tbl.final()); got != 5 {
		t.Fatalf("%d rows; a different day is a different partition", got)
	}
}

// flaky is a ClickHouse that can be taken down and brought back.
type flaky struct {
	tbl      *replacingTable
	mu       sync.Mutex
	down     bool
	attempts int
	// onInsert runs after a successful insert, outside the lock.
	onInsert func()
}

var errDown = errors.New("clickhouse: connection refused")

func (f *flaky) Insert(ctx context.Context, rows []pipe.Alert) error {
	f.mu.Lock()
	f.attempts++
	down := f.down
	f.mu.Unlock()
	if down {
		return errDown
	}
	if err := f.tbl.Insert(ctx, rows); err != nil {
		return err
	}
	if f.onInsert != nil {
		f.onInsert()
	}
	return nil
}

func (f *flaky) setDown(d bool) {
	f.mu.Lock()
	f.down = d
	f.mu.Unlock()
}

func (f *flaky) attemptCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts
}
