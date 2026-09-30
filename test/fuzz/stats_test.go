package fuzz

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestRecordOutcomeIncrementsGivenCounter(t *testing.T) {
	// Passing a local counter, rather than one of the package's globals,
	// isolates the increment behavior from the shared statWrites counter
	// that other tests and the fuzz target's seed corpus also advance in
	// the same test binary.
	var c atomic.Uint64
	for i := 0; i < 5; i++ {
		recordOutcome(&c)
	}
	if got := c.Load(); got != 5 {
		t.Fatalf("counter = %d, want 5", got)
	}
}

// FlushStats must be a no-op when SIGNALMAN_FUZZ_STATS is unset: an ordinary
// go test run has no such directory to write into, and the function must not
// assume one exists.
func TestFlushStatsNoopWithoutEnv(t *testing.T) {
	t.Setenv("SIGNALMAN_FUZZ_STATS", "")
	FlushStats() // must not panic or attempt to create a "" path
}

func TestFlushStatsWritesCounterFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SIGNALMAN_FUZZ_STATS", dir)

	want := snapshot()
	FlushStats()

	path := filepath.Join(dir, fmt.Sprintf("%d.json", os.Getpid()))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var got stats
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	if got != want {
		t.Fatalf("flushed stats = %+v, want the snapshot taken just before the flush: %+v", got, want)
	}
}
