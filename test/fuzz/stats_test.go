package fuzz

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
// fall back to the working directory.
func TestFlushStatsNoopWithoutEnv(t *testing.T) {
	t.Setenv("SIGNALMAN_FUZZ_STATS", "")
	t.Chdir(t.TempDir())
	FlushStats()
	if files, _ := filepath.Glob("*.json*"); len(files) != 0 {
		t.Fatalf("FlushStats wrote %v with the env var unset", files)
	}
}

func TestWriteStatsWritesCounterFileAtomically(t *testing.T) {
	dir := t.TempDir()
	want := stats{Compared: 3, Suppressed: 1}
	if err := writeStats(dir, want); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(dir, statsFile))
	if err != nil {
		t.Fatal(err)
	}
	var got stats
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	if got != want {
		t.Fatalf("written stats = %+v, want %+v", got, want)
	}
	if tmps, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(tmps) != 0 {
		t.Fatalf("temporary files left behind: %v", tmps)
	}
}

// A process that evaluated nothing writes nothing. The fuzz coordinator runs
// the target's setup too, and a file of zeros from it would be counted as a
// worker.
func TestWriteStatsSkipsZeroCounters(t *testing.T) {
	dir := t.TempDir()
	if err := writeStats(dir, stats{}); err != nil {
		t.Fatal(err)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "*")); len(files) != 0 {
		t.Fatalf("zero counters wrote %v", files)
	}
}

// The file name must not collide with an earlier process that had the same
// pid within one run: each flush holds that process's cumulative counters
// and replaces its own file.
func TestStatsFileNameIsPerProcessStart(t *testing.T) {
	prefix := fmt.Sprintf("%d-", os.Getpid())
	if !strings.HasPrefix(statsFile, prefix) || !strings.HasSuffix(statsFile, ".json") || statsFile == prefix+".json" {
		t.Fatalf("statsFile = %q, want %s<start>.json", statsFile, prefix)
	}
}
