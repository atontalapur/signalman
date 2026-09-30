package fuzz

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// The raw execution count go test prints is not the number the gate cares
// about. Many inputs are skipped before either engine (empty values,
// invalid UTF-8, patterns reSafe declines), and an input that never reached
// either engine proves nothing. These counters separate
// the outcomes so what gets recorded in docs/results.md is the number of
// real comparisons.
var (
	statCompared   atomic.Uint64 // both engines produced a verdict, and agreed
	statRejected   atomic.Uint64 // both engines refused the rule
	statSuppressed atomic.Uint64 // landed in a KNOWN_DIVERGENCES.md gap
	statTimeout    atomic.Uint64 // the oracle hung and was replaced
	statSkipped    atomic.Uint64 // never reached either engine
	statWrites     atomic.Uint64
)

type stats struct {
	Compared   uint64 `json:"compared"`
	Rejected   uint64 `json:"rejected_by_both"`
	Suppressed uint64 `json:"suppressed"`
	Timeout    uint64 `json:"oracle_timeout"`
	Skipped    uint64 `json:"skipped"`
}

func snapshot() stats {
	return stats{
		Compared:   statCompared.Load(),
		Rejected:   statRejected.Load(),
		Suppressed: statSuppressed.Load(),
		Timeout:    statTimeout.Load(),
		Skipped:    statSkipped.Load(),
	}
}

// Stats renders the counters for a test log line.
func Stats() string {
	s := snapshot()
	return fmt.Sprintf("compared=%d rejected-by-both=%d suppressed=%d oracle-timeout=%d skipped=%d",
		s.Compared, s.Rejected, s.Suppressed, s.Timeout, s.Skipped)
}

// statsFlushEvery bounds how much a killed worker can lose. Fuzzing runs the
// target in worker processes that the coordinator may kill outright, so the
// counters have to reach disk during the run, not at the end of it.
const statsFlushEvery = 128

// recordOutcome bumps a counter and periodically writes the process's
// counters to the directory named by SIGNALMAN_FUZZ_STATS, one file per
// process.
// scripts/fuzz_stats.py sums them. Without this, a fuzz run's real
// comparison count is unobservable: each worker is its own process and the
// coordinator only reports executions.
func recordOutcome(c *atomic.Uint64) {
	c.Add(1)
	if statWrites.Add(1)%statsFlushEvery == 0 {
		FlushStats()
	}
}

// statsFile names this process's counter file. The start time keeps a
// later process that reuses the pid from replacing an earlier one's counts.
var statsFile = fmt.Sprintf("%d-%d.json", os.Getpid(), time.Now().UnixNano())

// FlushStats writes this process's counters. It is a no-op when
// SIGNALMAN_FUZZ_STATS is unset, which is the case for an ordinary go test
// run. A failed write is ignored on purpose: losing a statistic must not
// fail a fuzz case, and scripts/fuzz_stats.py undercounts rather than
// overcounts when one is lost.
func FlushStats() {
	dir := os.Getenv("SIGNALMAN_FUZZ_STATS")
	if dir == "" {
		return
	}
	_ = writeStats(dir, snapshot())
}

// writeStats replaces this process's counter file. Each flush holds the
// cumulative counts, so the write goes to a temporary name and is renamed
// into place: a worker killed mid-write leaves its previous flush intact
// instead of a truncated file that loses every count it made. A process
// that evaluated nothing writes nothing.
func writeStats(dir string, s stats) error {
	if s == (stats{}) {
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, statsFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
