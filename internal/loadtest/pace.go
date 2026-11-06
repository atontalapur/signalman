package loadtest

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
)

// Phase is one segment of a load profile: Rate records per second for For.
// A zero Rate is an idle phase, which is how a profile leaves room for the
// pipeline to drain.
type Phase struct {
	Rate float64
	For  time.Duration
}

// Count is how many records the phase sends: Rate x For, rounded. It is a
// function of the phase alone, so two runs of a profile send the same
// records whatever the machine did.
func (p Phase) Count() int {
	if p.Rate <= 0 {
		return 0
	}
	return int(math.Round(p.Rate * p.For.Seconds()))
}

// Clock is the time source a replay paces against. Tests substitute a fake
// one; real runs use WallClock.
type Clock interface {
	Now() time.Time
	// Sleep waits d or until ctx ends, and reports whether d elapsed.
	Sleep(ctx context.Context, d time.Duration) bool
}

// WallClock is the real clock.
type WallClock struct{}

func (WallClock) Now() time.Time { return time.Now() }

func (WallClock) Sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ReplayConfig is how a corpus is replayed.
type ReplayConfig struct {
	Phases []Phase
	// Batch is the most records one Produce call carries. Default 100.
	Batch int
	// Start is the index into the corpus of the first record sent. A
	// replay that continues an earlier one passes the earlier Sent.
	Start int
	Clock Clock
	// RetryBackoff is the wait after a failed produce. Default 100ms.
	RetryBackoff time.Duration
}

// ReplayStats is what a replay did.
type ReplayStats struct {
	// Sent is records the broker acknowledged, which equals the profile's
	// total unless the context ended first.
	Sent    int
	Batches int
	// Retries counts failed produce calls; each was retried with the same
	// records, so a failure never loses a record.
	Retries int
	// Resent counts records produced again because their call failed. A
	// Kafka produce can write part of a call before it fails, so up to
	// Resent records may be duplicates in events.raw. The pipeline treats
	// each as its own event (its own offset, its own verdicts); the count
	// says how far the log's record count can exceed Sent.
	Resent int
	// MaxBehind is how late the latest batch went out against its
	// schedule. A replay that falls behind sends the next batch at once,
	// one batch at a time; it never skips records and never sends more
	// than one batch per call to catch up.
	MaxBehind time.Duration
	Elapsed   time.Duration
}

// Offered is the achieved rate over the whole replay.
func (s ReplayStats) Offered() float64 {
	if s.Elapsed <= 0 {
		return 0
	}
	return float64(s.Sent) / s.Elapsed.Seconds()
}

// Replay produces c's records, cycling through them, at each phase's rate.
//
// The schedule is fixed in advance: within a phase, record j is due at
// phase start + j/Rate, and a batch goes out when its first record is due.
// Which records are sent, in what order and in which batches, depends only
// on the corpus and the profile; only the timing varies between runs. The
// replay holds one batch at a time, so its memory is bounded whatever the
// broker does, and a broker that is slower than the profile shows up as
// MaxBehind rather than as an unbounded buffer.
func Replay(ctx context.Context, b broker.Broker, c *Corpus, cfg ReplayConfig) (ReplayStats, error) {
	if len(c.Records) == 0 {
		return ReplayStats{}, errors.New("replay: empty corpus")
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 100
	}
	if cfg.Clock == nil {
		cfg.Clock = WallClock{}
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 100 * time.Millisecond
	}
	var st ReplayStats
	start := cfg.Clock.Now()
	phaseStart := start
	next := cfg.Start
	buf := make([]broker.Record, 0, cfg.Batch)
	for _, ph := range cfg.Phases {
		n := ph.Count()
		for sent := 0; sent < n; {
			due := phaseStart.Add(time.Duration(float64(sent) / ph.Rate * float64(time.Second)))
			if wait := due.Sub(cfg.Clock.Now()); wait > 0 {
				if !cfg.Clock.Sleep(ctx, wait) {
					st.Elapsed = cfg.Clock.Now().Sub(start)
					return st, ctx.Err()
				}
			} else if behind := -wait; behind > st.MaxBehind {
				st.MaxBehind = behind
			}
			k := min(cfg.Batch, n-sent)
			buf = buf[:0]
			for i := range k {
				buf = append(buf, c.Records[(next+i)%len(c.Records)])
			}
			for {
				err := b.Produce(ctx, buf)
				if err == nil {
					break
				}
				if ctx.Err() != nil {
					st.Elapsed = cfg.Clock.Now().Sub(start)
					return st, ctx.Err()
				}
				if errors.Is(err, broker.ErrPermanent) {
					st.Elapsed = cfg.Clock.Now().Sub(start)
					return st, fmt.Errorf("replay: produce: %w", err)
				}
				st.Retries++
				st.Resent += len(buf)
				if !cfg.Clock.Sleep(ctx, cfg.RetryBackoff) {
					st.Elapsed = cfg.Clock.Now().Sub(start)
					return st, fmt.Errorf("replay: produce: %w", err)
				}
			}
			sent += k
			next += k
			st.Sent += k
			st.Batches++
		}
		phaseStart = phaseStart.Add(ph.For)
		if wait := phaseStart.Sub(cfg.Clock.Now()); wait > 0 {
			if !cfg.Clock.Sleep(ctx, wait) {
				st.Elapsed = cfg.Clock.Now().Sub(start)
				return st, ctx.Err()
			}
		}
	}
	st.Elapsed = cfg.Clock.Now().Sub(start)
	return st, nil
}
