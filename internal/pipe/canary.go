package pipe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/obs"
)

// CanaryRuleID is the id of rules/signalman_canary.yml. signalmand resets
// signalman_canary_age_seconds when a match of this rule is durable on the
// alerts topic, and signalman-sink resets signalman_sink_canary_age_seconds
// when it is stored in ClickHouse.
const CanaryRuleID = "fbb72593-085d-4c15-8571-908e2b2d257c"

// CanaryHostID is the record key of every canary event. Staleness skips
// events with this host, or a steady canary would hide an upstream that
// stopped producing.
const CanaryHostID = "signalman-canary"

// CanaryRecord is the synthetic events.raw record for one partition. It is
// pinned to the partition, so a dead or wedged partition stops producing
// canary alerts even while the others keep going. The event time is the
// generator's clock; like any event time it is data the engine reads, not a
// clock the engine reads, so the verdict stays a pure function of the event.
func CanaryRecord(partition int32, at time.Time) broker.Record {
	body, err := json.Marshal(map[string]any{
		"channel":     "Microsoft-Windows-Sysmon/Operational",
		"event_id":    1,
		"Image":       `C:\signalman\signalman-canary.exe`,
		"CommandLine": "signalman-canary partition=" + strconv.Itoa(int(partition)),
		"User":        CanaryHostID,
		"event_time":  at.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		panic(err) // a map of strings and an int always marshals
	}
	return broker.Record{
		Topic:     TopicEventsRaw,
		Partition: partition,
		Key:       []byte(CanaryHostID),
		Value:     body,
		Headers:   []broker.Header{{Key: HeaderSource, Value: []byte("sysmon")}},
	}
}

// Canary writes one canary record to every events.raw partition per
// interval. It runs beside the pipeline, not in it: it only produces, so a
// wedged consumer cannot stop it, and the age it starts keeps climbing.
type Canary struct {
	b   broker.Broker
	m   *obs.Metrics
	now func() time.Time
	log *slog.Logger

	mu    sync.Mutex
	parts []int32 // the last partition list read
}

// NewCanary builds a generator. now is the clock for event times and for
// starting each partition's age; log may be nil.
func NewCanary(b broker.Broker, m *obs.Metrics, now func() time.Time, log *slog.Logger) *Canary {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Canary{b: b, m: m, now: now, log: log}
}

// Inject writes one canary to every partition events.raw has now. Every
// partition's age is started first, so a partition whose canary cannot
// even be written still climbs toward the page.
//
// One partition without a leader must not silence the others, or the page
// names every partition and hides which one is out. So the partition list
// falls back to the last one that was read (listing fails for the whole
// topic when one partition has no leader), and each partition's canary is
// produced on its own.
func (c *Canary) Inject(ctx context.Context) error {
	parts, listErr := c.partitions(ctx)
	if len(parts) == 0 {
		return fmt.Errorf("canary: list partitions: %w", listErr)
	}
	at := c.now()
	errs := make([]error, len(parts))
	var wg sync.WaitGroup
	for i, p := range parts {
		c.m.CanaryAge.Start(p)
		wg.Go(func() {
			if err := c.b.Produce(ctx, []broker.Record{CanaryRecord(p, at)}); err != nil {
				errs[i] = fmt.Errorf("canary: produce to partition %d: %w", p, err)
				return
			}
			c.m.CanaryInjected.WithLabelValues(strconv.Itoa(int(p))).Inc()
		})
	}
	wg.Wait()
	if listErr != nil {
		errs = append(errs, fmt.Errorf("canary: list partitions, using the last list: %w", listErr))
	}
	return errors.Join(errs...)
}

// partitions lists events.raw's partitions, or returns the last list that
// was read when listing fails, with the error.
func (c *Canary) partitions(ctx context.Context) ([]int32, error) {
	end, err := c.b.EndOffsets(ctx, TopicEventsRaw)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		return c.parts, err
	}
	parts := make([]int32, 0, len(end))
	for p := range end {
		parts = append(parts, p)
	}
	slices.Sort(parts)
	c.parts = parts
	return parts, nil
}

// Run injects now and then every interval until ctx ends. A failed
// injection is logged and not retried: the next tick is the retry, and the
// missing alert is what the age gauge is there to show.
func (c *Canary) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		ictx, cancel := context.WithTimeout(ctx, interval)
		if err := c.Inject(ictx); err != nil && ctx.Err() == nil {
			c.log.Warn("canary injection failed", "err", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
