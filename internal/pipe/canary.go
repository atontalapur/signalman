package pipe

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/obs"
)

// CanaryRuleID is the id of rules/signalman_canary.yml. The sink resets
// signalman_canary_age_seconds when a match of this rule is durable.
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
func (c *Canary) Inject(ctx context.Context) error {
	end, err := c.b.EndOffsets(ctx, TopicEventsRaw)
	if err != nil {
		return fmt.Errorf("canary: list partitions: %w", err)
	}
	parts := make([]int32, 0, len(end))
	for p := range end {
		parts = append(parts, p)
	}
	slices.Sort(parts)
	at := c.now()
	recs := make([]broker.Record, len(parts))
	for i, p := range parts {
		c.m.CanaryAge.Start(p)
		recs[i] = CanaryRecord(p, at)
	}
	if err := c.b.Produce(ctx, recs); err != nil {
		return fmt.Errorf("canary: produce: %w", err)
	}
	for _, p := range parts {
		c.m.CanaryInjected.WithLabelValues(strconv.Itoa(int(p))).Inc()
	}
	return nil
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
