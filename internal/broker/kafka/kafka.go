// Package kafka implements broker.Broker over the Kafka wire protocol with
// franz-go. It is what signalmand runs against Redpanda.
//
// Its tests need a live broker and carry the integration build tag; run
// them with `make integration` after `docker compose -f
// deploy/docker-compose.yml up -d --wait`.
package kafka

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
)

// Config is how to reach the cluster.
type Config struct {
	Brokers  []string
	ClientID string
	// MaxPollRecords caps one Poll. Zero means 500.
	MaxPollRecords int
}

// Broker is the franz-go implementation of broker.Broker. One producer
// client is shared by every Produce call; each consumer gets its own client,
// because a franz-go client is bound to one group or one assignment.
type Broker struct {
	cfg   Config
	prod  *kgo.Client
	admin *kadm.Client
}

var _ broker.Broker = (*Broker)(nil)

// Dial connects and pings the cluster.
func Dial(ctx context.Context, cfg Config) (*Broker, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("kafka: no brokers")
	}
	if cfg.MaxPollRecords == 0 {
		cfg.MaxPollRecords = 500
	}
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ClientID(cfg.ClientID),
		// Durable means acked by every in-sync replica. The offset commit
		// that follows a produce is only safe if this holds.
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordPartitioner(partitioner{keyed: kgo.StickyKeyPartitioner(nil)}),
		kgo.ProducerLinger(5*time.Millisecond),
		// The same limit as max.message.bytes on the topics, so a record
		// too large for the broker fails here, fast, as MessageTooLarge.
		kgo.ProducerBatchMaxBytes(broker.MaxMessageBytes),
	)
	if err != nil {
		return nil, err
	}
	if err := cl.Ping(ctx); err != nil {
		cl.Close()
		return nil, fmt.Errorf("kafka: ping %v: %w", cfg.Brokers, err)
	}
	return &Broker{cfg: cfg, prod: cl, admin: kadm.NewClient(cl)}, nil
}

// partitioner pins records that name a partition and hashes the key of the
// rest with Kafka's own murmur2, so a record keyed by host_id lands where any
// other Kafka client would put it.
type partitioner struct{ keyed kgo.Partitioner }

func (p partitioner) ForTopic(t string) kgo.TopicPartitioner {
	return topicPartitioner{keyed: p.keyed.ForTopic(t)}
}

type topicPartitioner struct{ keyed kgo.TopicPartitioner }

func (topicPartitioner) RequiresConsistency(*kgo.Record) bool { return true }

func (t topicPartitioner) Partition(r *kgo.Record, n int) int {
	if r.Partition >= 0 {
		// An out of range partition fails the record; it is not wrapped,
		// because a verdict on the wrong partition is a silent error.
		return int(r.Partition)
	}
	return t.keyed.Partition(r, n)
}

func toKgo(r broker.Record) *kgo.Record {
	kr := &kgo.Record{
		Topic:     r.Topic,
		Partition: r.Partition,
		Key:       r.Key,
		Value:     r.Value,
		Timestamp: r.Timestamp,
	}
	for _, h := range r.Headers {
		kr.Headers = append(kr.Headers, kgo.RecordHeader{Key: h.Key, Value: h.Value})
	}
	return kr
}

func fromKgo(kr *kgo.Record) broker.Record {
	r := broker.Record{
		Topic:     kr.Topic,
		Partition: kr.Partition,
		Offset:    kr.Offset,
		Key:       kr.Key,
		Value:     kr.Value,
		Timestamp: kr.Timestamp,
	}
	for _, h := range kr.Headers {
		r.Headers = append(r.Headers, broker.Header{Key: h.Key, Value: h.Value})
	}
	return r
}

// Produce writes recs synchronously. The idempotent producer, which franz-go
// enables by default, keeps per-partition order across retries.
func (b *Broker) Produce(ctx context.Context, recs []broker.Record) error {
	if len(recs) == 0 {
		return nil
	}
	krs := make([]*kgo.Record, len(recs))
	for i, r := range recs {
		krs[i] = toKgo(r)
	}
	return classify(b.prod.ProduceSync(ctx, krs...).FirstErr())
}

// permanent are the produce errors franz-go hands back that a retry cannot
// fix. franz-go has already retried what is retriable (an unknown topic a
// few times, for metadata to catch up), so these are final.
var permanent = []error{
	kerr.MessageTooLarge,
	kerr.RecordListTooLarge,
	kerr.InvalidRecord,
	kerr.UnknownTopicOrPartition,
	kerr.InvalidTopicException,
	kerr.TopicAuthorizationFailed,
	kerr.ClusterAuthorizationFailed,
}

// classify wraps a permanent produce error in broker.ErrPermanent. A pinned
// partition the topic does not have fails inside franz-go with a plain
// error and no code, so it is matched on its text.
func classify(err error) error {
	if err == nil {
		return nil
	}
	for _, p := range permanent {
		if errors.Is(err, p) {
			return fmt.Errorf("%w: %w", broker.ErrPermanent, err)
		}
	}
	if strings.Contains(err.Error(), "invalid record partitioning choice") {
		return fmt.Errorf("%w: %w", broker.ErrPermanent, err)
	}
	return err
}

// Consume joins group. Offsets are never committed automatically: the
// pipeline commits a batch only after its outputs are durable.
//
// On a rebalance, a batch in flight for a partition this member lost may
// finish afterwards. Its commit is dropped (see ownership), so it cannot
// move the new owner's group offset backwards; the new owner redelivers
// from its own position, which is the at-least-once duplicate the sink
// absorbs, not a gap.
func (b *Broker) Consume(group string, topics []string) (broker.Consumer, error) {
	own := &ownership{}
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(b.cfg.Brokers...),
		kgo.ClientID(b.cfg.ClientID),
		kgo.ConsumerGroup(group),
		kgo.ConsumeTopics(topics...),
		kgo.DisableAutoCommit(),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.FetchMaxWait(500*time.Millisecond),
		kgo.OnPartitionsAssigned(func(_ context.Context, _ *kgo.Client, m map[string][]int32) { own.assign(m) }),
		kgo.OnPartitionsRevoked(func(_ context.Context, _ *kgo.Client, m map[string][]int32) { own.revoke(m) }),
		kgo.OnPartitionsLost(func(context.Context, *kgo.Client, map[string][]int32) { own.lose() }),
	)
	if err != nil {
		return nil, err
	}
	return &consumer{cl: cl, max: b.cfg.MaxPollRecords, own: own}, nil
}

// ReadFrom consumes exact partitions from exact offsets with no group.
func (b *Broker) ReadFrom(start map[broker.TopicPartition]int64) (broker.Consumer, error) {
	parts := map[string]map[int32]kgo.Offset{}
	for tp, off := range start {
		if parts[tp.Topic] == nil {
			parts[tp.Topic] = map[int32]kgo.Offset{}
		}
		parts[tp.Topic][tp.Partition] = kgo.NewOffset().At(off)
	}
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(b.cfg.Brokers...),
		kgo.ClientID(b.cfg.ClientID),
		kgo.ConsumePartitions(parts),
		kgo.FetchMaxWait(500*time.Millisecond),
	)
	if err != nil {
		return nil, err
	}
	return &consumer{cl: cl, max: b.cfg.MaxPollRecords, fixed: slices.Collect(maps.Keys(start))}, nil
}

func (b *Broker) EndOffsets(ctx context.Context, topic string) (map[int32]int64, error) {
	l, err := b.admin.ListEndOffsets(ctx, topic)
	if err != nil {
		return nil, err
	}
	if err := l.Error(); err != nil {
		return nil, err
	}
	out := map[int32]int64{}
	l.Each(func(o kadm.ListedOffset) { out[o.Partition] = o.Offset })
	return out, nil
}

func (b *Broker) StartOffsets(ctx context.Context, topic string) (map[int32]int64, error) {
	l, err := b.admin.ListStartOffsets(ctx, topic)
	if err != nil {
		return nil, err
	}
	if err := l.Error(); err != nil {
		return nil, err
	}
	out := map[int32]int64{}
	l.Each(func(o kadm.ListedOffset) { out[o.Partition] = o.Offset })
	return out, nil
}

func (b *Broker) CommittedOffsets(ctx context.Context, group, topic string) (map[int32]int64, error) {
	rs, err := b.admin.FetchOffsetsForTopics(ctx, group, topic)
	if err != nil {
		return nil, err
	}
	out := map[int32]int64{}
	var ferr error
	rs.Each(func(o kadm.OffsetResponse) {
		if o.Err != nil && ferr == nil {
			ferr = o.Err
		}
		if o.Topic == topic && o.At >= 0 {
			out[o.Partition] = o.At
		}
	})
	return out, ferr
}

// Checkpoints is CommittedOffsets with the metadata of each commit.
func (b *Broker) Checkpoints(ctx context.Context, group, topic string) (map[int32]broker.Checkpoint, error) {
	rs, err := b.admin.FetchOffsetsForTopics(ctx, group, topic)
	if err != nil {
		return nil, err
	}
	out := map[int32]broker.Checkpoint{}
	var ferr error
	rs.Each(func(o kadm.OffsetResponse) {
		if o.Err != nil && ferr == nil {
			ferr = o.Err
		}
		if o.Topic == topic && o.At >= 0 {
			out[o.Partition] = broker.Checkpoint{Next: o.At, Meta: o.Metadata}
		}
	})
	return out, ferr
}

// CommitCheckpoints commits cps for group through the admin client,
// outside any group membership. Kafka accepts it only while the group is
// empty.
func (b *Broker) CommitCheckpoints(ctx context.Context, group string, cps map[broker.TopicPartition]broker.Checkpoint) error {
	os := kadm.Offsets{}
	for tp, cp := range cps {
		os.Add(kadm.Offset{Topic: tp.Topic, Partition: tp.Partition, At: cp.Next, LeaderEpoch: -1, Metadata: cp.Meta})
	}
	return b.admin.CommitAllOffsets(ctx, group, os)
}

// TopicSpec is one topic EnsureTopics creates.
type TopicSpec struct {
	Name        string
	Partitions  int32
	Replication int16
	Configs     map[string]string
}

// EnsureTopics creates any topic in specs that does not exist. An existing
// topic is left as it is, even if its partition count differs.
func (b *Broker) EnsureTopics(ctx context.Context, specs []TopicSpec) error {
	for _, s := range specs {
		cfg := map[string]*string{}
		for k, v := range s.Configs {
			cfg[k] = &v
		}
		// kadm returns the topic's own error as err too, so an existing
		// topic arrives here, not only in resp.Err.
		resp, err := b.admin.CreateTopic(ctx, s.Partitions, s.Replication, cfg, s.Name)
		if err == nil {
			err = resp.Err
		}
		if err != nil && !errors.Is(err, kerr.TopicAlreadyExists) {
			return fmt.Errorf("create %s: %w", s.Name, err)
		}
	}
	return nil
}

func (b *Broker) Close() { b.prod.Close() }

type consumer struct {
	cl  *kgo.Client
	max int
	own *ownership // nil for a positioned reader
	// fixed is a positioned reader's partitions.
	fixed []broker.TopicPartition
}

var errClosed = errors.New("kafka: consumer closed")

func (c *consumer) Poll(ctx context.Context) (broker.Fetch, error) {
	for {
		fs := c.cl.PollRecords(ctx, c.max)
		if fs.IsClientClosed() {
			return broker.Fetch{}, errClosed
		}
		f := broker.Fetch{HighWatermarks: map[broker.TopicPartition]int64{}}
		var ferr error
		fs.EachPartition(func(p kgo.FetchTopicPartition) {
			if p.Err != nil {
				if ferr == nil && !errors.Is(p.Err, context.Canceled) && !errors.Is(p.Err, context.DeadlineExceeded) {
					ferr = fmt.Errorf("fetch %s/%d: %w", p.Topic, p.Partition, p.Err)
				}
				return
			}
			tp := broker.TopicPartition{Topic: p.Topic, Partition: p.Partition}
			f.HighWatermarks[tp] = p.HighWatermark
			if c.own != nil && len(p.Records) > 0 {
				c.own.polled(tp, p.Records[0].Offset)
			}
			for _, r := range p.Records {
				f.Records = append(f.Records, fromKgo(r))
			}
		})
		if len(f.Records) > 0 {
			return f, nil
		}
		if err := ctx.Err(); err != nil {
			return broker.Fetch{}, err
		}
		if ferr != nil {
			return broker.Fetch{}, ferr
		}
	}
}

func (c *consumer) Commit(ctx context.Context, next map[broker.TopicPartition]int64) error {
	if c.own == nil {
		return errors.New("kafka: a positioned reader has no group")
	}
	c.own.mu.Lock()
	defer c.own.mu.Unlock()
	next = c.own.filterLocked(next)
	if len(next) == 0 {
		return nil
	}
	offs := map[string]map[int32]kgo.EpochOffset{}
	for tp, off := range next {
		if offs[tp.Topic] == nil {
			offs[tp.Topic] = map[int32]kgo.EpochOffset{}
		}
		offs[tp.Topic][tp.Partition] = kgo.EpochOffset{Epoch: -1, Offset: off}
	}
	var cerr error
	c.cl.CommitOffsetsSync(ctx, offs, func(_ *kgo.Client, _ *kmsg.OffsetCommitRequest, resp *kmsg.OffsetCommitResponse, err error) {
		if err != nil {
			cerr = err
			return
		}
		for _, t := range resp.Topics {
			for _, p := range t.Partitions {
				if e := kerr.ErrorForCode(p.ErrorCode); e != nil && cerr == nil {
					cerr = fmt.Errorf("commit %s/%d: %w", t.Topic, p.Partition, e)
				}
			}
		}
	})
	if cerr == nil {
		c.own.committedLocked(next)
	}
	return cerr
}

func (c *consumer) Close() { c.cl.Close() }

// Owned is the partitions assigned to this member and not since revoked
// or lost, or a positioned reader's partitions.
func (c *consumer) Owned() []broker.TopicPartition {
	if c.own == nil {
		return slices.Clone(c.fixed)
	}
	return c.own.owned()
}
