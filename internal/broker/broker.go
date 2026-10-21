// Package broker is the narrow slice of a Kafka-protocol log the pipeline
// needs: read records with their partition and offset, write records, and
// commit consumer offsets by hand.
//
// It exists so that the pipeline's delivery logic can be tested without a
// broker. Memory is the implementation the unit tests use; the kafka
// subpackage is the franz-go implementation signalmand runs against.
// Anything the pipeline relies on is stated here as a contract both
// implementations keep, because a property that only the in-memory broker
// has is a property the tests prove and production does not have.
package broker

import (
	"context"
	"time"
)

// AnyPartition on a produced record means "partition by key", which is how
// every keyed topic is written. Any other value pins the record to that
// partition, which is how verdicts.v1 follows the event's own partition.
const AnyPartition int32 = -1

// Header is one record header.
type Header struct {
	Key   string
	Value []byte
}

// Record is one log entry. Partition and Offset are filled in on consume.
// On produce, Partition is AnyPartition or a pinned partition and Offset is
// ignored.
type Record struct {
	Topic     string
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
	Headers   []Header
	// Timestamp is the broker or producer timestamp. It is never consulted
	// by an engine; it exists for ingest-time metadata only.
	Timestamp time.Time
}

// Header returns the value of the first header named key, or nil.
func (r Record) Header(key string) []byte {
	for _, h := range r.Headers {
		if h.Key == key {
			return h.Value
		}
	}
	return nil
}

// TopicPartition names one partition of one topic.
type TopicPartition struct {
	Topic     string
	Partition int32
}

// Fetch is one poll's worth of records. Within a partition, records are in
// offset order. HighWatermarks is the log end offset of every partition the
// fetch touched, as of the fetch, for lag accounting.
type Fetch struct {
	Records        []Record
	HighWatermarks map[TopicPartition]int64
}

// Consumer reads records. A group consumer resumes from the group's
// committed offsets; a positioned reader starts where it was told.
type Consumer interface {
	// Poll blocks until at least one record is available or ctx ends. It
	// returns ctx.Err() when ctx ends with nothing fetched.
	Poll(ctx context.Context) (Fetch, error)
	// Commit records, per partition, the next offset the group should read.
	// Nothing is committed implicitly: an offset the caller never commits
	// is redelivered after a restart. Positioned readers return an error.
	Commit(ctx context.Context, next map[TopicPartition]int64) error
	Close()
}

// Broker is the whole surface.
type Broker interface {
	// Produce writes recs and returns once every one is durable (acked by
	// the broker with the configured acks). On error some records may have
	// been written; callers that retry produce duplicates, never gaps.
	// Within one partition, records are written in slice order.
	Produce(ctx context.Context, recs []Record) error
	// Consume joins group on topics and resumes from the group's committed
	// offsets, or from the start of the log when the group has none.
	Consume(group string, topics []string) (Consumer, error)
	// ReadFrom reads the given partitions from the given offsets with no
	// group and no commits.
	ReadFrom(start map[TopicPartition]int64) (Consumer, error)
	// EndOffsets returns, per partition, the offset the next produced
	// record will get.
	EndOffsets(ctx context.Context, topic string) (map[int32]int64, error)
	// CommittedOffsets returns the group's committed next offset per
	// partition. A partition with no commit is absent.
	CommittedOffsets(ctx context.Context, group, topic string) (map[int32]int64, error)
	// CommitOffsets records next as group's committed offsets without
	// joining the group. It is for a reader that positions itself with
	// ReadFrom and checkpoints by hand, like the differ; the group must have
	// no active members.
	CommitOffsets(ctx context.Context, group string, next map[TopicPartition]int64) error
	Close()
}
