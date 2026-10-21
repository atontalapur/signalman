package kafka

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/twmb/franz-go/pkg/kerr"
)

func TestProduceErrorsThatCannotSucceedArePermanent(t *testing.T) {
	permanent := []error{
		fmt.Errorf("%w (uncompressed_bytes=2000000)", kerr.MessageTooLarge),
		kerr.RecordListTooLarge,
		kerr.InvalidRecord,
		kerr.UnknownTopicOrPartition,
		kerr.TopicAuthorizationFailed,
		errors.New("invalid record partitioning choice of 5 from 2 available"),
	}
	for _, err := range permanent {
		if got := classify(err); !errors.Is(got, broker.ErrPermanent) || !errors.Is(got, err) {
			t.Fatalf("classify(%v) = %v; want it permanent and still wrapping the cause", err, got)
		}
	}
	transient := []error{kerr.NotLeaderForPartition, kerr.RequestTimedOut, context.DeadlineExceeded, errors.New("broken pipe")}
	for _, err := range transient {
		if got := classify(err); errors.Is(got, broker.ErrPermanent) {
			t.Fatalf("classify(%v) is permanent; a transient error is retried", err)
		}
	}
	if classify(nil) != nil {
		t.Fatal("classify(nil) != nil")
	}
}
