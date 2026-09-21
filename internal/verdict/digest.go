// Package verdict folds a verdict stream into a short hash, so two engines
// can be compared with a string equality instead of a forty-million-row
// diff.
package verdict

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/atontalapur/signalman/internal/event"
)

// FNV-1a 64, written out rather than imported so the fold order is visible
// at the call site. Two engines, and eventually two languages, have to
// produce the same number from the same stream.
const (
	fnvOffset uint64 = 14695981039346656037
	fnvPrime  uint64 = 1099511628211
)

func fnvBytes(h uint64, b []byte) uint64 {
	for _, c := range b {
		h ^= uint64(c)
		h *= fnvPrime
	}
	return h
}

func fnvU64(h uint64, v uint64) uint64 {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return fnvBytes(h, buf[:])
}

// Digest is a rolling hash over one partition's verdicts, in seq order.
//
// Within one event the fold is commutative: the per-verdict hashes are
// summed, so the digest does not depend on the order rules were evaluated
// in. Across events it is not: each event's accumulated value is folded
// into the rolling hash together with its seq. That pair of properties is
// the whole point. A rule set shuffle must not move the digest, and a
// reordered or lossy event stream must.
type Digest struct {
	rolling  uint64
	curSeq   uint64
	curAcc   uint64
	started  bool
	verdicts uint64
	events   uint64
}

func New() *Digest { return &Digest{rolling: fnvOffset} }

// Fold adds one verdict. Verdicts must arrive in non-decreasing seq order,
// which is the order a partition produces them; a seq going backwards is an
// error rather than a silently meaningless digest.
//
// Only Seq, RuleID, and Matched are folded. Engine, RuleSetV, TaxonomyV, and
// Partition identify the stream, not the verdict: folding them in would make
// two engines differ by construction and the comparison worthless. They are
// compared separately, as equal preconditions of the comparison.
func (d *Digest) Fold(v event.Verdict) error {
	switch {
	case !d.started:
		d.started = true
		d.curSeq = v.Seq
		d.events = 1
	case v.Seq < d.curSeq:
		return fmt.Errorf("verdict seq %d arrived after %d; a digest needs monotonic seq", v.Seq, d.curSeq)
	case v.Seq > d.curSeq:
		d.flush()
		d.curSeq = v.Seq
		d.events++
	}

	h := fnvBytes(fnvOffset, []byte(v.RuleID))
	// A separator so that rule ids cannot run into the matched byte and let
	// two different (id, matched) pairs hash alike.
	h = fnvBytes(h, []byte{0})
	if v.Matched {
		h = fnvBytes(h, []byte{1})
	} else {
		h = fnvBytes(h, []byte{0})
	}
	// Addition, not XOR: two verdicts that hash alike would cancel under
	// XOR and vanish from the digest.
	d.curAcc += h
	d.verdicts++
	return nil
}

func (d *Digest) flush() {
	d.rolling = fnvU64(d.rolling, d.curSeq)
	d.rolling = fnvU64(d.rolling, d.curAcc)
	d.curAcc = 0
}

// Sum returns the digest of everything folded so far, including the event in
// progress. It does not close the digest; folding may continue.
func (d *Digest) Sum() string {
	final := *d
	if final.started {
		final.flush()
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], final.rolling)
	return hex.EncodeToString(buf[:])
}

// Verdicts is how many verdicts were folded, and Events how many distinct
// seqs they covered. Both are reported beside the digest: two engines that
// agree on the hash but disagree on the count were not fed the same stream.
func (d *Digest) Verdicts() uint64 { return d.verdicts }
func (d *Digest) Events() uint64   { return d.events }

// Set folds a whole topic: one Digest per partition, because partitions are
// independent ordered streams. A partition's digest never depends on another
// partition's traffic, so a rebalance cannot look like a divergence.
type Set struct {
	byPartition map[int32]*Digest
}

func NewSet() *Set { return &Set{byPartition: map[int32]*Digest{}} }

func (s *Set) Fold(v event.Verdict) error {
	d, ok := s.byPartition[v.Partition]
	if !ok {
		d = New()
		s.byPartition[v.Partition] = d
	}
	if err := d.Fold(v); err != nil {
		return fmt.Errorf("partition %d: %w", v.Partition, err)
	}
	return nil
}

// Partitions returns the partitions seen, sorted.
func (s *Set) Partitions() []int32 {
	out := make([]int32, 0, len(s.byPartition))
	for p := range s.byPartition {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Sums returns one digest per partition, ordered by partition, so two sets
// compare element by element.
func (s *Set) Sums() []string {
	parts := s.Partitions()
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, s.byPartition[p].Sum())
	}
	return out
}

// Digest returns one partition's digest, for reporting a divergence down to
// the stream it happened in.
func (s *Set) Digest(partition int32) (*Digest, bool) {
	d, ok := s.byPartition[partition]
	return d, ok
}
