package v1

import (
	"math/rand"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/verdict"
)

// stream builds a deterministic set of events covering both mapped
// logsources, some matching and some not.
func stream(n int) []*event.Event {
	out := make([]*event.Event, 0, n)
	for i := 0; i < n; i++ {
		ev := &event.Event{Seq: uint64(i + 1), Partition: int32(i % 3)}
		switch i % 4 {
		case 0:
			ev.Fields = map[string]event.Value{
				"channel":     event.String("Microsoft-Windows-Sysmon/Operational"),
				"event_id":    event.Int(1),
				"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
				"CommandLine": event.String(`rundll32.exe comsvcs.dll, MiniDump 624 C:\t.dmp full`),
				"ParentImage": event.String(`C:\Windows\explorer.exe`),
			}
		case 1:
			ev.Fields = map[string]event.Value{
				"channel":         event.String("Microsoft-Windows-Sysmon/Operational"),
				"event_id":        event.Int(3),
				"DestinationPort": event.Int(4444),
			}
		case 2:
			ev.Fields = map[string]event.Value{
				"channel":        event.String("Security"),
				"event_id":       event.Int(4688),
				"NewProcessName": event.String(`C:\Windows\System32\certutil.exe`),
			}
		default:
			ev.Fields = map[string]event.Value{
				"channel":  event.String("Some-Other-Channel"),
				"event_id": event.Int(99),
			}
		}
		out = append(out, ev)
	}
	return out
}

func digestOf(t *testing.T, rs *sigma.RuleSet, evs []*event.Event) []string {
	t.Helper()
	e := New(rs)
	set := verdict.NewSet()
	buf := make([]event.Verdict, 0, len(rs.Rules))
	for _, ev := range evs {
		buf = e.EvaluateInto(buf[:0], ev)
		for _, v := range buf {
			if err := set.Fold(v); err != nil {
				t.Fatalf("fold: %v", err)
			}
		}
	}
	return set.Sums()
}

// TestDigestSurvivesARuleSetShuffle is the Plan B gate property: the same
// events and the same rules, with the rules in ten different orders, must
// produce the same per-partition digests. If this fails, a digest
// comparison between v1 and v2 would report divergences that are really
// just a difference in load order.
func TestDigestSurvivesARuleSetShuffle(t *testing.T) {
	rs := load(t)
	evs := stream(60)
	want := digestOf(t, rs, evs)
	if len(want) != 3 {
		t.Fatalf("expected 3 partitions, got %d", len(want))
	}

	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 10; i++ {
		shuffled := &sigma.RuleSet{
			Rules:     append([]sigma.Rule(nil), rs.Rules...),
			Version:   rs.Version,
			TaxonomyV: rs.TaxonomyV,
		}
		rng.Shuffle(len(shuffled.Rules), func(a, b int) {
			shuffled.Rules[a], shuffled.Rules[b] = shuffled.Rules[b], shuffled.Rules[a]
		})
		got := digestOf(t, shuffled, evs)
		if len(got) != len(want) {
			t.Fatalf("shuffle %d gave %d partitions, want %d", i, len(got), len(want))
		}
		for p := range want {
			if got[p] != want[p] {
				t.Fatalf("shuffle %d partition %d digest = %s, want %s", i, p, got[p], want[p])
			}
		}
	}
}

// TestDigestMovesWhenOneRuleChanges is the other half: a digest that never
// moved would also be useless. Dropping a rule that matched has to change
// the stream it summarizes.
func TestDigestMovesWhenOneRuleChanges(t *testing.T) {
	rs := load(t)
	evs := stream(60)
	want := digestOf(t, rs, evs)

	fewer := &sigma.RuleSet{
		Rules:     rs.Rules[1:],
		Version:   rs.Version,
		TaxonomyV: rs.TaxonomyV,
	}
	got := digestOf(t, fewer, evs)
	same := true
	for p := range want {
		if got[p] != want[p] {
			same = false
		}
	}
	if same {
		t.Fatal("removing a rule must change the digest")
	}
}
