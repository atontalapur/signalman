package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/pipe"
)

func memDial(mem *broker.Memory) func(context.Context) (broker.Broker, error) {
	return func(context.Context) (broker.Broker, error) { return mem, nil }
}

func produced(t *testing.T, mem *broker.Memory) int64 {
	t.Helper()
	end, err := mem.EndOffsets(context.Background(), pipe.TopicEventsRaw)
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, e := range end {
		n += e
	}
	return n
}

func TestReplaysTheProfileAtMultiplesOfTheBaseline(t *testing.T) {
	f, err := parseFlags([]string{
		"-rules", "../../rules", "-taxonomy", "../../config/taxonomy",
		"-baseline", "1000", "-profile", "2:100ms,0:50ms,0.5:200ms",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	mem := broker.NewMemory(map[string]int32{pipe.TopicEventsRaw: 4})
	var out bytes.Buffer
	if err := run(context.Background(), f, memDial(mem), &out); err != nil {
		t.Fatal(err)
	}
	if n := produced(t, mem); n != 300 {
		t.Fatalf("%d records produced, want 2000/s x 0.1s + 500/s x 0.2s = 300\n%s", n, out.String())
	}
	if !strings.Contains(out.String(), "sent 300 of 300") {
		t.Fatalf("report:\n%s", out.String())
	}
}

func TestMeasureBaselineFirst(t *testing.T) {
	f, err := parseFlags([]string{
		"-rules", "../../rules", "-taxonomy", "../../config/taxonomy",
		"-measure-baseline", "2000", "-multiple", "0.01", "-duration", "100ms",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	mem := broker.NewMemory(map[string]int32{pipe.TopicEventsRaw: 4})
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := run(ctx, f, memDial(mem), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "baseline: ") || !strings.Contains(out.String(), "in process, in-memory broker") {
		t.Fatalf("report:\n%s", out.String())
	}
	if produced(t, mem) == 0 {
		t.Fatal("nothing replayed after the baseline")
	}
}

func TestFlagErrors(t *testing.T) {
	for _, args := range [][]string{
		{"-baseline", "10"},
		{"-rules", "r", "-corpus", "c", "-baseline", "10"},
		{"-rules", "r"},
		{"-corpus", "c", "-measure-baseline", "10"},
	} {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
}

func TestParseProfile(t *testing.T) {
	ps, err := parseProfile("2:30m, 0:10m", 1500)
	if err != nil || len(ps) != 2 || ps[0].Rate != 3000 || ps[0].For != 30*time.Minute || ps[1].Rate != 0 {
		t.Fatalf("%+v %v", ps, err)
	}
	for _, bad := range []string{"", "2", "x:1m", "2:0s", "-1:1m"} {
		if _, err := parseProfile(bad, 1); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
