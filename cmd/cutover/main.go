// Command cutover checks the v1 to v2 gate ladder and runs the rollback
// game day (spec phase 09, docs/cutover.md).
//
//	cutover check   -gate G2 -prom http://localhost:9090 -drill rollback.json
//	cutover gameday -prom http://localhost:9090 -rollout-file /etc/signalman/rollout -out gameday.json
//	cutover measure -prom http://localhost:9090 -from 100 -to 0 -written-at 2026-11-03T14:00:00Z -out drill.json
//
// check prints every criterion of one gate with its evidence and exits 0
// only if all of them hold. It changes nothing unless -record is given, and
// then only for a gate that passed: it dates the gate in docs/cutover.md and
// appends the evidence.
//
// gameday rewrites the -rollout file signalmand reads, so it is the one
// subcommand that changes production. measure only reads metrics, for a
// change an operator made by hand.
//
// Exit codes: 0 passed, 1 failed or not checkable, 2 usage.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/atontalapur/signalman/internal/cutover"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "check":
		return cmdCheck(ctx, args[1:], stdout, stderr)
	case "gameday":
		return cmdGameday(ctx, args[1:], stdout, stderr)
	case "measure":
		return cmdMeasure(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stderr)
		return exitUsage
	}
	fmt.Fprintf(stderr, "cutover: unknown command %q\n", args[0])
	usage(stderr)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage: cutover <command> [flags]
  check    evaluate one gate (G0 to G6) and print each criterion with its evidence
  gameday  roll back and forward through the -rollout file and measure both
  measure  measure a rollout change made by hand, from metrics`)
}

// attestFlag collects -attest key=evidence.
type attestFlag map[string]string

func (a attestFlag) String() string { return "" }
func (a attestFlag) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
		return fmt.Errorf("want key=evidence, got %q", s)
	}
	a[strings.TrimSpace(k)] = strings.TrimSpace(v)
	return nil
}

// timeFlag parses RFC 3339.
type timeFlag struct{ t time.Time }

func (f *timeFlag) String() string {
	if f.t.IsZero() {
		return ""
	}
	return f.t.Format(time.RFC3339)
}
func (f *timeFlag) Set(s string) error {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return fmt.Errorf("want an RFC 3339 time such as 2026-11-03T14:00:00Z: %w", err)
	}
	f.t = t
	return nil
}

func cmdCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cutover check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c cutover.Config
	attest := attestFlag{}
	var at, baseline timeFlag
	prom := fs.String("prom", "", "Prometheus base URL (every gate but G0)")
	fs.StringVar(&c.Gate, "gate", "", "gate to check: G0 to G6 (required)")
	fs.IntVar(&c.Percent, "percent", 0, "G3 step: 10 or 50")
	fs.Var(&at, "at", "end of the window checked, RFC 3339 (default now)")
	fs.DurationVar(&c.Window, "window", 0, "override the gate's hold (G1 168h, G2 to G4 48h, G6 336h)")
	fs.Var(attest, "attest", "key=evidence for a manual check; repeatable")
	drill := fs.String("drill", "", "game day result from cutover gameday or measure (G2 to G6)")
	fs.StringVar(&c.Rules, "rules", "", "G0: rule directory to replay")
	fs.StringVar(&c.Taxonomy, "taxonomy", "config/taxonomy", "G0: taxonomy directory")
	fs.StringVar(&c.Corpus, "corpus", "", "G0: event corpus directory (.ndjson, .jsonl)")
	fs.IntVar(&c.Partitions, "partitions", 8, "G0: partitions the replay spreads the corpus over")
	fs.StringVar(&c.FuzzStats, "fuzz-stats", "", "G0: worker stats directory from make fuzz-differential")
	fs.Int64Var(&c.FuzzMin, "fuzz-min", 100_000_000, "G0: comparisons the fuzzer must have made")
	goTest := fs.Bool("go-test", false, "G0: run the property and equivalence tests with go test from the module root")
	fs.Var(&baseline, "baseline-at", "G6: end of a window in which v1 served every rule, RFC 3339")
	doc := fs.String("doc", "docs/cutover.md", "the cutover document G6 reads and -record writes")
	tz := fs.String("tz", "UTC", "G5: time zone of the business hours")
	hours := fs.String("business-hours", "9-17", "G5: weekday hours the game day must start in, start-end")
	fs.Float64Var(&c.FullTraffic, "full-traffic", 0.8, "G5: share of the 7 day mean ingest rate that counts as full traffic")
	fs.Float64Var(&c.NoiseSigma, "noise-sigma", 3, "alert volume: standard deviations a rule's count may move")
	fs.Float64Var(&c.VerdictTolerance, "verdict-tolerance", 0.001, "largest |v2/v1 - 1| on verdict counts")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	record := fs.Bool("record", false, "if the gate passed, date it in -doc and append the evidence")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if c.Gate == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "cutover check: -gate is required and takes no arguments")
		return exitUsage
	}
	c.Gate = strings.ToUpper(c.Gate)
	c.Attest, c.BaselineAt, c.At = attest, baseline.t, at.t
	if c.At.IsZero() {
		c.At = time.Now()
	}
	if *prom != "" {
		c.Source = &cutover.Prom{Base: *prom}
	}
	loc, err := time.LoadLocation(*tz)
	if err != nil {
		fmt.Fprintln(stderr, "cutover check: -tz:", err)
		return exitUsage
	}
	c.Location = loc
	if c.BusinessStart, c.BusinessEnd, err = parseHours(*hours); err != nil {
		fmt.Fprintln(stderr, "cutover check: -business-hours:", err)
		return exitUsage
	}
	if *drill != "" {
		d, err := readDrill(*drill)
		if err != nil {
			fmt.Fprintln(stderr, "cutover check:", err)
			return exitUsage
		}
		c.Drill, c.DrillFile = &d, *drill
	}
	if *goTest {
		c.RunTests = runPropertyTests
	}
	var docText string
	if c.Gate == "G6" || *record {
		b, err := os.ReadFile(*doc)
		if err != nil {
			fmt.Fprintln(stderr, "cutover check:", err)
			return exitUsage
		}
		docText = string(b)
		c.Doc = docText
	}

	r, err := cutover.Evaluate(ctx, c)
	if err != nil {
		fmt.Fprintln(stderr, "cutover check:", err)
		return exitUsage
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		printReport(stdout, r)
	}
	if !r.Passed() {
		if *record {
			fmt.Fprintf(stderr, "cutover check: %s did not pass; nothing recorded\n", r.Name())
		}
		return exitFail
	}
	if *record {
		out, err := cutover.Record(docText, r, "cutover check "+strings.Join(args, " "))
		if err != nil {
			fmt.Fprintln(stderr, "cutover check:", err)
			return exitFail
		}
		if err := os.WriteFile(*doc, []byte(out), 0o644); err != nil {
			fmt.Fprintln(stderr, "cutover check:", err)
			return exitFail
		}
		fmt.Fprintf(stdout, "recorded %s in %s\n", r.Name(), *doc)
	}
	return exitOK
}

func printReport(w io.Writer, r cutover.Report) {
	verdict := "NOT PASSED"
	if r.Passed() {
		verdict = "PASSED"
	}
	window := ""
	if r.Window > 0 {
		window = fmt.Sprintf(" over the %s ending", r.Window)
	}
	fmt.Fprintf(w, "%s %s%s %s\n", r.Name(), verdict, window, r.At.Format(time.RFC3339))
	for _, c := range r.Checks {
		fmt.Fprintf(w, "  %-9s %-20s %s\n", c.Status, c.Key, c.Criterion)
		fmt.Fprintf(w, "  %-9s %-20s %s\n", "", "", c.Evidence)
	}
}

func parseHours(s string) (int, int, error) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf("want start-end, such as 9-17, got %q", s)
	}
	lo, err1 := strconv.Atoi(a)
	hi, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || lo < 0 || hi > 24 || lo >= hi {
		return 0, 0, fmt.Errorf("want start-end hours with 0 <= start < end <= 24, got %q", s)
	}
	return lo, hi, nil
}

// propertyPackages hold the property, equivalence and idempotence tests G0
// names: determinism, rule independence, prefilter and gate soundness, the
// fixture equivalence harness, and the ReplacingMergeTree model.
var propertyPackages = []string{"./internal/engine/...", "./internal/verdict/...", "./internal/pipe/chsink/..."}

func runPropertyTests(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "go", append([]string{"test", "-count=1"}, propertyPackages...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func readDrill(path string) (cutover.Drill, error) {
	var d cutover.Drill
	b, err := os.ReadFile(path)
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

func writeDrill(path string, d cutover.Drill) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func measureFlags(fs *flag.FlagSet, m *cutover.MeasureConfig) {
	fs.DurationVar(&m.Step, "step", time.Second, "range query resolution")
	fs.DurationVar(&m.Quiet, "quiet", 20*time.Second, "how long the old engine must be silent before the window ends")
}

func cmdGameday(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cutover gameday", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c cutover.DrillConfig
	prom := fs.String("prom", "", "Prometheus base URL (required)")
	fs.StringVar(&c.RolloutFile, "rollout-file", "", "the file signalmand -rollout reads (required)")
	fs.IntVar(&c.From, "from", 100, "rollout the drill starts and ends at")
	fs.IntVar(&c.To, "to", 0, "rollout to roll back to")
	fs.DurationVar(&c.Observe, "observe", 90*time.Second, "how long each change is watched before it is measured")
	fs.DurationVar(&c.Hold, "hold", 5*time.Minute, "how long the rollback is held before rolling forward")
	fs.BoolVar(&c.NoForward, "rollback-only", false, "stop after the rollback (the G2 to G4 rollback drill)")
	out := fs.String("out", "", "file the result is written to as JSON (required)")
	measureFlags(fs, &c.Measure)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *prom == "" || c.RolloutFile == "" || *out == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "cutover gameday: -prom, -rollout-file and -out are required")
		return exitUsage
	}
	c.Source = &cutover.Prom{Base: *prom}
	c.Log = func(format string, a ...any) {
		fmt.Fprintf(stdout, "%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, a...))
	}
	d, err := cutover.RunDrill(ctx, c)
	if werr := writeDrill(*out, d); werr != nil {
		fmt.Fprintln(stderr, "cutover gameday:", werr)
		return exitFail
	}
	if err != nil {
		fmt.Fprintln(stderr, "cutover gameday:", err)
		return exitFail
	}
	fmt.Fprintf(stdout, "wrote %s\n", *out)
	return exitOK
}

func cmdMeasure(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cutover measure", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var m cutover.MeasureConfig
	var written, forward timeFlag
	prom := fs.String("prom", "", "Prometheus base URL (required)")
	fs.IntVar(&m.From, "from", 100, "rollout before the change")
	fs.IntVar(&m.To, "to", 0, "rollout after the change")
	fs.Var(&written, "written-at", "when the rollout file was replaced, RFC 3339 (required)")
	fs.Var(&forward, "forward-at", "when the file was set back to -from, RFC 3339, for a game day done by hand")
	observe := fs.Duration("observe", 90*time.Second, "how long after each write to look")
	out := fs.String("out", "", "file the result is written to as JSON (required)")
	measureFlags(fs, &m)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *prom == "" || written.t.IsZero() || *out == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "cutover measure: -prom, -written-at and -out are required")
		return exitUsage
	}
	if !forward.t.IsZero() && m.To > m.From {
		fmt.Fprintln(stderr, "cutover measure: -forward-at follows a rollback; -to must be below -from")
		return exitUsage
	}
	src := &cutover.Prom{Base: *prom}
	d := cutover.Drill{StartedAt: written.t.UTC()}
	measure := func(from, to int, w time.Time) (*cutover.Step, error) {
		mc := m
		mc.From, mc.To, mc.WrittenAt, mc.Until = from, to, w.UTC(), w.Add(*observe).UTC()
		s, err := cutover.Measure(ctx, src, mc)
		return &s, err
	}
	s, err := measure(m.From, m.To, written.t)
	if err != nil {
		fmt.Fprintln(stderr, "cutover measure:", err)
		return exitFail
	}
	if m.To < m.From {
		d.Rollback = s
	} else {
		d.RollForward = s
	}
	fmt.Fprintln(stdout, s.String())
	ok := s.Measured()
	if !forward.t.IsZero() {
		f, err := measure(m.To, m.From, forward.t)
		if err != nil {
			fmt.Fprintln(stderr, "cutover measure:", err)
			return exitFail
		}
		d.RollForward = f
		fmt.Fprintln(stdout, f.String())
		ok = ok && f.Measured()
	}
	if err := writeDrill(*out, d); err != nil {
		fmt.Fprintln(stderr, "cutover measure:", err)
		return exitFail
	}
	if !ok {
		return exitFail
	}
	return exitOK
}
