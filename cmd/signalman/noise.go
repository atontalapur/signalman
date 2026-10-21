package main

import (
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

// noiseSamples is how many matching events noise prints, the first ones in
// corpus order.
const noiseSamples = 10

// maxSample bounds a printed sample line. The full event is in the corpus
// at the printed file and line.
const maxSample = 300

// cmdNoise runs one rule over a corpus with the v1 evaluator and reports
// how often it would have fired, per 100,000 events, with sample matches.
// When the rule declares budget: and the rate exceeds it, noise exits 1.
func cmdNoise(args []string, stdout, stderr io.Writer) int {
	fs, taxDir := newFlags("noise", stderr)
	corpus := fs.String("corpus", "", "directory of .ndjson or .jsonl events (required)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(pos) != 1 || *corpus == "" {
		fmt.Fprintln(stderr, "usage: signalman noise [--taxonomy dir] <rule.yml> --corpus <dir>")
		return exitUsage
	}
	tax, ok := loadTaxonomy(*taxDir, stderr)
	if !ok {
		return exitUsage
	}
	events, err := readCorpus(*corpus)
	if err != nil {
		fmt.Fprintf(stderr, "signalman: %v\n", err)
		return exitUsage
	}
	r, lerr := sigma.LoadRule(pos[0], tax)
	if lerr != nil {
		fmt.Fprintln(stdout, lerr.Error())
		return exitFail
	}

	e := v1.New(&sigma.RuleSet{Rules: []sigma.Rule{*r}, TaxonomyV: tax.Version})
	buf := make([]event.Verdict, 0, 1)
	var samples []corpusEvent
	matches := 0
	for _, ce := range events {
		buf = e.EvaluateInto(buf[:0], ce.Event)
		if !buf[0].Matched {
			continue
		}
		matches++
		if len(samples) < noiseSamples {
			samples = append(samples, ce)
		}
	}
	rate := float64(matches) * 100000 / float64(len(events))

	fmt.Fprintf(stdout, "rule      %s (%s)\n", r.Path, r.ID)
	fmt.Fprintf(stdout, "corpus    %s\n", *corpus)
	fmt.Fprintf(stdout, "events    %d\n", len(events))
	fmt.Fprintf(stdout, "matches   %d\n", matches)
	fmt.Fprintf(stdout, "per 100k  %.1f\n", rate)
	exceeded := false
	switch {
	case r.Budget == nil:
		fmt.Fprintln(stdout, "budget    none declared")
	case rate > *r.Budget:
		exceeded = true
		fmt.Fprintf(stdout, "budget    %s per 100k, EXCEEDED\n", formatBudget(*r.Budget))
	default:
		fmt.Fprintf(stdout, "budget    %s per 100k, within\n", formatBudget(*r.Budget))
	}
	if len(samples) > 0 {
		fmt.Fprintf(stdout, "samples   first %d of %d, in corpus order\n", len(samples), matches)
		for _, s := range samples {
			fmt.Fprintf(stdout, "  %s:%d  %s\n", s.File, s.Line, sampleText(s.Event.Raw))
		}
	}
	if exceeded {
		return exitFail
	}
	return exitOK
}

func formatBudget(b float64) string { return strconv.FormatFloat(b, 'f', -1, 64) }

func sampleText(raw []byte) string {
	if len(raw) <= maxSample {
		return string(raw)
	}
	cut := maxSample
	for cut > 0 && !utf8.RuneStart(raw[cut]) {
		cut--
	}
	return string(raw[:cut]) + " ..."
}
