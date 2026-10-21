package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/atontalapur/signalman/internal/sigma"
)

// cmdLint loads the named rules as one rule set and prints every rejection.
// Loading covers parsing, modifier chains, the condition, the taxonomy
// resolve, and duplicate ids across every file named.
func cmdLint(args []string, stdout, stderr io.Writer) int {
	fs, taxDir := newFlags("lint", stderr)
	asJSON := fs.Bool("json", false, "print one JSON object per load error")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	tax, ok := loadTaxonomy(*taxDir, stderr)
	if !ok {
		return exitUsage
	}
	paths, ok := ruleFiles(pos, stderr)
	if !ok {
		return exitUsage
	}

	rs, errs := sigma.LoadRuleFiles(paths, tax)
	enc := json.NewEncoder(stdout)
	for _, e := range errs {
		if *asJSON {
			if err := enc.Encode(lintRecord{e.Path, e.Line, e.RuleID, e.Code, e.Reason}); err != nil {
				fmt.Fprintf(stderr, "signalman: %v\n", err)
				return exitUsage
			}
			continue
		}
		fmt.Fprintln(stdout, e.Error())
	}
	if !*asJSON {
		fmt.Fprintf(stdout, "%d rules, %d loaded, %d rejected\n", len(paths), len(rs.Rules), len(errs))
	}
	if len(errs) > 0 {
		return exitFail
	}
	return exitOK
}

// lintRecord is the JSON form of a sigma.LoadError, without the wrapped
// cause, which has no stable encoding.
type lintRecord struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	RuleID string `json:"rule_id"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
}
