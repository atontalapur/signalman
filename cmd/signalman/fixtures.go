package main

import (
	"fmt"
	"io"

	"github.com/atontalapur/signalman/internal/fixture"
	"github.com/atontalapur/signalman/internal/sigma"
)

// cmdTest runs every rule's fixtures. A rule fails when it does not load,
// has no fixture file, has a case that disagrees, or lacks either a match
// case or a no-match case.
func cmdTest(args []string, stdout, stderr io.Writer) int {
	fs, taxDir := newFlags("test", stderr)
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

	passed := 0
	for _, p := range paths {
		cases, problems := testRule(p, tax)
		if len(problems) == 0 {
			passed++
			fmt.Fprintf(stdout, "ok    %s  %d cases\n", p, cases)
			continue
		}
		fmt.Fprintf(stdout, "FAIL  %s\n", p)
		for _, msg := range problems {
			fmt.Fprintf(stdout, "      %s\n", msg)
		}
	}
	fmt.Fprintf(stdout, "%d rules, %d passed, %d failed\n", len(paths), passed, len(paths)-passed)
	if passed != len(paths) {
		return exitFail
	}
	return exitOK
}

// testRule returns the case count and, on a failure, one line per problem.
func testRule(path string, tax *sigma.Taxonomy) (int, []string) {
	r, lerr := sigma.LoadRule(path, tax)
	if lerr != nil {
		return 0, []string{lerr.Error()}
	}
	f, err := fixture.Load(sigma.FixturePath(path))
	if err != nil {
		return 0, []string{fmt.Sprintf("fixture: %v", err)}
	}
	res := fixture.Run(r, f)
	var out []string
	for _, fl := range res.Failed {
		out = append(out, fmt.Sprintf("case %q (line %d): want %s, got %s",
			fl.Case.Name, fl.Case.Line, outcome(fl.Case.Expect), outcome(fl.Got)))
	}
	if res.Problem != "" {
		out = append(out, res.Problem)
	}
	return res.Cases, out
}

func outcome(matched bool) string {
	if matched {
		return "match"
	}
	return "no-match"
}
