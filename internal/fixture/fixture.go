// Package fixture reads a rule's test cases from its sibling .test.yml and
// runs them through the reference evaluator.
//
// The file is author-facing: no Go, no build step. Each case names an
// expected outcome and an event written as a YAML map, with field names as
// they appear on a normalized event (after the taxonomy, so a Security 4688
// event carries NewProcessName, not Image).
package fixture

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
	"gopkg.in/yaml.v3"
)

// Case is one fixture case. Expect is true for "match".
type Case struct {
	Name   string
	Expect bool
	Event  *event.Event
	// Line is the 1-based line the case starts on, for error messages.
	Line int
}

// File is a loaded fixture file.
type File struct {
	Path string
	// Rule is the rule file name the fixture says it belongs to.
	Rule  string
	Cases []Case
}

type rawFile struct {
	Rule  string    `yaml:"rule"`
	Cases []rawCase `yaml:"cases"`
}

type rawCase struct {
	Name   string         `yaml:"name"`
	Expect string         `yaml:"expect"`
	Event  map[string]any `yaml:"event"`
}

// Load reads and validates a fixture file. Unknown keys are errors: a
// misspelled expect key would otherwise read as an empty expectation.
func Load(path string) (*File, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(src))
	dec.KnownFields(true)
	var raw rawFile
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	lines := caseLines(src)

	f := &File{Path: path, Rule: raw.Rule, Cases: make([]Case, 0, len(raw.Cases))}
	for i, rc := range raw.Cases {
		line := 0
		if i < len(lines) {
			line = lines[i]
		}
		name := rc.Name
		if name == "" {
			name = fmt.Sprintf("case %d", i+1)
		}
		var expect bool
		switch rc.Expect {
		case "match":
			expect = true
		case "no-match":
		default:
			return nil, fmt.Errorf("%s:%d: case %q: expect must be \"match\" or \"no-match\", got %q", path, line, name, rc.Expect)
		}
		if rc.Event == nil {
			return nil, fmt.Errorf("%s:%d: case %q has no event", path, line, name)
		}
		ev, err := event.FromMap(rc.Event)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: case %q: %w", path, line, name, err)
		}
		// Seq is the case index, so every case in a file is a distinct
		// event to anything that keys on it.
		ev.Seq = uint64(i)
		f.Cases = append(f.Cases, Case{Name: name, Expect: expect, Event: ev, Line: line})
	}
	return f, nil
}

// caseLines finds the line each item of the cases list starts on.
func caseLines(src []byte) []int {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "cases" {
			var out []int
			for _, item := range root.Content[i+1].Content {
				out = append(out, item.Line)
			}
			return out
		}
	}
	return nil
}

// Failure is a case whose verdict disagreed with its expectation.
type Failure struct {
	Case *Case
	Got  bool
}

// Result is the outcome of running one fixture file.
type Result struct {
	Cases     int
	Matches   int
	NoMatches int
	Failed    []Failure
	// Problem is set when the file is wrong as a whole: it names another
	// rule, or it lacks a match case or a no-match case.
	Problem string
}

// OK reports whether the rule passed.
func (r Result) OK() bool { return len(r.Failed) == 0 && r.Problem == "" }

// Run evaluates every case with the v1 evaluator over a rule set holding
// only this rule. v1 is the oracle, so a fixture pins behavior against the
// engine every later one is compared with, logsource check included.
func Run(r *sigma.Rule, f *File) Result {
	res := Result{Cases: len(f.Cases)}
	if f.Rule != "" && f.Rule != filepath.Base(r.Path) {
		res.Problem = fmt.Sprintf("fixture names rule %s, but sits beside %s", f.Rule, filepath.Base(r.Path))
	}
	e := v1.New(&sigma.RuleSet{Rules: []sigma.Rule{*r}})
	buf := make([]event.Verdict, 0, 1)
	for i := range f.Cases {
		c := &f.Cases[i]
		if c.Expect {
			res.Matches++
		} else {
			res.NoMatches++
		}
		buf = e.EvaluateInto(buf[:0], c.Event)
		if got := buf[0].Matched; got != c.Expect {
			res.Failed = append(res.Failed, Failure{Case: c, Got: got})
		}
	}
	if res.Problem == "" && (res.Matches < 1 || res.NoMatches < 1) {
		res.Problem = fmt.Sprintf("needs at least one match and one no-match case, has %d match and %d no-match",
			res.Matches, res.NoMatches)
	}
	return res
}
