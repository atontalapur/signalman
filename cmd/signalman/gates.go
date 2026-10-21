package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	v2 "github.com/atontalapur/signalman/internal/engine/v2"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/fixture"
	"github.com/atontalapur/signalman/internal/sigma"
)

// reportMarker opens every gates report. The rules workflow finds its own
// earlier comment by it and edits that comment instead of adding another.
const reportMarker = "<!-- signalman-gates -->"

// maxReport keeps the report under GitHub's 65,536 character comment limit
// with room to spare. Past it the details are dropped and the table kept.
const maxReport = 60000

type gateStatus int

const (
	gatePass gateStatus = iota
	gateWarn
	gateSkip
	gateFail
)

// The five gates, in report order.
const (
	gParse = iota
	gFixtures
	gNoise
	gLatency
	gPrefilter
	numGates
)

var gateNames = [numGates]string{"Parse", "Fixtures", "Noise", "Latency", "Prefilter"}

// gateResult is one gate's outcome for one rule. Note is the short form for
// the table cell; Detail and Samples go in the rule's details section.
type gateResult struct {
	Status  gateStatus
	Note    string
	Detail  []string
	Samples []string
	// Help is prose shown after the detail block, outside any code.
	Help string
}

type ruleGates struct {
	Path  string
	Gates [numGates]gateResult
}

func (rg *ruleGates) worst() gateStatus {
	w := gatePass
	for _, g := range rg.Gates {
		if g.Status == gateFail {
			return gateFail
		}
		if g.Status == gateWarn {
			w = gateWarn
		}
	}
	return w
}

type reportHeader struct {
	TaxonomyV string
	Corpus    string
	Events    int
	Threshold time.Duration
	Samples   int
}

// cmdGates runs the five rule pull request gates over a set of rule files
// and writes a markdown report for the PR comment: parse, fixtures, noise
// budget, latency budget, and prefilter. It exits 1 when any gate failed. A
// prefilter warning, or a noise gate skipped for want of a corpus, does not
// fail it.
func cmdGates(args []string, stdout, stderr io.Writer) int {
	fs, taxDir := newFlags("gates", stderr)
	corpus := fs.String("corpus", "", "directory of .ndjson or .jsonl events for the noise gate (skipped without one)")
	set := fs.String("set", "", "rule directory to check ids against, so a new rule cannot reuse an existing id")
	changed := fs.String("changed", "", "file of changed paths, NUL or newline separated, as git diff writes them")
	samples := fs.Int("samples", 10000, "timed evaluations per rule for the latency gate")
	threshold := fs.Duration("threshold", 50*time.Microsecond, "p99 latency budget per rule")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	if *samples < 1 {
		fmt.Fprintln(stderr, "signalman: --samples must be at least 1")
		return exitUsage
	}
	var paths, missing []string
	if *changed != "" {
		if len(pos) > 0 {
			fmt.Fprintln(stderr, "signalman: give rule files or --changed, not both")
			return exitUsage
		}
		paths, missing, err = changedRules(*changed)
		if err != nil {
			fmt.Fprintf(stderr, "signalman: %v\n", err)
			return exitUsage
		}
	} else {
		var ok bool
		if paths, ok = ruleFiles(pos, stderr); !ok {
			return exitUsage
		}
	}
	tax, ok := loadTaxonomy(*taxDir, stderr)
	if !ok {
		return exitUsage
	}

	var corpusEvents []corpusEvent
	if *corpus != "" {
		if corpusEvents, err = readCorpus(*corpus); err != nil {
			fmt.Fprintf(stderr, "signalman: %v\n", err)
			return exitUsage
		}
	}
	ids, err := setIDs(*set, tax)
	if err != nil {
		fmt.Fprintf(stderr, "signalman: --set: %v\n", err)
		return exitUsage
	}

	// The latency gate times against the corpus when there is one, and
	// otherwise against every fixture case of the rules checked, as bench
	// does. A fixture that does not load is the fixtures gate's to report.
	var timing []*event.Event
	if len(corpusEvents) > 0 {
		for _, ce := range corpusEvents {
			timing = append(timing, ce.Event)
		}
	} else {
		timing = fixtureEvents(paths)
	}

	g := gateRunner{
		tax: tax, ids: ids, corpus: corpusEvents, timing: timing,
		samples: *samples, threshold: *threshold,
	}
	report := make([]ruleGates, 0, len(paths))
	failed := false
	for _, p := range paths {
		rg := g.run(p)
		if rg.worst() == gateFail {
			failed = true
		}
		report = append(report, rg)
	}

	hdr := reportHeader{TaxonomyV: tax.Version, Corpus: *corpus, Events: len(corpusEvents),
		Threshold: *threshold, Samples: *samples}
	if err := renderReport(stdout, hdr, report, missing); err != nil {
		fmt.Fprintf(stderr, "signalman: %v\n", err)
		return exitUsage
	}
	if failed {
		return exitFail
	}
	return exitOK
}

type gateRunner struct {
	tax       *sigma.Taxonomy
	ids       map[string][]string // rule id to the --set files that claim it
	corpus    []corpusEvent
	timing    []*event.Event
	samples   int
	threshold time.Duration
}

func (g *gateRunner) run(path string) ruleGates {
	rg := ruleGates{Path: path}
	r, lerr := sigma.LoadRule(path, g.tax)
	if lerr != nil {
		rg.Gates[gParse] = gateResult{Status: gateFail, Note: lerr.Code, Detail: []string{lerr.Error()}}
		for i := gFixtures; i < numGates; i++ {
			rg.Gates[i] = gateResult{Status: gateSkip}
		}
		return rg
	}
	rg.Gates[gParse] = g.parse(path, r)
	rg.Gates[gFixtures] = g.fixtures(path)
	rg.Gates[gNoise] = g.noise(r)
	rg.Gates[gLatency] = g.latency(r)
	rg.Gates[gPrefilter] = g.prefilter(r)
	return rg
}

// parse passes a rule that loaded, unless another file in --set claims its
// id. Loading the changed files alone would miss that, and a duplicate id
// is rejected when the full rule set loads.
func (g *gateRunner) parse(path string, r *sigma.Rule) gateResult {
	self := absPath(path)
	var others []string
	for _, p := range g.ids[r.ID] {
		if absPath(p) != self {
			others = append(others, p)
		}
	}
	if len(others) == 0 {
		return gateResult{Status: gatePass}
	}
	return gateResult{
		Status: gateFail,
		Note:   sigma.CodeDuplicateID,
		Detail: []string{fmt.Sprintf("%s:1 [%s] rule %s: id already claimed by %s",
			path, sigma.CodeDuplicateID, r.ID, strings.Join(others, ", "))},
	}
}

func (g *gateRunner) fixtures(path string) gateResult {
	cases, problems := testRule(path, g.tax)
	if len(problems) > 0 {
		return gateResult{Status: gateFail, Note: "fixtures disagree", Detail: problems}
	}
	return gateResult{Status: gatePass, Note: fmt.Sprintf("%d cases", cases)}
}

func (g *gateRunner) noise(r *sigma.Rule) gateResult {
	if len(g.corpus) == 0 {
		// The report header says why, once for every rule.
		return gateResult{Status: gateSkip}
	}
	matches, samples := noiseOf(r, g.tax.Version, g.corpus)
	rate := per100k(matches, len(g.corpus))
	res := gateResult{Status: gatePass}
	budget := "no budget"
	if r.Budget != nil {
		budget = "budget " + formatBudget(*r.Budget)
		if rate > *r.Budget {
			res.Status = gateFail
		}
	}
	res.Note = fmt.Sprintf("%.1f per 100k, %s", rate, budget)
	res.Detail = []string{fmt.Sprintf("%d matches in %d events, %.1f per 100k, %s", matches, len(g.corpus), rate, budget)}
	for _, s := range samples {
		res.Samples = append(res.Samples, fmt.Sprintf("%s:%d  %s", s.File, s.Line, sampleText(s.Event.Raw)))
	}
	if r.Budget == nil && matches > 0 {
		res.Help = "No `budget:` declared, so this figure cannot fail the gate. Declare one in matches per 100k events."
	}
	return res
}

func (g *gateRunner) latency(r *sigma.Rule) gateResult {
	if len(g.timing) == 0 {
		return gateResult{Status: gateSkip, Help: "Skipped: no corpus and no fixture events to time against."}
	}
	st := timeRule(r, g.timing, g.samples)
	res := gateResult{
		Status: gatePass,
		Note:   "p99 " + st.p99.String(),
		Detail: []string{fmt.Sprintf("p50 %s, p99 %s, max %s over %d samples of %d events, against the %s p99 budget",
			st.p50, st.p99, st.max, g.samples, len(g.timing), g.threshold)},
	}
	if st.p99 > g.threshold {
		res.Status = gateFail
		res.Detail[0] = strings.Replace(res.Detail[0], "against the", "over the", 1)
		res.Help = "Over budget usually means an unanchored regex that should be a `contains`, `startswith`, or `endswith`."
	}
	return res
}

// prefilter warns when v2's literal prefilter can derive nothing to key the
// rule on. Such a rule is in Program.Always and its tree is walked for every
// event. That is correct, so it is a warning, but it is a cost the author
// can usually remove.
func (g *gateRunner) prefilter(r *sigma.Rule) gateResult {
	p, err := v2.Compile(&sigma.RuleSet{Rules: []sigma.Rule{*r}, TaxonomyV: g.tax.Version})
	if err != nil {
		return gateResult{Status: gateFail, Note: "v2 compile failed", Detail: []string{err.Error()}}
	}
	if p.AlwaysSize() == 0 {
		return gateResult{Status: gatePass}
	}
	return gateResult{
		Status: gateWarn,
		Note:   "in Always",
		Help: "The prefilter found no literal this rule requires, so v2 evaluates it on every event. " +
			"Add a plain string test (equals, `contains`, `startswith`, or `endswith`) that every match must pass, " +
			"ANDed with the rest of the condition and not under a `not`. See docs/authoring.md.",
	}
}

// changedRules reads a list of changed paths and returns the rule files to
// gate, sorted and deduplicated. A changed fixture stands for its rule. A
// rule that is no longer on disk is returned in missing; files that are
// neither rules nor fixtures are dropped.
func changedRules(listPath string) (rules, missing []string, err error) {
	b, err := os.ReadFile(listPath)
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	for _, f := range bytes.FieldsFunc(b, func(r rune) bool { return r == 0 || r == '\n' || r == '\r' }) {
		p := filepath.Clean(string(f))
		ext := filepath.Ext(p)
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		if sigma.IsFixture(p) {
			p = strings.TrimSuffix(p, ".test"+ext) + ext
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		if _, err := os.Stat(p); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, nil, err
			}
			missing = append(missing, p)
			continue
		}
		rules = append(rules, p)
	}
	sort.Strings(rules)
	sort.Strings(missing)
	return rules, missing, nil
}

// setIDs loads every rule under dir and maps each id to the files claiming
// it. Rules that do not load are left out: they claim no id.
func setIDs(dir string, tax *sigma.Taxonomy) (map[string][]string, error) {
	if dir == "" {
		return nil, nil
	}
	paths, err := sigma.RuleFiles(dir)
	if err != nil {
		return nil, err
	}
	ids := map[string][]string{}
	for _, p := range paths {
		if r, lerr := sigma.LoadRule(p, tax); lerr == nil {
			ids[r.ID] = append(ids[r.ID], p)
		}
	}
	return ids, nil
}

func fixtureEvents(paths []string) []*event.Event {
	var out []*event.Event
	for _, p := range paths {
		f, err := fixture.Load(sigma.FixturePath(p))
		if err != nil {
			continue
		}
		for _, c := range f.Cases {
			out = append(out, c.Event)
		}
	}
	return out
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return filepath.Clean(p)
}

// renderReport writes the markdown report: a summary table with one row per
// rule and one cell per gate, then a details section for each rule with
// anything to say. Everything taken from a rule or an event goes inside a
// code span or a fenced block.
func renderReport(w io.Writer, h reportHeader, rules []ruleGates, missing []string) error {
	var head strings.Builder
	fmt.Fprintln(&head, reportMarker)
	fmt.Fprintln(&head, "## Rule gates")
	fmt.Fprintln(&head)
	if len(rules) == 0 {
		fmt.Fprintln(&head, "No rule files changed.")
	} else {
		failed, warned := 0, 0
		for i := range rules {
			switch rules[i].worst() {
			case gateFail:
				failed++
			case gateWarn:
				warned++
			}
		}
		noun := "rules"
		if len(rules) == 1 {
			noun = "rule"
		}
		fmt.Fprintf(&head, "%d %s checked: %d failed, %d with warnings, %d passed.\n\n",
			len(rules), noun, failed, warned, len(rules)-failed-warned)
		corpus := "no corpus given, so the noise gate is skipped"
		if h.Corpus != "" {
			corpus = fmt.Sprintf("corpus %s, %d events", mdCode(h.Corpus), h.Events)
		}
		fmt.Fprintf(&head, "Taxonomy %s; %s; latency budget %s p99 over %d samples.\n\n",
			mdCode(h.TaxonomyV), corpus, h.Threshold, h.Samples)
		fmt.Fprintln(&head, "| Rule | Parse | Fixtures | Noise | Latency | Prefilter |")
		fmt.Fprintln(&head, "|---|---|---|---|---|---|")
		for i := range rules {
			rg := &rules[i]
			cells := make([]string, 0, numGates+1)
			cells = append(cells, cellText(mdCode(rg.Path)))
			for _, g := range rg.Gates {
				cells = append(cells, cellText(statusCell(g)))
			}
			fmt.Fprintf(&head, "| %s |\n", strings.Join(cells, " | "))
		}
	}
	if len(missing) > 0 {
		fmt.Fprintln(&head)
		fmt.Fprintln(&head, "Not checked:")
		fmt.Fprintln(&head)
		for _, p := range missing {
			fmt.Fprintf(&head, "- %s: not present in this revision (a fixture changed for a deleted rule?)\n", mdCode(p))
		}
	}

	var details strings.Builder
	for i := range rules {
		writeDetails(&details, &rules[i])
	}

	out := head.String()
	if len(out)+len(details.String()) <= maxReport {
		out += details.String()
	} else {
		out += "\nDetails were cut to fit a PR comment. Run `signalman gates` locally, or read the job summary, for the full report.\n"
	}
	_, err := io.WriteString(w, out)
	return err
}

func statusCell(g gateResult) string {
	switch g.Status {
	case gateFail:
		return strings.TrimSpace("**FAIL** " + g.Note)
	case gateSkip:
		return "skipped"
	}
	word := "pass"
	if g.Status == gateWarn {
		word = "warning"
	}
	if g.Note == "" {
		return word
	}
	return word + ", " + g.Note
}

func writeDetails(b *strings.Builder, rg *ruleGates) {
	var body strings.Builder
	for i, g := range rg.Gates {
		if g.Status == gatePass && len(g.Samples) == 0 && g.Help == "" {
			continue
		}
		if g.Status == gateSkip && g.Help == "" {
			continue
		}
		fmt.Fprintf(&body, "**%s: %s**\n\n", gateNames[i], statusWord(g.Status))
		if len(g.Detail) > 0 {
			writeBlock(&body, g.Detail)
		}
		if g.Help != "" {
			fmt.Fprintf(&body, "%s\n\n", g.Help)
		}
		if len(g.Samples) > 0 {
			fmt.Fprintf(&body, "<details><summary>%d sample matches, first in corpus order</summary>\n\n", len(g.Samples))
			writeBlock(&body, g.Samples)
			fmt.Fprintln(&body, "</details>")
			fmt.Fprintln(&body)
		}
	}
	if body.Len() == 0 {
		return
	}
	fmt.Fprintf(b, "\n### %s\n\n%s", mdCode(rg.Path), strings.TrimRight(body.String(), "\n")+"\n")
}

func statusWord(s gateStatus) string {
	switch s {
	case gateFail:
		return "FAIL"
	case gateWarn:
		return "warning"
	case gateSkip:
		return "skipped"
	}
	return "pass"
}

func writeBlock(b *strings.Builder, lines []string) {
	f := fence(lines)
	fmt.Fprintln(b, f)
	for _, l := range lines {
		fmt.Fprintln(b, l)
	}
	fmt.Fprintln(b, f)
	fmt.Fprintln(b)
}

// fence returns a backtick fence longer than any backtick run in lines, so
// rule or event text cannot close the block early.
func fence(lines []string) string {
	n := longestRun(strings.Join(lines, "\n"), '`')
	return strings.Repeat("`", max(3, n+1))
}

// mdCode wraps s in a code span whose delimiter outruns any backticks in s.
func mdCode(s string) string {
	d := strings.Repeat("`", longestRun(s, '`')+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return d + s + d
}

func longestRun(s string, c byte) int {
	best, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			cur++
			best = max(best, cur)
		} else {
			cur = 0
		}
	}
	return best
}

// cellText makes s safe inside a table cell: a pipe would end the cell,
// even inside a code span, and a newline would end the row.
func cellText(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}
