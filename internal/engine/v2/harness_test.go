package v2

import (
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	v1 "github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/sigma/ast"
	"github.com/atontalapur/signalman/internal/sigma/match"
	"github.com/atontalapur/signalman/internal/verdict"
)

// ruleSource is one rule set the equivalence tests run against.
type ruleSource struct {
	name string
	rs   *sigma.RuleSet
}

func loadSet(t testing.TB, rulesDir, taxDir string) *sigma.RuleSet {
	t.Helper()
	tax, err := sigma.LoadTaxonomy(taxDir)
	if err != nil {
		t.Fatal(err)
	}
	// Rejections are expected in the sigma fixtures (an aggregation, an
	// unmapped logsource); only what loaded is evaluated, by both engines.
	rs, _, err := sigma.LoadRuleSet(rulesDir, tax)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// fixtureSources are the rule sets checked into the repository, including the
// shipped rules/ directory, so they run in CI where the corpus does not exist.
func fixtureSources(t testing.TB) []ruleSource {
	t.Helper()
	return []ruleSource{
		{"sigma-fixtures", loadSet(t, "../../sigma/testdata/rules", "../../sigma/testdata/taxonomy")},
		{"v1-fixtures", loadSet(t, "../v1/testdata/rules", "../v1/testdata/taxonomy")},
		{"shipped-rules", loadSet(t, "../../../rules", "../../../config/taxonomy")},
	}
}

// corpusRoot is the SigmaHQ clone. SIGNALMAN_CORPUS overrides the default,
// which is the gitignored corpora/ directory at the module root.
func corpusRoot() string {
	if d := os.Getenv("SIGNALMAN_CORPUS"); d != "" {
		return d
	}
	return "../../../corpora/sigmahq"
}

// corpusDir is the corpus `rules` tree, or an error when it is absent.
func corpusDir() (string, error) {
	dir := filepath.Join(corpusRoot(), "rules")
	_, err := os.Stat(dir)
	return dir, err
}

var (
	corpusOnce sync.Once
	corpusRS   *sigma.RuleSet
	corpusErr  error
)

// corpusSource loads the accepted SigmaHQ `rules` tree against the shipping
// taxonomy: the same set the v1 baseline benchmark measures. It skips when
// the corpus is absent, which it is in CI.
func corpusSource(t testing.TB) *sigma.RuleSet {
	t.Helper()
	dir, err := corpusDir()
	if err != nil {
		t.Skip("SigmaHQ corpus not vendored (set SIGNALMAN_CORPUS or clone into corpora/sigmahq)")
	}
	corpusOnce.Do(func() {
		tax, err := sigma.LoadTaxonomy("../../../config/taxonomy")
		if err != nil {
			corpusErr = err
			return
		}
		corpusRS, _, corpusErr = sigma.LoadRuleSet(dir, tax)
	})
	if corpusErr != nil {
		t.Fatal(corpusErr)
	}
	return corpusRS
}

// genEvents builds a deterministic event stream aimed at the rule set:
// for each rule, events that try to satisfy its condition, the same events
// perturbed, and events that mix two rules' fields. A stream of random
// events would make every verdict false and the digest comparison
// vacuous; aiming at the rules is what makes true verdicts common enough
// for a disagreement to show.
func genEvents(rs *sigma.RuleSet, perRule int, seed int64) []*event.Event {
	rng := rand.New(rand.NewSource(seed))
	var out []*event.Event
	add := func(f map[string]event.Value) {
		out = append(out, &event.Event{Fields: f})
	}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		for k := 0; k < perRule; k++ {
			f := map[string]event.Value{}
			if rng.Intn(10) != 0 {
				satisfyLogsource(r, f)
			}
			satisfy(r.Cond, f, rng)
			switch rng.Intn(4) {
			case 0:
				perturb(f, rng)
			case 1:
				o := &rs.Rules[rng.Intn(len(rs.Rules))]
				satisfy(o.Cond, f, rng)
			}
			add(f)
		}
	}
	// A few events no rule was aimed at: empty, null-heavy, list valued.
	add(map[string]event.Value{})
	add(map[string]event.Value{"channel": event.Null(), "Image": event.Null(), "CommandLine": event.List()})
	add(map[string]event.Value{
		"channel":     event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id":    event.List(event.Int(3), event.Int(1)),
		"CommandLine": event.List(event.String("a"), event.Int(7), event.Null(), event.List(event.String("x"))),
	})

	// Seq is monotonic per partition, which the digest requires.
	next := map[int32]uint64{}
	for i, ev := range out {
		ev.Partition = int32(i % 4)
		next[ev.Partition]++
		ev.Seq = next[ev.Partition]
	}
	return out
}

func satisfyLogsource(r *sigma.Rule, f map[string]event.Value) {
	var walk func(ast.Node)
	walk = func(n ast.Node) {
		switch n := n.(type) {
		case *ast.And:
			for _, c := range n.Children {
				walk(c)
			}
		case *ast.Pred:
			if len(n.Vals) > 0 {
				f[n.Field] = n.Vals[0]
			}
		}
	}
	if r.LogSource.Node != nil {
		walk(r.LogSource.Node)
	}
}

// satisfy writes field values that try to make n true. It is a heuristic,
// not a solver: Or picks one arm, Not is left to chance, and regexes get
// their source text. Wrong guesses are fine; they are false verdicts both
// engines must agree on.
func satisfy(n ast.Node, f map[string]event.Value, rng *rand.Rand) {
	switch n := n.(type) {
	case *ast.And:
		for _, c := range n.Children {
			satisfy(c, f, rng)
		}
	case *ast.Or:
		satisfy(n.Children[rng.Intn(len(n.Children))], f, rng)
	case *ast.Not:
		if rng.Intn(3) == 0 {
			satisfy(n.Child, f, rng)
		}
	case *ast.Pred:
		satisfyPred(n, f, rng)
	}
}

func satisfyPred(p *ast.Pred, f map[string]event.Value, rng *rand.Rand) {
	if len(p.Vals) == 0 {
		return
	}
	if p.Keyword {
		s, _ := p.Vals[0].Text()
		f[fmt.Sprintf("Message%d", rng.Intn(3))] = event.String("pre " + caseFlip(s, rng) + " post")
		return
	}
	var comparison string
	var all bool
	var transforms []string
	fieldref := false
	for _, m := range p.Mods {
		switch m {
		case "contains", "startswith", "endswith", "re", "cidr", "lt", "lte", "gt", "gte":
			comparison = m
		case "all":
			all = true
		case "fieldref":
			fieldref = true
		case "i":
		default:
			transforms = append(transforms, m)
		}
	}
	pick := p.Vals[rng.Intn(len(p.Vals))]
	if pick.Kind == event.KindNull {
		if rng.Intn(2) == 0 {
			delete(f, p.Field)
		} else {
			f[p.Field] = event.Null()
		}
		return
	}
	text, _ := pick.Text()
	if fieldref {
		v := event.String("ref-" + strconv.Itoa(rng.Intn(5)))
		f[p.Field] = v
		f[text] = v
		return
	}
	switch comparison {
	case "cidr":
		if pfx, err := netip.ParsePrefix(text); err == nil {
			f[p.Field] = event.String(pfx.Masked().Addr().String())
		}
		return
	case "lt", "lte", "gt", "gte":
		n, _ := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
		f[p.Field] = event.Int(n + int64(rng.Intn(3)-1))
		return
	case "re":
		f[p.Field] = event.String(strings.Map(func(r rune) rune {
			if strings.ContainsRune(`\^$.|?*+()[]{}`, r) {
				return -1
			}
			return r
		}, text))
		return
	}

	texts := []string{text}
	if all {
		texts = texts[:0]
		for _, v := range p.Vals {
			s, _ := v.Text()
			texts = append(texts, s)
		}
	}
	for i, s := range texts {
		s = unwild(s)
		for _, tr := range transforms {
			s = applyTransform(tr, s, rng)
		}
		texts[i] = caseFlip(s, rng)
	}
	s := strings.Join(texts, " ")
	switch comparison {
	case "contains":
		s = "x" + s + "y"
	case "startswith":
		s += "_tail"
	case "endswith":
		s = "head_" + s
	}
	var v event.Value
	if _, err := strconv.ParseInt(s, 10, 64); err == nil && rng.Intn(2) == 0 {
		n, _ := strconv.ParseInt(s, 10, 64)
		v = event.Int(n)
	} else {
		v = event.String(s)
	}
	if rng.Intn(6) == 0 {
		v = event.List(event.String("decoy"), v)
	}
	f[p.Field] = v
}

func applyTransform(tr, s string, rng *rand.Rand) string {
	switch tr {
	case "base64":
		return match.Base64(s)
	case "base64offset":
		return match.Base64Offsets(s)[rng.Intn(3)]
	case "utf16le", "wide":
		return match.UTF16LE(s)
	case "utf16be":
		return match.UTF16BE(s)
	case "utf16":
		return match.UTF16(s)
	case "windash":
		if vs, err := match.WinDashVariants(s); err == nil {
			return vs[rng.Intn(len(vs))]
		}
	}
	return s
}

// unwild turns a Sigma wildcard pattern into one string it matches.
func unwild(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s) && strings.IndexByte(`*?\`, s[i+1]) >= 0:
			i++
			b.WriteByte(s[i])
		case c == '*':
			b.WriteString("zz")
		case c == '?':
			b.WriteByte('q')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func caseFlip(s string, rng *rand.Rand) string {
	switch rng.Intn(3) {
	case 0:
		return strings.ToUpper(s)
	case 1:
		return strings.ToLower(s)
	}
	return s
}

func perturb(f map[string]event.Value, rng *rand.Rand) {
	if len(f) == 0 {
		return
	}
	names := make([]string, 0, len(f))
	for k := range f {
		names = append(names, k)
	}
	sort.Strings(names)
	k := names[rng.Intn(len(names))]
	switch rng.Intn(3) {
	case 0:
		delete(f, k)
	case 1:
		f[k] = event.Null()
	default:
		if s, ok := f[k].Text(); ok && len(s) > 1 {
			f[k] = event.String(s[:len(s)/2])
		}
	}
}

// equivalence is what one comparison found.
type equivalence struct {
	rules, events int
	verdicts      uint64
	matched       int
	digests       []string
}

// compareEngines runs both engines over the stream and fails on the first
// verdict that differs, naming the rule and the event. Then it compares the
// per-partition digests, which is the comparison the cutover will rely on.
func compareEngines(t testing.TB, rs *sigma.RuleSet, evs []*event.Event) equivalence {
	t.Helper()
	ref := v1.New(rs)
	got := New(rs)
	refSet, gotSet := verdict.NewSet(), verdict.NewSet()
	var refBuf, gotBuf []event.Verdict
	res := equivalence{rules: len(rs.Rules), events: len(evs)}
	for _, ev := range evs {
		refBuf = ref.EvaluateInto(refBuf[:0], ev)
		gotBuf = got.EvaluateInto(gotBuf[:0], ev)
		if len(gotBuf) != len(refBuf) {
			t.Fatalf("event %d/%d: v2 gave %d verdicts, v1 %d", ev.Partition, ev.Seq, len(gotBuf), len(refBuf))
		}
		for i := range refBuf {
			a, b := refBuf[i], gotBuf[i]
			if a.RuleID != b.RuleID || a.Matched != b.Matched || a.Seq != b.Seq ||
				a.Partition != b.Partition || a.RuleSetV != b.RuleSetV || a.TaxonomyV != b.TaxonomyV {
				t.Fatalf("divergence on event %d/%d fields %v:\n v1 %+v\n v2 %+v", ev.Partition, ev.Seq, ev.Fields, a, b)
			}
			if b.Engine != Name {
				t.Fatalf("v2 verdict stamped %q", b.Engine)
			}
			if a.Matched {
				res.matched++
			}
			if err := refSet.Fold(a); err != nil {
				t.Fatal(err)
			}
			if err := gotSet.Fold(b); err != nil {
				t.Fatal(err)
			}
		}
	}
	want, have := refSet.Sums(), gotSet.Sums()
	if len(want) != len(have) {
		t.Fatalf("v1 has %d partitions, v2 %d", len(want), len(have))
	}
	for i, p := range refSet.Partitions() {
		if want[i] != have[i] {
			t.Fatalf("partition %d digest v2 %s, v1 %s", p, have[i], want[i])
		}
		a, _ := refSet.Digest(p)
		b, _ := gotSet.Digest(p)
		if a.Verdicts() != b.Verdicts() || a.Events() != b.Events() {
			t.Fatalf("partition %d counts differ: v1 %d/%d v2 %d/%d", p, a.Verdicts(), a.Events(), b.Verdicts(), b.Events())
		}
		res.verdicts += a.Verdicts()
	}
	res.digests = want
	return res
}

// TestFixtureSourcesCoverShippedRules keeps the shipped rules/ directory in
// the CI equivalence set. Every shipped rule must load: a rejection there
// would silently shrink what the equivalence tests compare.
func TestFixtureSourcesCoverShippedRules(t *testing.T) {
	var got *sigma.RuleSet
	for _, src := range fixtureSources(t) {
		if src.name == "shipped-rules" {
			got = src.rs
		}
	}
	if got == nil {
		t.Fatal("fixtureSources does not include the shipped rules/ directory")
	}
	files, err := sigma.RuleFiles("../../../rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) == 0 || len(got.Rules) != len(files) {
		t.Fatalf("shipped-rules loaded %d rules from %d rule files", len(got.Rules), len(files))
	}
}
