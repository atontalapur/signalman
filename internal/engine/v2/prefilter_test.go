package v2

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	v1 "github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

func ruleFrom(t testing.TB, detection string) *sigma.Rule {
	t.Helper()
	tax, err := sigma.LoadTaxonomy("../v1/testdata/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	y := "title: t\nid: 00000000-0000-4000-8000-00000000a001\nlevel: low\nlogsource: {product: windows, category: process_creation}\ndetection:\n" + detection
	r, lerr := sigma.LoadRuleBytes("r", []byte(y), tax)
	if lerr != nil {
		t.Fatal(lerr)
	}
	return r
}

func litStrings(ls []Literal) string {
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		f := l.Field
		if l.Keyword {
			f = "*"
		}
		out = append(out, f+"="+l.Text)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// The derivation is checked on the condition alone: the logsource always
// carries a literal, which would hide every case here.
func TestRequiredLiteralsDerivation(t *testing.T) {
	cases := []struct{ name, det, want string }{
		{"equals", "  sel: {Image: 'C:\\X.exe'}\n  condition: sel\n", `Image=c:\x.exe`},
		{"contains list is a union", "  sel: {CommandLine|contains: [abc, defg]}\n  condition: sel\n", "CommandLine=abc CommandLine=defg"},
		{"all takes one value", "  sel: {CommandLine|contains|all: [ab, cdef]}\n  condition: sel\n", "CommandLine=cdef"},
		{"wildcard takes the longest run", "  sel: {Image: 'a*bcd?e'}\n  condition: sel\n", "Image=bcd"},
		{"and picks the best child", "  a: {Image|endswith: '\\x.exe'}\n  b: {CommandLine|contains: 'q'}\n  condition: a and b\n", `Image=\x.exe`},
		{"never from under not", "  a: {Image|endswith: '\\x.exe'}\n  b: {CommandLine|contains: 'a long literal'}\n  condition: a and not b\n", `Image=\x.exe`},
		{"not alone has none", "  a: {Image|endswith: '\\x.exe'}\n  condition: not a\n", ""},
		{"or needs every arm", "  a: {Image|endswith: '\\x.exe'}\n  b: {CommandLine|re: 'x+'}\n  condition: a or b\n", ""},
		{"or unions arms", "  a: {Image|endswith: '\\x.exe'}\n  b: {CommandLine|contains: 'yy'}\n  condition: a or b\n", `CommandLine=yy Image=\x.exe`},
		{"1 of is an or", "  sel1: {Image: 'aa'}\n  sel2: {Image: 'bb'}\n  condition: 1 of sel*\n", "Image=aa Image=bb"},
		{"regex has none", "  sel: {CommandLine|re: 'abc'}\n  condition: sel\n", ""},
		{"cidr has none", "  sel: {DestinationIp|cidr: '10.0.0.0/8'}\n  condition: sel\n", ""},
		{"compare has none", "  sel: {EventID|gt: 4}\n  condition: sel\n", ""},
		{"fieldref has none", "  sel: {Image|fieldref: ParentImage}\n  condition: sel\n", ""},
		{"null has none", "  sel: {Image: null}\n  condition: sel\n", ""},
		{"a null value poisons the list", "  sel: {Image: [null, 'abc']}\n  condition: sel\n", ""},
		{"pure wildcard has none", "  sel: {Image: '*'}\n  condition: sel\n", ""},
		{"keyword reads every field", "  kw: [mimikatz]\n  condition: kw\n", "*=mimikatz"},
		{"case is folded", "  sel: {Image|contains: 'ÄBC'}\n  condition: sel\n", "Image=äbc"},
		{"windash unions variants", "  sel: {CommandLine|windash|contains: ' -x'}\n  condition: sel\n", "CommandLine= -x CommandLine= /x CommandLine= –x CommandLine= —x CommandLine= ―x"},
		{"int values are text", "  sel: {EventID: 4688}\n  condition: sel\n", "EventID=4688"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ruleFrom(t, c.det)
			if got := litStrings(requiredLiterals(r.Cond)); got != c.want {
				t.Fatalf("requiredLiterals = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRulesWithoutALiteralGoToAlways(t *testing.T) {
	tax, err := sigma.LoadTaxonomy("../v1/testdata/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	// A taxonomy entry always contributes a literal, so the only way into
	// Always is a logsource with no match criteria. Build one directly.
	r := ruleFrom(t, "  sel: {CommandLine|re: 'x'}\n  condition: sel\n")
	r.LogSource = sigma.LogSourceMatcher{}
	keyed := ruleFrom(t, "  sel: {CommandLine|contains: 'x'}\n  condition: sel\n")
	keyed.ID = "s"
	p, err := Compile(&sigma.RuleSet{Rules: []sigma.Rule{*r, *keyed}, Version: "x", TaxonomyV: tax.Version})
	if err != nil {
		t.Fatal(err)
	}
	if p.AlwaysSize() != 1 || p.Always[0] != 0 {
		t.Fatalf("Always = %v, want [0]", p.Always)
	}
}

// admittedBy runs only the prefilter.
func admittedBy(e *Evaluator, ev *event.Event) []bool {
	s := e.pool.Get().(*scratch)
	defer e.pool.Put(s)
	s.reset(ev)
	s.load()
	out := make([]bool, len(e.prog.Trees))
	for i := range out {
		out[i] = s.candidate(i)
	}
	return out
}

// checkPrefilterSound asserts the S-71 property: for every rule and every
// event, the prefilter rejecting the rule implies v1 evaluates it false.
func checkPrefilterSound(t testing.TB, rs *sigma.RuleSet, evs []*event.Event) (rejected, total int) {
	t.Helper()
	ref := v1.New(rs)
	e := New(rs)
	var buf []event.Verdict
	for _, ev := range evs {
		adm := admittedBy(e, ev)
		buf = ref.EvaluateInto(buf[:0], ev)
		for i, v := range buf {
			total++
			if adm[i] {
				continue
			}
			rejected++
			if v.Matched {
				t.Fatalf("prefilter rejected rule %s on an event v1 matches: %v\nliterals %s",
					v.RuleID, ev.Fields, litStrings(e.prog.reqs[i]))
			}
		}
	}
	return rejected, total
}

func TestPrefilterSoundOnFixtures(t *testing.T) {
	for _, src := range fixtureSources(t) {
		t.Run(src.name, func(t *testing.T) {
			rej, total := checkPrefilterSound(t, src.rs, genEvents(src.rs, 40, 7))
			if rej == 0 {
				t.Fatal("the prefilter rejected nothing; the property was not exercised")
			}
			t.Logf("%d of %d (rule, event) pairs rejected", rej, total)
		})
	}
}

func TestPrefilterSoundOnCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus is not a short test")
	}
	rs := corpusSource(t)
	e := New(rs)
	p := e.Program()
	cond := 0
	for i := range rs.Rules {
		if len(requiredLiterals(rs.Rules[i].Cond)) > 0 {
			cond++
		}
	}
	rej, total := checkPrefilterSound(t, rs, genEvents(rs, 1, 8))
	if rej == 0 {
		t.Fatal("the prefilter rejected nothing")
	}
	t.Logf("corpus: %d rules, %d keyed on a condition literal, %d on a logsource literal only, Always %d; %d literals; %d of %d (rule, event) pairs rejected",
		len(rs.Rules), cond, len(rs.Rules)-cond-p.AlwaysSize(), p.AlwaysSize(), len(p.lits), rej, total)
}

// fuzzMods are modifier chains for the soundness fuzzer. Unlike the pySigma
// differential fuzzer there is no oracle to stay inside, so every chain the
// loader accepts is fair game, including the ones that must land in
// Always.
var fuzzMods = []string{
	"", "contains", "startswith", "endswith", "contains|all", "all",
	"re", "re|i", "cidr", "lt", "gte", "fieldref",
	"base64|contains", "base64offset|contains", "wide|base64|contains", "windash|contains",
}

var fuzzConds = []string{
	"sel",
	"not sel",
	"sel and filter",
	"sel and not filter",
	"sel or filter",
	"not (sel or filter)",
	"not (sel and not filter)",
	"1 of sel*",
	"all of sel*",
	"kw and sel",
	"kw or not sel",
	"(sel or kw) and not filter",
}

var fuzzFieldNames = []string{"Image", "CommandLine", "ParentImage", "User"}

// fuzzCase renders one rule and one event from the fuzzer's choices.
func fuzzCase(modSel, condSel, kind uint8, val, val2, evVal string) (string, *event.Event) {
	mods := fuzzMods[int(modSel)%len(fuzzMods)]
	cond := fuzzConds[int(condSel)%len(fuzzConds)]
	field := fuzzFieldNames[int(modSel/16)%len(fuzzFieldNames)]
	key := field
	if mods != "" {
		key += "|" + mods
	}
	q := func(s string) string { return fmt.Sprintf("%q", s) }
	det := fmt.Sprintf("  sel: {%s: [%s, %s]}\n  sel2: {ParentImage|contains: %s}\n  filter: {User|startswith: %s}\n  kw: [%s]\n  condition: %s\n",
		q(key), q(val), q(val2), q(val2), q(val), q(val2), cond)
	y := "title: t\nid: 00000000-0000-4000-8000-00000000a002\nlevel: low\nlogsource: {product: windows, category: process_creation}\ndetection:\n" + det

	var v event.Value
	switch kind % 5 {
	case 0:
		v = event.String(evVal)
	case 1:
		v = event.Int(int64(len(evVal)))
	case 2:
		v = event.Null()
	case 3:
		v = event.List(event.String(evVal), event.String(val))
	default:
		v = event.String(val + evVal + val2)
	}
	fields := map[string]event.Value{
		"channel":     event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id":    event.Int(1),
		"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
		"CommandLine": event.String("rundll32.exe " + evVal),
		"ParentImage": event.String(evVal),
		"User":        event.String(val2),
	}
	if kind%7 == 6 {
		delete(fields, "channel")
	}
	fields[field] = v
	return y, &event.Event{Seq: 1, Fields: fields}
}

// FuzzPrefilterSound drives rule shapes and values through the prefilter
// and asserts its one property: a rejected rule is a rule v1 evaluates
// false. It also checks v2's verdict against v1's on the same case.
func FuzzPrefilterSound(f *testing.F) {
	f.Add(uint8(1), uint8(0), uint8(0), "comsvcs", "MiniDump", "x comsvcs y")
	f.Add(uint8(3), uint8(3), uint8(4), `\rundll32.exe`, "veeam", "")
	f.Add(uint8(6), uint8(4), uint8(3), "a.c", "ABC", "zzABCzz")
	f.Add(uint8(14), uint8(10), uint8(0), "-enc", "IEX", "powershell /enc")
	f.Add(uint8(4), uint8(11), uint8(1), "x", "y", "")
	tax, err := sigma.LoadTaxonomy("../v1/testdata/taxonomy")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, modSel, condSel, kind uint8, val, val2, evVal string) {
		y, ev := fuzzCase(modSel, condSel, kind, val, val2, evVal)
		r, lerr := sigma.LoadRuleBytes("f", []byte(y), tax)
		if lerr != nil {
			return
		}
		rs := &sigma.RuleSet{Rules: []sigma.Rule{*r}, Version: "f", TaxonomyV: tax.Version}
		want := v1.New(rs).Evaluate(ev)[0].Matched
		e := New(rs)
		if !admittedBy(e, ev)[0] && want {
			t.Fatalf("prefilter rejected a rule v1 matches\nrule:\n%s\nevent %v\nliterals %s", y, ev.Fields, litStrings(e.prog.reqs[0]))
		}
		if got := e.Evaluate(ev)[0].Matched; got != want {
			t.Fatalf("v2 = %v, v1 = %v\nrule:\n%s\nevent %v", got, want, y, ev.Fields)
		}
	})
}
