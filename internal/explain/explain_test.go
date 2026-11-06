package explain

import (
	"bytes"
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/fixture"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/sigma/ast"
)

func loadTax(t *testing.T) *sigma.Taxonomy {
	t.Helper()
	tax, err := sigma.LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	return tax
}

func loadRule(t *testing.T, path string) *sigma.Rule {
	t.Helper()
	r, lerr := sigma.LoadRule(path, loadTax(t))
	if lerr != nil {
		t.Fatal(lerr)
	}
	return r
}

func render(t *testing.T, x *Explanation) string {
	t.Helper()
	var b bytes.Buffer
	if err := x.Render(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// The spec's abbreviated example, on the spec's event.
func TestRenderMatchesTheSpecFormat(t *testing.T) {
	r := loadRule(t, "../../rules/proc_dump.yml")
	ev := &event.Event{Fields: map[string]event.Value{
		"channel":     event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id":    event.Int(1),
		"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
		"CommandLine": event.String(`rundll32.exe comsvcs.dll, MiniDump 624 C:\t.dmp full`),
		"ParentImage": event.String(`C:\Windows\explorer.exe`),
	}}
	got := render(t, Explain(r, ev))
	want := strings.Join([]string{
		`rule  proc_dump  (T1003.001 / LSASS Memory Dump via comsvcs)  => MATCH`,
		`  logsource                                                   true`,
		`    channel 'Microsoft-Windows-Sysmon/Operational'            true   ("Microsoft-Windows-Sysmon/Operational")`,
		`    event_id '1'                                              true   (1)`,
		`  AND`,
		`    selection_img                                             true`,
		`      Image|endswith '\rundll32.exe'                          true   ("C:\Windows\System32\rundll32.exe")`,
		`    selection_cli                                             true`,
		`      CommandLine|contains 'comsvcs.dll', 'MiniDump'          true   ("rundll32.exe comsvcs.dll, MiniDump 624 ...")`,
		`    NOT filter_backup                                         true`,
		`      ParentImage|endswith '\veeam.exe'                       false  ("C:\Windows\explorer.exe")`,
		``,
	}, "\n")
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderShowsALogsourceMismatch(t *testing.T) {
	r := loadRule(t, "../../rules/proc_dump.yml")
	ev := &event.Event{Fields: map[string]event.Value{
		"channel":     event.String("Security"),
		"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
		"CommandLine": event.String(`rundll32.exe comsvcs.dll MiniDump`),
	}}
	x := Explain(r, ev)
	if x.Matched || x.LogSource.Result || !x.Condition.Result {
		t.Fatalf("matched=%v logsource=%v condition=%v", x.Matched, x.LogSource.Result, x.Condition.Result)
	}
	out := render(t, x)
	for _, want := range []string{"=> NO MATCH", `("Security")`, "event_id '1'", "(absent)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestRenderNamesTheRenamedField(t *testing.T) {
	r := loadRule(t, "../../rules/net_user_add.yml")
	ev := &event.Event{Fields: map[string]event.Value{
		"channel":        event.String("Security"),
		"event_id":       event.Int(4688),
		"NewProcessName": event.String(`C:\Windows\System32\net.exe`),
		"CommandLine":    event.String(`net user x /add`),
	}}
	out := render(t, Explain(r, ev))
	if !strings.Contains(out, `(NewProcessName: "C:\Windows\System32\net.exe")`) {
		t.Fatalf("a renamed field should be named beside its value:\n%s", out)
	}
	if !strings.Contains(out, `("net user x /add")`) {
		t.Fatalf("an unrenamed field should not be:\n%s", out)
	}
}

func TestRenderKeywordAndListAndQuantifier(t *testing.T) {
	r := loadRule(t, "../../rules/mimikatz_keywords.yml")
	ev := &event.Event{Fields: map[string]event.Value{
		"channel":     event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id":    event.Int(1),
		"CommandLine": event.String(`m.exe sekurlsa::logonpasswords`),
	}}
	out := render(t, Explain(r, ev))
	if !strings.Contains(out, "keyword 'sekurlsa::'") || !strings.Contains(out, "(any field)") {
		t.Fatalf("keyword leaves:\n%s", out)
	}

	r = loadRule(t, "../../rules/bcdedit_recovery_disabled.yml")
	out = render(t, Explain(r, &event.Event{Fields: map[string]event.Value{
		"Image": event.List(event.String("a"), event.Int(2)),
	}}))
	for _, want := range []string{"selection_opt_ignore", "selection_opt_recovery", `(["a", 2])`, "  OR"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestRenderEscapesControlCharacters(t *testing.T) {
	r := loadRule(t, "../../rules/psexec_service_child.yml")
	out := render(t, Explain(r, &event.Event{Fields: map[string]event.Value{
		"ParentImage": event.String("a\nb\tc\\d"),
	}}))
	if !strings.Contains(out, `("a\nb\tc\d")`) || strings.Count(out, "\n") != 6 {
		t.Fatalf("a value must stay on its line:\n%s", out)
	}
}

// The tracing walker is a second evaluator, so it has to agree with the
// real one on every rule and every event available: each shipped rule
// against every fixture event of every shipped rule.
func TestExplainAgreesWithV1(t *testing.T) {
	tax := loadTax(t)
	paths, err := sigma.RuleFiles("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	var rules []*sigma.Rule
	var events []*event.Event
	for _, p := range paths {
		r, lerr := sigma.LoadRule(p, tax)
		if lerr != nil {
			t.Fatal(lerr)
		}
		rules = append(rules, r)
		f, err := fixture.Load(sigma.FixturePath(p))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range f.Cases {
			events = append(events, c.Event)
		}
	}
	matches := 0
	for _, r := range rules {
		e := v1.New(&sigma.RuleSet{Rules: []sigma.Rule{*r}})
		for i, ev := range events {
			x := Explain(r, ev)
			want := e.Evaluate(ev)[0].Matched
			if x.Matched != want {
				t.Errorf("%s event %d: explain %v, v1 %v", r.Path, i, x.Matched, want)
			}
			if x.Condition.Result != ast.Eval(r.Cond, ev) {
				t.Errorf("%s event %d: condition disagrees with ast.Eval", r.Path, i)
			}
			if want {
				matches++
			}
		}
	}
	if len(rules) < 20 || matches == 0 {
		t.Fatalf("%d rules, %d matches: the comparison covered too little", len(rules), matches)
	}
}

// A rule built without the named form still explains, from the bound tree.
func TestExplainFallsBackToTheBoundTree(t *testing.T) {
	r := *loadRule(t, "../../rules/proc_dump.yml")
	r.Condition, r.Selections = nil, nil
	x := Explain(&r, &event.Event{Fields: map[string]event.Value{
		"Image": event.String(`C:\rundll32.exe`),
	}})
	if x.Condition == nil || x.Condition.Result {
		t.Fatalf("condition = %+v", x.Condition)
	}
	if out := render(t, x); strings.Contains(out, "selection_img") {
		t.Fatalf("no names to show:\n%s", out)
	}
}
