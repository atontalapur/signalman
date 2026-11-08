package cutover

import (
	"os"
	"strings"
	"testing"
	"time"
)

func passed(gate string, step int) Report {
	return Report{Gate: gate, Step: step, At: checkAt, Window: 48 * time.Hour, Checks: []Check{
		{Key: "divergences", Criterion: "no divergence", Status: Pass, Evidence: "0 over 48h"},
		{Key: "flag-only", Criterion: "flag only", Status: Attested, Evidence: "attested: diff empty", Manual: true},
	}}
}

// recordNow is the clock Record checks report times against.
var recordNow = checkAt.Add(time.Hour)

func undated() string {
	doc := ladderDoc
	for _, d := range []string{"2026-09-01", "2026-09-10", "2026-09-12", "2026-09-16", "2026-09-18", "2026-09-19"} {
		doc = strings.Replace(doc, " "+d+" |", " |", 1)
	}
	return doc
}

// datedBefore is undated() with every gate before gate dated, as the ladder
// requires before gate is recorded.
func datedBefore(gate string) string {
	doc := undated()
	for _, g := range Gates {
		if g == gate {
			break
		}
		lines := strings.Split(doc, "\n")
		for i, l := range lines {
			if strings.HasPrefix(l, "| "+g+" ") && strings.HasSuffix(l, "| |") {
				lines[i] = strings.TrimSuffix(l, " |") + " 2026-09-01 |"
			}
		}
		doc = strings.Join(lines, "\n")
	}
	return doc
}

func TestRecordDatesTheGateAndAppendsEvidence(t *testing.T) {
	doc := datedBefore("G4")
	out, err := Record(doc, passed("G4", 0), "cutover check -gate G4 -record", recordNow)
	if err != nil {
		t.Fatal(err)
	}
	if d := LadderDates(out); d["G4"] != "2026-11-02" || d["G5"] != "" {
		t.Fatalf("dates %v", d)
	}
	if !strings.Contains(out, "| G4 100% served by v2 | e | 2026-11-02 |") {
		t.Fatalf("row not dated in place:\n%s", out)
	}
	for _, want := range []string{
		"\n### G4 passed 2026-11-02\n",
		"Checked over the 48h ending 2026-11-02T12:00:00Z with `cutover check -gate G4 -record`.",
		"- `divergences` pass: no divergence. 0 over 48h\n",
		"- `flag-only` attested: flag only. attested: diff empty\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("record lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, noEvidence) {
		t.Error("the placeholder survived the first record")
	}
	if !strings.Contains(out, "## Gate evidence\n\n### G4 passed") {
		t.Errorf("the first entry does not follow the heading after one blank line:\n%s", out)
	}
	if _, err := Record(out, passed("G4", 0), "again", recordNow); err == nil {
		t.Fatal("a gate recorded twice")
	}
}

func TestRecordRefusesAGateThatDidNotPass(t *testing.T) {
	r := passed("G2", 0)
	r.Checks[0].Status = Unchecked
	if out, err := Record(undated(), r, "x", recordNow); err == nil || out != undated() {
		t.Fatal("an unchecked gate was recorded")
	}
	if _, err := Record(undated(), Report{Gate: "G2", At: checkAt}, "x", recordNow); err == nil {
		t.Fatal("a gate with no checks was recorded")
	}
}

func TestRecordG3TakesBothStepsInOrder(t *testing.T) {
	doc := datedBefore("G3")
	if _, err := Record(doc, passed("G3", 50), "x", recordNow); err == nil {
		t.Fatal("G3 50% recorded before 10%")
	}
	doc, err := Record(doc, passed("G3", 10), "x", recordNow)
	if err != nil {
		t.Fatal(err)
	}
	if LadderDates(doc)["G3"] != "" {
		t.Fatal("the 10% step dated G3")
	}
	doc, err = Record(doc, passed("G3", 50), "x", recordNow)
	if err != nil {
		t.Fatal(err)
	}
	if LadderDates(doc)["G3"] != "2026-11-02" || !strings.Contains(doc, "### G3 10% passed") || !strings.Contains(doc, "### G3 50% passed") {
		t.Fatalf("G3:\n%s", doc)
	}
}

func TestRecordNeedsEvidenceLast(t *testing.T) {
	doc := undated() + "\n## Later\n\ntext\n"
	if _, err := Record(doc, passed("G2", 0), "x", recordNow); err == nil {
		t.Fatal("evidence appended under the wrong section")
	}
}

func TestOpenDivergences(t *testing.T) {
	doc := strings.Replace(ladderDoc, "| fixed |", "| fixed |\n| 2 | 2026-09-04 | missing_verdict | r | 1/2 | | | open |", 1)
	open, n := OpenDivergences(doc)
	if n != 2 || len(open) != 1 || open[0] != "#2" {
		t.Fatalf("open %v of %d", open, n)
	}
}

// The checked-in document has every gate in its table and the evidence
// section last, so -record has somewhere to write.
func TestCutoverDocHasTheLadder(t *testing.T) {
	b, err := os.ReadFile("../../docs/cutover.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	dates := LadderDates(doc)
	for _, g := range Gates {
		if _, ok := dates[g]; !ok {
			t.Errorf("no %s row in the gate ladder", g)
		}
	}
	i := strings.LastIndex(doc, "\n## ")
	if i < 0 || !strings.HasPrefix(doc[i+1:], headingEvidence+"\n") {
		t.Fatal("the last section of docs/cutover.md is not the gate evidence")
	}
}

// A report dated after now would put a future date in the ladder.
func TestRecordRefusesAReportFromTheFuture(t *testing.T) {
	if _, err := Record(undated(), passed("G0", 0), "x", checkAt.Add(-time.Second)); err == nil {
		t.Fatal("a report dated after now was recorded")
	}
}

// The ladder is climbed in order: a gate is recorded only once every gate
// before it has a date.
func TestRecordEnforcesLadderOrder(t *testing.T) {
	if _, err := Record(undated(), passed("G0", 0), "x", recordNow); err != nil {
		t.Fatalf("G0 needs nothing before it: %v", err)
	}
	doc := datedBefore("G4")
	doc = strings.Replace(doc, "| c | 2026-09-01 |", "| c | |", 1) // G2 undated
	_, err := Record(doc, passed("G4", 0), "x", recordNow)
	if err == nil || !strings.Contains(err.Error(), "G2") {
		t.Fatalf("G4 recorded with G2 undated: %v", err)
	}
	if _, err := Record(datedBefore("G3"), passed("G3", 10), "x", recordNow); err != nil {
		t.Fatalf("G3 10%% after G2: %v", err)
	}
	if _, err := Record(datedBefore("G2"), passed("G3", 10), "x", recordNow); err == nil {
		t.Fatal("G3 10% recorded before G2")
	}
}
