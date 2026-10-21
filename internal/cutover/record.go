package cutover

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Section headings in docs/cutover.md that the checker reads and writes.
const (
	headingLadder      = "## Gate ladder"
	headingDivergences = "## Divergence log"
	headingEvidence    = "## Gate evidence"
)

// section returns the lines under heading, up to the next "## " heading.
func section(doc, heading string) []string {
	var out []string
	in := false
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "## ") {
			if in {
				break
			}
			in = strings.TrimSpace(line) == heading
			continue
		}
		if in {
			out = append(out, line)
		}
	}
	return out
}

// cells splits a markdown table row into trimmed cells.
func cells(line string) []string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
		return nil
	}
	parts := strings.Split(line[1:len(line)-1], "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// LadderDates reads the Date passed column of the gate ladder table, by
// gate: "G0" to "G6". An undated gate maps to "".
func LadderDates(doc string) map[string]string {
	out := map[string]string{}
	for _, line := range section(doc, headingLadder) {
		c := cells(line)
		if len(c) < 3 {
			continue
		}
		g, _, _ := strings.Cut(c[0], " ")
		for _, want := range Gates {
			if g == want {
				out[g] = c[len(c)-1]
			}
		}
	}
	return out
}

func ladderSummary(dates map[string]string) string {
	var parts []string
	for _, g := range Gates {
		if d, ok := dates[g]; ok && d != "" {
			parts = append(parts, g+" "+d)
		}
	}
	return strings.Join(parts, ", ")
}

// OpenDivergences returns the divergence log entries that are not closed:
// no root cause, no fix, or a status other than fixed or closed. n is the
// number of entries.
func OpenDivergences(doc string) (open []string, n int) {
	for _, line := range section(doc, headingDivergences) {
		c := cells(line)
		if len(c) < 8 {
			continue
		}
		if _, err := strconv.Atoi(c[0]); err != nil {
			continue // header or separator
		}
		n++
		cause, fix, status := c[5], c[6], strings.ToLower(c[7])
		if cause == "" || fix == "" || (status != "fixed" && status != "closed") {
			open = append(open, "#"+c[0])
		}
	}
	return open, n
}

// Record adds a passed gate to docs/cutover.md: the date in the ladder
// table, and the evidence under "## Gate evidence". It refuses a report that
// did not pass, a gate already dated, and a step already recorded. G3 is
// two steps: 10% records evidence only, and 50% dates the gate once 10% is
// recorded. invocation is the command line, recorded with the evidence.
func Record(doc string, r Report, invocation string) (string, error) {
	if !r.Passed() {
		return doc, fmt.Errorf("%s did not pass; only a passed gate is recorded", r.Name())
	}
	if i := strings.LastIndex(doc, "\n## "); i < 0 || !strings.HasPrefix(doc[i+1:], headingEvidence+"\n") {
		return doc, fmt.Errorf("the document's last section is not %q, which evidence is appended to", headingEvidence)
	}
	date := r.At.UTC().Format(time.DateOnly)
	head := fmt.Sprintf("### %s passed", r.Name())
	if strings.Contains(doc, "\n"+head+" ") {
		return doc, fmt.Errorf("%s is already recorded", r.Name())
	}
	dates := LadderDates(doc)
	if _, ok := dates[r.Gate]; !ok {
		return doc, fmt.Errorf("no %s row in the gate ladder table", r.Gate)
	}
	if dates[r.Gate] != "" {
		return doc, fmt.Errorf("%s is already dated %s", r.Gate, dates[r.Gate])
	}
	dateIt := !(r.Gate == "G3" && r.Step == 10)
	if r.Gate == "G3" && r.Step == 50 && !strings.Contains(doc, "\n### G3 10% passed ") {
		return doc, fmt.Errorf("G3 50%% is recorded after G3 10%%, which is not")
	}

	lines := strings.Split(doc, "\n")
	if dateIt {
		in := false
		for i, line := range lines {
			if strings.HasPrefix(line, "## ") {
				in = strings.TrimSpace(line) == headingLadder
				continue
			}
			c := cells(line)
			if !in || len(c) < 3 {
				continue
			}
			if g, _, _ := strings.Cut(c[0], " "); g == r.Gate {
				end := strings.LastIndex(strings.TrimRight(line, " "), "|")
				prev := strings.LastIndex(line[:end], "|")
				lines[i] = line[:prev+1] + " " + date + " " + line[end:]
				break
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n\n", head, date)
	when := "at"
	if r.Window > 0 {
		when = fmt.Sprintf("over the %s ending", promDur(r.Window))
	}
	fmt.Fprintf(&b, "Checked %s %s with `%s`.\n\n", when, r.At.UTC().Format(time.RFC3339), invocation)
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "- `%s` %s: %s. %s\n", c.Key, c.Status, c.Criterion, c.Evidence)
	}
	out := strings.TrimRight(strings.Join(lines, "\n"), "\n")
	// The placeholder line goes once something is recorded.
	out = strings.Replace(out, "\n"+noEvidence+"\n", "\n", 1)
	out = strings.TrimSuffix(out, "\n"+noEvidence)
	return out + "\n\n" + b.String(), nil
}

// noEvidence is the Gate evidence section's text before anything is
// recorded.
const noEvidence = "Nothing recorded. No gate has been checked against production traffic."
