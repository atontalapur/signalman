// Package explain answers "why did this rule say that about this event". It
// walks a rule's condition with the selection names kept, records every
// node's result and every leaf's observed value, and renders the tree.
//
// This is a second walker over the same predicates v1 uses, so it carries
// an equivalence test against v1 over every shipped rule and fixture. It
// differs from ast.Eval in one way only: it never short circuits, because an
// analyst needs to see every leaf. Predicates are pure functions of the
// event, so evaluating all of them cannot change a node's result.
package explain

import (
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/sigma/ast"
)

// Op is a node's kind in the explained tree.
type Op uint8

const (
	OpAnd Op = iota
	OpOr
	OpNot
	OpSelection
	OpPred
)

// Node is one evaluated node.
type Node struct {
	Op     Op
	Result bool
	// Name is the selection name for OpSelection.
	Name string
	// Pred is the leaf for OpPred, and Observed is what it read.
	Pred     *ast.Pred
	Observed event.Value
	Present  bool
	Children []*Node
}

// Explanation is the evaluated rule against one event.
type Explanation struct {
	Rule *sigma.Rule
	// LogSource is nil when the rule's logsource admits every event.
	LogSource *Node
	Condition *Node
	// Matched is the verdict: logsource admits the event and the condition
	// holds. It is what v1 returns for the same rule and event.
	Matched bool
}

// Explain evaluates r against ev.
func Explain(r *sigma.Rule, ev *event.Event) *Explanation {
	x := &Explanation{Rule: r}
	lsOK := true
	if r.LogSource.Node != nil {
		x.LogSource = trace(r.LogSource.Node, nil, ev)
		lsOK = x.LogSource.Result
	}
	if r.Condition != nil {
		x.Condition = trace(r.Condition, r.Selections, ev)
	} else {
		x.Condition = trace(r.Cond, nil, ev)
	}
	x.Matched = lsOK && x.Condition.Result
	return x
}

func trace(n ast.Node, sels map[string]ast.Node, ev *event.Event) *Node {
	switch n := n.(type) {
	case *ast.And:
		out := &Node{Op: OpAnd, Result: true}
		for _, c := range n.Children {
			t := trace(c, sels, ev)
			out.Children = append(out.Children, t)
			out.Result = out.Result && t.Result
		}
		return out
	case *ast.Or:
		out := &Node{Op: OpOr}
		for _, c := range n.Children {
			t := trace(c, sels, ev)
			out.Children = append(out.Children, t)
			out.Result = out.Result || t.Result
		}
		return out
	case *ast.Not:
		t := trace(n.Child, sels, ev)
		return &Node{Op: OpNot, Result: !t.Result, Children: []*Node{t}}
	case *ast.Ident:
		sel, ok := sels[n.Name]
		if !ok {
			panic(fmt.Sprintf("explain: selection %q has no subtree", n.Name))
		}
		t := trace(sel, nil, ev)
		return &Node{Op: OpSelection, Name: n.Name, Result: t.Result, Children: []*Node{t}}
	case *ast.Pred:
		v, present := ev.Fields[n.Field]
		return &Node{Op: OpPred, Pred: n, Result: n.Match(ev), Observed: v, Present: present}
	}
	panic(fmt.Sprintf("explain: unexpected node %T", n))
}

// line is one rendered row before alignment.
type line struct {
	indent int
	label  string
	result string
	value  string
}

// Render writes the tree in the spec's explain format: the header, then one
// row per node with its result, and each leaf's observed value. AND and OR
// rows carry no result, as in the spec; the row above them does.
func (x *Explanation) Render(w io.Writer) error {
	var rows []line
	if x.LogSource != nil {
		rows = append(rows, line{indent: 2, label: "logsource", result: boolText(x.LogSource.Result)})
		// The logsource test is always a conjunction of equalities, so its
		// AND row adds nothing and the leaves sit directly under it.
		if x.LogSource.Op == OpAnd {
			for _, c := range x.LogSource.Children {
				rows = appendRows(rows, c, 4)
			}
		} else {
			rows = appendRows(rows, x.LogSource, 4)
		}
	}
	rows = appendRows(rows, x.Condition, 2)

	verdict := "NO MATCH"
	if x.Matched {
		verdict = "MATCH"
	}
	header := "rule  " + x.ruleName() + "  (" + x.ruleTitle() + ")"

	width := len(header)
	for _, r := range rows {
		if n := r.indent + utf8.RuneCountInString(r.label); n > width {
			width = n
		}
	}
	width += 2

	var b strings.Builder
	b.WriteString(pad(header, width) + "=> " + verdict + "\n")
	for _, r := range rows {
		s := strings.Repeat(" ", r.indent) + r.label
		if r.result != "" {
			s = pad(s, width) + r.result
			if r.value != "" {
				s = pad(s, width+7) + r.value
			}
		}
		b.WriteString(s + "\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func appendRows(rows []line, n *Node, indent int) []line {
	switch n.Op {
	case OpAnd, OpOr:
		label := "AND"
		if n.Op == OpOr {
			label = "OR"
		}
		rows = append(rows, line{indent: indent, label: label})
		for _, c := range n.Children {
			rows = appendRows(rows, c, indent+2)
		}
	case OpNot:
		child := n.Children[0]
		if child.Op == OpSelection {
			rows = append(rows, line{indent: indent, label: "NOT " + child.Name, result: boolText(n.Result)})
			rows = appendRows(rows, child.Children[0], indent+2)
			break
		}
		rows = append(rows, line{indent: indent, label: "NOT", result: boolText(n.Result)})
		rows = appendRows(rows, child, indent+2)
	case OpSelection:
		rows = append(rows, line{indent: indent, label: n.Name, result: boolText(n.Result)})
		rows = appendRows(rows, n.Children[0], indent+2)
	case OpPred:
		rows = append(rows, line{indent: indent, label: n.Pred.Desc, result: boolText(n.Result), value: observed(n)})
	}
	return rows
}

// observed renders the value a leaf read, naming the event field when the
// taxonomy renamed it, so "Image" in the rule and "NewProcessName" on the
// event are visibly the same thing.
func observed(n *Node) string {
	if n.Pred.Field == "" {
		return "(any field)"
	}
	var v string
	switch {
	case !n.Present:
		v = "absent"
	default:
		v = valueText(n.Observed)
	}
	if written := descField(n.Pred.Desc); written != n.Pred.Field {
		return "(" + n.Pred.Field + ": " + v + ")"
	}
	return "(" + v + ")"
}

// descField is the field name as the rule wrote it: the start of the
// detection key, before any modifier or value.
func descField(desc string) string {
	if i := strings.IndexAny(desc, "| "); i >= 0 {
		return desc[:i]
	}
	return desc
}

const maxValue = 40

func valueText(v event.Value) string {
	switch v.Kind {
	case event.KindNull:
		return "null"
	case event.KindString:
		s := escape(v.S)
		if utf8.RuneCountInString(s) > maxValue {
			s = string([]rune(s)[:maxValue-1]) + "..."
		}
		return `"` + s + `"`
	case event.KindList:
		parts := make([]string, len(v.L))
		for i, item := range v.L {
			parts[i] = valueText(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	s, _ := v.Text()
	return s
}

// escape keeps a value on one row. Backslashes stay as they are: a Windows
// path is the common case and doubling every separator would make it
// unreadable.
func escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func pad(s string, width int) string {
	if n := utf8.RuneCountInString(s); n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s + " "
}

func (x *Explanation) ruleName() string {
	base := filepath.Base(x.Rule.Path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

var technique = regexp.MustCompile(`^attack\.(t\d{4}(\.\d{3})?)$`)

// ruleTitle is "T1003.001 / title" when the rule carries an ATT&CK
// technique tag, the title alone otherwise, and the id if there is no title.
func (x *Explanation) ruleTitle() string {
	title := x.Rule.Title
	if title == "" {
		title = x.Rule.ID
	}
	for _, tag := range x.Rule.Tags {
		if m := technique.FindStringSubmatch(strings.ToLower(tag)); m != nil {
			return strings.ToUpper(m[1]) + " / " + title
		}
	}
	return title
}
