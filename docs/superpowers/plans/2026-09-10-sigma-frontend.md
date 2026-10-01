# Plan A: Sigma Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Sigma rule YAML into a bound, evaluable AST, with the event value model it evaluates against, and prove the semantics against an independent oracle.

**Architecture:** A lexer and precedence-climbing parser turn the `condition` string into an AST whose leaves are selection identifiers. Quantifiers (`1 of selection_*`) expand at parse time so the evaluator only ever sees AND, OR, NOT, and leaf predicates. The detection block compiles into predicate subtrees, which are then substituted for the identifiers. Taxonomy config binds abstract logsources to concrete field names and match criteria, and its content hash plus the rule set's content hash pin every verdict.

**Tech Stack:** Go 1.27, `gopkg.in/yaml.v3`, Go native fuzzing, Python 3 with pySigma as a subprocess oracle.

**Spec:** `docs/spec/signalman-v1.html`, phase 02 and the type definitions in phase 01. Roadmap: `docs/superpowers/plans/2026-09-10-signalman-roadmap.md`.

## Global Constraints

- Go 1.27. `go version` must report 1.27 or later before Task 1.
- Sigma string comparison is case insensitive by default. `|re` is case sensitive unless `|re|i`.
- A condition containing `|` means aggregation. Reject at load with rule ID, line number, and the phrase "aggregation is not supported".
- A logsource with no taxonomy entry is a load failure, not a rule that matches nothing.
- No dependence on Go map iteration order anywhere. Sort keys before building trees.
- Wildcards are matched by a purpose-built matcher, never by translating to regex.
- Logsource mismatch must be representable as an explicit `false`, so the logsource test stays separate from the condition tree.
- `gofmt -l .` empty, `go vet ./...` clean, `go test ./...` green before every commit.
- Conventional Commits. One branch and one PR per Jira story (`feat/SIG-<n>-<slug>`), opened with `/ship`. See Review amendments, Execution order.
- No emojis anywhere.

---

## Review amendments (2026-09-11)

Settled by `/office-hours` and `/plan-eng-review`; design record in `docs/designs/plan-a-sigma-frontend.md`. Where an amendment below disagrees with drafted code in a task, the amendment wins. Apply it when implementing that task, test first.

### Execution order

Tasks run corpus-first so the acceptance report and the fuzzer exist before the encoding and comparison modifiers are built. Nine branches, one per story.

| Step | Tasks | Story | Branch |
|---|---|---|---|
| 1 | 1 | S-10 / SIG-13 | `feat/SIG-13-event-value-model` |
| 2 | 5, 6, 9 (minimal) | S-12 / SIG-15 | `feat/SIG-15-wildcard-string-modifiers` |
| 3 | 2, 3, 4 | S-11 / SIG-14 | `feat/SIG-14-condition-parser` |
| 4 | 10 | S-14 / SIG-17 | `feat/SIG-17-detection-compile` |
| 5 | 11 | S-15 / SIG-18 | `feat/SIG-18-taxonomy` |
| 6 | 12 | S-16 / SIG-19 | `feat/SIG-19-rule-loader` |
| 7 | 13 | S-17 / SIG-20 | `feat/SIG-20-corpus-acceptance` |
| 8 | 14 | S-18 / SIG-21 | `feat/SIG-21-pysigma-fuzzer` |
| 9 | 7, 8, rest of 9, fuzz allowlist growth | S-13 / SIG-16 | `feat/SIG-16-encoding-modifiers` |

Step 2 ships `match.Build` handling `contains`, `startswith`, `endswith`, `re`, `i`, `all`, and null; every other modifier returns `ErrUnsupportedModifier`. Step 9 adds the remaining cases to the same function. Before the step 9 PR, edit `docs/backlog.yml`: S-13 `plan:` becomes "Plan A, Tasks 7, 8, rest of 9" and its windash acceptance line becomes every-dash expansion; run `make check-backlog`.

### Per-task amendments

**Task 1.** No `.gitignore` write (already fixed in the step above).

**Task 3 / ast.** Add `func Eval(n Node, ev *event.Event) bool`: the single tree walker for And, Or, Not, Pred; panics with the node type on Ident or Quant. Add `func Canonical(n Node) string` for hashing: same shape as `String` but every string is written with `%q` so quotes and separators cannot collide. `String` stays for explain output. Plan B's v1 may wrap `Eval` or reimplement it as its own obviously-correct walker; decide there.

**Task 6.** `escapeWildcards` counts the run of trailing backslashes and appends one when the count is odd. Table test: `a`, `a\`, `a\\`, `a\\\`, `a\\\\`.

**Task 7.** `WinDashVariants` matches pySigma and the spec: every `-` or `/` at a word boundary (`\B[-/]\b`) is replaced by each of the five dash characters, and the result is the cartesian product. Cap the number of dash positions at 5 (3125 variants) and return an error above it, surfaced as a `modifier` load error. Test `-nop -w hidden -enc` yields 125 variants and includes the all-slash and all-en-dash forms.

**Task 8.** Add tests for each of `lt`, `lte`, `gte` (only `gt` and `lt` are exercised in the draft).

**Task 9.** `var ErrUnsupportedModifier = errors.New("unsupported modifier")`; `Build` returns `fmt.Errorf("%w %q", ErrUnsupportedModifier, m)`. After collecting modifiers, validate the chain before building: transforms combined with `re`, `cidr`, `lt/lte/gt/gte`, or `fieldref` is an error; `i` without `re` is an error; two comparison modifiers is an error. All wrap `ErrUnsupportedModifier`. Table test of bad chains plus a test that `errors.Is(err, ErrUnsupportedModifier)` holds.

**Task 10.** Keywords stay `Contains` over every field value; this is a deliberate, documented deviation from the spec's whole-value reading (row in `KNOWN_DIVERGENCES.md`). Use `ast.Eval` in tests; delete `walkForTest`. Add a test that `toValue` rejects an unsupported YAML type with an error naming the type.

**Task 11.** `Resolve` is an exact match on all three components, blank equal to blank; no rule-side wildcard. `LoadTaxonomy` rejects two entries with the same logsource with an error naming both files. `LogSourceMatcher.Matches` calls `ast.Eval`; delete `walkNode`. Tests: a second windows entry with a different category resolves independently; duplicate logsource fails to load; TaxonomyV changes when one match value in a `t.TempDir` copy of the fixtures changes.

**Task 12.** Classify the `modifier` code with `errors.Is(err, match.ErrUnsupportedModifier)`, never by error text. Accept `condition` as a YAML list of strings: parse each, wrap in `ast.Or`; any other type is a `condition` error naming the type. `LoadRuleSet` rejects the second file carrying an already-seen `id` with code `duplicate-id`, naming both paths. `RuleSetV` hashes `r.ID` and `ast.Canonical(r.Cond)`. Add `LoadRuleBytes(path string, src []byte, tax *Taxonomy) (*Rule, *LoadError)`; `LoadRule` reads the file and calls it. Fixtures and tests: list-form condition, duplicate id, missing id, malformed yaml, RuleSetV changes when a rule value changes and when TaxonomyV changes.

**Task 13.** The corpus test loads all of `corpora/sigmahq/rules`, walks the tree for the file count, and skips under `testing.Short()`. Log the corpus commit SHA (`git -C corpora/sigmahq rev-parse HEAD`) and record it in `docs/corpus-acceptance.md` with each run.

**Task 14.** Rewrite the bridge:
- `EvalOnce` uses `LoadRuleBytes` (no temp file) and does not gate on the logsource; the fuzzer tests condition semantics, the taxonomy has its own tests.
- `pysigma_eval.py` builds the table from the union of the rule's field names (pySigma exposes them from the parsed detection) and the event's keys, so an absent field is NULL, not "no such column". Columns are typed: INTEGER for ints, TEXT COLLATE NOCASE for strings, NULL for null. Bools have no natural SQLite type; Go renders them as the text `true`/`false`, so decide the column type (TEXT of that form, or INTEGER 0/1 with the rule value coerced the same way) before the first fuzz run and record it in `KNOWN_DIVERGENCES.md`. Register a `REGEXP` function via `create_function` using Python `re.search`. Verify the NOCASE behavior against `=` and `LIKE` empirically on the first run; adjust and document.
- Events are typed: the Go side generates `map[string]event.Value` and sends JSON with native ints, bools, nulls, and strings.
- The fuzz target uses the fuzz bytes to seed a structured generator (field name, modifier chain from an allowlist, value, event) rather than mutating raw YAML. The allowlist starts as the step 2 modifier set and grows in step 9.
- `known()` gains rows for: oracle cannot evaluate keyword lists (`NotImplementedError`), Python `re` vs Go RE2 syntax differences, and the keyword `Contains` deviation. Every row has a section in `KNOWN_DIVERGENCES.md`.
- Python discovery: `$SIGNALMAN_PYTHON`, falling back to `test/fuzz/.venv/bin/python`. When `CI=true` a missing oracle is `f.Fatal`, not `f.Skip`. `test/fuzz/requirements.txt` pins `pysigma` and `pysigma-backend-sqlite` to exact versions; `.github/workflows/nightly.yml` installs from it and sets `SIGNALMAN_PYTHON=python3` (run `/cso` for the workflow edit).
- Restrict generated strings to ASCII, since SQLite NOCASE is ASCII-only and Go's `ToLower` is not.

### Test additions not tied to a fix

- `internal/event`: `Event.Field` on an absent name returns a value of `KindNull`.
- `internal/sigma`: parser depth cap test, `strings.Repeat("(", 200) + "a" + strings.Repeat(")", 200)` returns an error, not a stack overflow.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/event/value.go` | `Value` sum type, constructors, canonical text form |
| `internal/event/event.go` | `Event`, `Verdict`, field lookup |
| `internal/sigma/ast/ast.go` | Node types: `And`, `Or`, `Not`, `Ident`, `Quant`, `Pred`, `Matcher` interface |
| `internal/sigma/lexer.go` | Condition tokenizer |
| `internal/sigma/parser.go` | Precedence-climbing parser, produces a tree with `Ident` and `Quant` leaves |
| `internal/sigma/expand.go` | Quantifier expansion against the set of selection names |
| `internal/sigma/match/wildcard.go` | Case-insensitive `*` and `?` matcher with escapes |
| `internal/sigma/match/string.go` | equals, contains, startswith, endswith, re |
| `internal/sigma/match/encode.go` | utf16le, utf16be, wide, base64, base64offset, windash |
| `internal/sigma/match/compare.go` | lt, lte, gt, gte, cidr, fieldref, null |
| `internal/sigma/match/build.go` | Modifier chain to `Matcher`, list combination |
| `internal/sigma/detection.go` | Detection block to predicate subtrees |
| `internal/sigma/rule.go` | Rule YAML to `Rule`, aggregation rejection, identifier binding |
| `internal/sigma/taxonomy.go` | Taxonomy loading, logsource resolution, field renaming, `TaxonomyV` |
| `internal/sigma/ruleset.go` | Directory load, `RuleSetV`, structured load errors |
| `test/fuzz/differential_test.go` | pySigma differential fuzzer |
| `test/fuzz/pysigma_eval.py` | Oracle subprocess |
| `cmd/corpusaccept/main.go` | SigmaHQ acceptance report |

`match` does not import `ast`. The `Matcher` interface is satisfied structurally, so the dependency runs one way: `sigma` imports both `ast` and `match`; both import `event`.

---

### Task 1: Module scaffold and the event value model

**Files:**
- Create: `go.mod`, `.gitignore`, `internal/event/value.go`, `internal/event/event.go`
- Test: `internal/event/value_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `event.Value` with `Kind ValueKind` and fields `S string`, `I int64`, `B bool`, `L []Value`; constructors `event.String(string) Value`, `event.Int(int64) Value`, `event.Bool(bool) Value`, `event.Null() Value`, `event.List(...Value) Value`; method `(Value) Text() (string, bool)`; `event.Event` with `Seq uint64`, `Partition int32`, `Source string`, `EventTime`, `IngestAt time.Time`, `Fields map[string]Value`, `Raw []byte`; `event.Verdict` with `Seq`, `Partition`, `RuleID`, `Matched`, `Engine`, `RuleSetV`, `TaxonomyV`.

- [ ] **Step 1: Initialize the module and branch**

```bash
cd /Users/advaithtontalapur/Documents/Projects/signalman
git checkout -b feat/SIG-13-event-value-model
go mod init github.com/atontalapur/signalman
```

`.gitignore` already exists and already covers `bin/`, `corpora/`, `*.test`, and `.venv/`. Do not recreate it.

- [ ] **Step 2: Write the failing test**

Create `internal/event/value_test.go`:

```go
package event

import "testing"

func TestValueText(t *testing.T) {
	cases := []struct {
		name string
		in   Value
		want string
		ok   bool
	}{
		{"string", String("abc"), "abc", true},
		{"empty string", String(""), "", true},
		{"int", Int(1234), "1234", true},
		{"negative int", Int(-7), "-7", true},
		{"bool true", Bool(true), "true", true},
		{"bool false", Bool(false), "false", true},
		{"null has no text", Null(), "", false},
		{"list has no text", List(String("a")), "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := c.in.Text()
			if ok != c.ok || got != c.want {
				t.Fatalf("Text() = %q,%v want %q,%v", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestNullIsDistinctFromEmptyString(t *testing.T) {
	if Null().Kind == String("").Kind {
		t.Fatal("null and empty string must have different kinds")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/event/`
Expected: FAIL, undefined: String, Int, Bool, Null, List.

- [ ] **Step 4: Write the implementation**

Create `internal/event/value.go`:

```go
// Package event defines the unit of work that flows through the pipeline
// and the verdict that every engine emits for it.
package event

import "strconv"

type ValueKind uint8

const (
	KindNull ValueKind = iota
	KindString
	KindInt
	KindBool
	KindList
)

// Value is a closed sum type. Sigma comparison semantics differ per kind,
// so the kind is carried explicitly rather than inferred.
type Value struct {
	Kind ValueKind
	S    string
	I    int64
	B    bool
	L    []Value
}

func String(s string) Value  { return Value{Kind: KindString, S: s} }
func Int(i int64) Value      { return Value{Kind: KindInt, I: i} }
func Bool(b bool) Value      { return Value{Kind: KindBool, B: b} }
func Null() Value            { return Value{Kind: KindNull} }
func List(vs ...Value) Value { return Value{Kind: KindList, L: vs} }

// Text returns the canonical string form used for Sigma string comparison.
// Null and list values have no such form and report false.
func (v Value) Text() (string, bool) {
	switch v.Kind {
	case KindString:
		return v.S, true
	case KindInt:
		return strconv.FormatInt(v.I, 10), true
	case KindBool:
		return strconv.FormatBool(v.B), true
	default:
		return "", false
	}
}
```

Create `internal/event/event.go`:

```go
package event

import "time"

// Event is the unit of work. Seq is assigned once, at ingest, and is
// monotonic within a partition. Everything downstream is keyed on it.
type Event struct {
	Seq       uint64
	Partition int32
	Source    string
	EventTime time.Time
	IngestAt  time.Time
	Fields    map[string]Value
	Raw       []byte
}

// Field returns the named field. An absent field reads as null, which is
// what makes "field: null" match both absence and an explicit null.
func (e *Event) Field(name string) Value {
	if v, ok := e.Fields[name]; ok {
		return v
	}
	return Null()
}

// Verdict is the equivalence unit. One per (event, enabled rule).
type Verdict struct {
	Seq       uint64
	Partition int32
	RuleID    string
	Matched   bool
	Engine    string
	RuleSetV  string
	TaxonomyV string
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/event/ -v`
Expected: PASS for both tests.

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./...
git add go.mod internal/event
git commit -m "feat(event): add value model, event, and verdict types"
```

---

### Task 2: Condition lexer

**Files:**
- Create: `internal/sigma/lexer.go`
- Test: `internal/sigma/lexer_test.go`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: unexported `token{kind tokenKind, text string, pos int}`, `tokenKind` constants `tokEOF, tokIdent, tokAnd, tokOr, tokNot, tokOf, tokLParen, tokRParen`, and `func lex(s string) ([]token, error)`. `ErrAggregation` is exported so the rule loader can classify it.

- [ ] **Step 1: Write the failing test**

Create `internal/sigma/lexer_test.go`:

```go
package sigma

import (
	"errors"
	"testing"
)

func kinds(ts []token) []tokenKind {
	out := make([]tokenKind, len(ts))
	for i, t := range ts {
		out[i] = t.kind
	}
	return out
}

func TestLexBasic(t *testing.T) {
	got, err := lex("selection and not (filter1 or filter2)")
	if err != nil {
		t.Fatalf("lex: %v", err)
	}
	want := []tokenKind{
		tokIdent, tokAnd, tokNot, tokLParen,
		tokIdent, tokOr, tokIdent, tokRParen, tokEOF,
	}
	g := kinds(got)
	if len(g) != len(want) {
		t.Fatalf("got %v want %v", g, want)
	}
	for i := range want {
		if g[i] != want[i] {
			t.Fatalf("token %d: got %v want %v", i, g[i], want[i])
		}
	}
}

func TestLexQuantifierAndGlob(t *testing.T) {
	got, err := lex("1 of selection_* and all of them")
	if err != nil {
		t.Fatalf("lex: %v", err)
	}
	want := []tokenKind{
		tokIdent, tokOf, tokIdent, tokAnd, tokIdent, tokOf, tokIdent, tokEOF,
	}
	g := kinds(got)
	for i := range want {
		if g[i] != want[i] {
			t.Fatalf("token %d: got %v want %v", i, g[i], want[i])
		}
	}
	if got[2].text != "selection_*" {
		t.Fatalf("glob text = %q want selection_*", got[2].text)
	}
}

func TestLexKeywordsAreCaseInsensitive(t *testing.T) {
	got, _ := lex("a AND b OR NOT c")
	want := []tokenKind{tokIdent, tokAnd, tokIdent, tokOr, tokNot, tokIdent, tokEOF}
	g := kinds(got)
	for i := range want {
		if g[i] != want[i] {
			t.Fatalf("token %d: got %v want %v", i, g[i], want[i])
		}
	}
}

func TestLexPipeIsAggregation(t *testing.T) {
	_, err := lex("selection | count() > 5 by User")
	if !errors.Is(err, ErrAggregation) {
		t.Fatalf("err = %v want ErrAggregation", err)
	}
}

func TestLexRejectsUnknownRune(t *testing.T) {
	if _, err := lex("selection & filter"); err == nil {
		t.Fatal("expected error on '&'")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sigma/`
Expected: FAIL, undefined: lex, token, tokenKind, ErrAggregation.

- [ ] **Step 3: Write the implementation**

Create `internal/sigma/lexer.go`:

```go
// Package sigma parses Sigma rules into an evaluable AST.
package sigma

import (
	"errors"
	"fmt"
	"strings"
)

// ErrAggregation reports a condition that uses the aggregation pipe. The
// engine cannot evaluate these, and skipping them silently would be a
// missed detection with no signal attached, so loading fails loudly.
var ErrAggregation = errors.New("aggregation is not supported")

type tokenKind uint8

const (
	tokEOF tokenKind = iota
	tokIdent
	tokAnd
	tokOr
	tokNot
	tokOf
	tokLParen
	tokRParen
)

func (k tokenKind) String() string {
	switch k {
	case tokEOF:
		return "end of condition"
	case tokIdent:
		return "identifier"
	case tokAnd:
		return "and"
	case tokOr:
		return "or"
	case tokNot:
		return "not"
	case tokOf:
		return "of"
	case tokLParen:
		return "("
	case tokRParen:
		return ")"
	}
	return "unknown"
}

type token struct {
	kind tokenKind
	text string
	pos  int
}

func isIdentRune(r byte) bool {
	return r == '_' || r == '*' || r == '-' || r == '.' ||
		(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func lex(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			out = append(out, token{tokLParen, "(", i})
			i++
		case c == ')':
			out = append(out, token{tokRParen, ")", i})
			i++
		case c == '|':
			return nil, fmt.Errorf("at offset %d: %w", i, ErrAggregation)
		case isIdentRune(c):
			start := i
			for i < len(s) && isIdentRune(s[i]) {
				i++
			}
			text := s[start:i]
			out = append(out, token{keywordKind(text), text, start})
		default:
			return nil, fmt.Errorf("unexpected character %q at offset %d", string(c), i)
		}
	}
	out = append(out, token{tokEOF, "", len(s)})
	return out, nil
}

func keywordKind(text string) tokenKind {
	switch strings.ToLower(text) {
	case "and":
		return tokAnd
	case "or":
		return tokOr
	case "not":
		return tokNot
	case "of":
		return tokOf
	}
	return tokIdent
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sigma/ -v`
Expected: PASS, five tests.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/sigma/lexer.go internal/sigma/lexer_test.go
git commit -m "feat(sigma): add condition lexer with loud aggregation rejection"
```

---

### Task 3: AST node types and the parser

**Files:**
- Create: `internal/sigma/ast/ast.go`, `internal/sigma/parser.go`
- Test: `internal/sigma/parser_test.go`

**Interfaces:**
- Consumes: `lex`, `token`, `tokenKind` from Task 2; `event.Event`, `event.Value` from Task 1.
- Produces:
  - `ast.Node` interface with unexported marker method.
  - `ast.And{Children []Node}`, `ast.Or{Children []Node}`, `ast.Not{Child Node}`.
  - `ast.Ident{Name string}`, `ast.Quant{Count QuantCount, Pattern string, Them bool}` with `ast.QuantOne` and `ast.QuantAll`.
  - `ast.Matcher` interface: `Match(v event.Value, ev *event.Event) bool`.
  - `ast.Pred{Field string, Desc string, M Matcher}` with method `Match(ev *event.Event) bool`.
  - `ast.String(n Node) string` for stable test assertions and for `signalman explain` later.
  - `func ParseCondition(s string) (ast.Node, error)` in package `sigma`.

- [ ] **Step 1: Write the failing test**

Create `internal/sigma/parser_test.go`:

```go
package sigma

import (
	"errors"
	"testing"

	"github.com/atontalapur/signalman/internal/sigma/ast"
)

func TestParsePrecedence(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a", "a"},
		{"a and b", "(and a b)"},
		{"a or b and c", "(or a (and b c))"},
		{"(a or b) and c", "(and (or a b) c)"},
		{"not a and b", "(and (not a) b)"},
		{"a and not (b or c)", "(and a (not (or b c)))"},
		{"a and b and c", "(and a b c)"},
		{"1 of selection_*", "(1of selection_*)"},
		{"all of them", "(allof them)"},
		{"any of filter*", "(1of filter*)"},
		{"1 of selection_* and not all of filter_*", "(and (1of selection_*) (not (allof filter_*)))"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			n, err := ParseCondition(c.in)
			if err != nil {
				t.Fatalf("parse %q: %v", c.in, err)
			}
			if got := ast.String(n); got != c.want {
				t.Fatalf("parse %q = %s want %s", c.in, got, c.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "a and", "(a", "a b", "and a", "1 of", "of them", ")"} {
		if _, err := ParseCondition(in); err == nil {
			t.Fatalf("expected error parsing %q", in)
		}
	}
}

func TestParseAggregationPropagates(t *testing.T) {
	_, err := ParseCondition("selection | count() > 5")
	if !errors.Is(err, ErrAggregation) {
		t.Fatalf("err = %v want ErrAggregation", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sigma/`
Expected: FAIL, no package `ast`, undefined `ParseCondition`.

- [ ] **Step 3: Write the AST**

Create `internal/sigma/ast/ast.go`:

```go
// Package ast holds the evaluable rule tree. After binding, a tree contains
// only And, Or, Not, and Pred. Ident and Quant exist between parsing and
// expansion and never reach an evaluator.
package ast

import (
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/event"
)

type Node interface{ node() }

type And struct{ Children []Node }
type Or struct{ Children []Node }
type Not struct{ Child Node }
type Ident struct{ Name string }

type QuantCount uint8

const (
	QuantOne QuantCount = iota // "1" and "any"
	QuantAll
)

type Quant struct {
	Count   QuantCount
	Pattern string // selection name glob, empty when Them is set
	Them    bool
}

// Matcher tests one field value. The event is passed because fieldref
// compares two fields on the same event.
type Matcher interface {
	Match(v event.Value, ev *event.Event) bool
}

// Pred is a leaf. Desc is the human-readable form used by explain output.
type Pred struct {
	Field string
	Desc  string
	M     Matcher
}

func (*And) node()   {}
func (*Or) node()    {}
func (*Not) node()   {}
func (*Ident) node() {}
func (*Quant) node() {}
func (*Pred) node()  {}

// Match reads the field, treating absence as null so that a null matcher
// matches both an absent field and an explicit null.
func (p *Pred) Match(ev *event.Event) bool {
	return p.M.Match(ev.Field(p.Field), ev)
}

// String renders a node in a stable s-expression form. Used by tests and by
// the explain command. It never sorts children, because child order is
// already deterministic by construction.
func String(n Node) string {
	var b strings.Builder
	write(&b, n)
	return b.String()
}

func write(b *strings.Builder, n Node) {
	switch n := n.(type) {
	case *And:
		writeList(b, "and", n.Children)
	case *Or:
		writeList(b, "or", n.Children)
	case *Not:
		b.WriteString("(not ")
		write(b, n.Child)
		b.WriteString(")")
	case *Ident:
		b.WriteString(n.Name)
	case *Quant:
		if n.Count == QuantAll {
			b.WriteString("(allof ")
		} else {
			b.WriteString("(1of ")
		}
		if n.Them {
			b.WriteString("them")
		} else {
			b.WriteString(n.Pattern)
		}
		b.WriteString(")")
	case *Pred:
		b.WriteString("[" + n.Desc + "]")
	default:
		b.WriteString("?")
	}
}

func writeList(b *strings.Builder, op string, kids []Node) {
	b.WriteString("(" + op)
	for _, k := range kids {
		b.WriteString(" ")
		write(b, k)
	}
	b.WriteString(")")
}

// SortedNames returns map keys in a fixed order. Every tree construction
// path uses it, because Go map iteration order would otherwise leak into
// the shape of the tree and break determinism.
func SortedNames(m map[string]Node) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
```

- [ ] **Step 4: Write the parser**

Create `internal/sigma/parser.go`:

```go
package sigma

import (
	"fmt"
	"strings"

	"github.com/atontalapur/signalman/internal/sigma/ast"
)

type parser struct {
	toks []token
	i    int
}

// ParseCondition parses a Sigma condition string. The result contains Ident
// and Quant leaves; expansion and binding replace them.
func ParseCondition(s string) (ast.Node, error) {
	toks, err := lex(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected %s at offset %d", p.peek().kind, p.peek().pos)
	}
	return n, nil
}

func (p *parser) peek() token { return p.toks[p.i] }

func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tokEOF {
		p.i++
	}
	return t
}

func (p *parser) parseOr() (ast.Node, error) {
	first, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	kids := []ast.Node{first}
	for p.peek().kind == tokOr {
		p.next()
		n, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		kids = append(kids, n)
	}
	if len(kids) == 1 {
		return first, nil
	}
	return &ast.Or{Children: kids}, nil
}

func (p *parser) parseAnd() (ast.Node, error) {
	first, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	kids := []ast.Node{first}
	for p.peek().kind == tokAnd {
		p.next()
		n, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		kids = append(kids, n)
	}
	if len(kids) == 1 {
		return first, nil
	}
	return &ast.And{Children: kids}, nil
}

func (p *parser) parseNot() (ast.Node, error) {
	if p.peek().kind == tokNot {
		p.next()
		child, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &ast.Not{Child: child}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (ast.Node, error) {
	t := p.peek()
	switch t.kind {
	case tokLParen:
		p.next()
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("missing ) at offset %d", p.peek().pos)
		}
		p.next()
		return n, nil
	case tokIdent:
		p.next()
		if p.peek().kind == tokOf {
			return p.parseQuant(t)
		}
		return &ast.Ident{Name: t.text}, nil
	default:
		return nil, fmt.Errorf("unexpected %s at offset %d", t.kind, t.pos)
	}
}

// parseQuant handles "1 of x", "any of x", "all of x", and "... of them".
// count has already been consumed as an identifier.
func (p *parser) parseQuant(count token) (ast.Node, error) {
	var c ast.QuantCount
	switch strings.ToLower(count.text) {
	case "1", "any":
		c = ast.QuantOne
	case "all":
		c = ast.QuantAll
	default:
		return nil, fmt.Errorf("unsupported quantifier %q at offset %d: only 1, any, and all are defined", count.text, count.pos)
	}
	p.next() // consume "of"
	target := p.peek()
	if target.kind != tokIdent {
		return nil, fmt.Errorf("expected a selection pattern or 'them' after 'of' at offset %d", target.pos)
	}
	p.next()
	if strings.EqualFold(target.text, "them") {
		return &ast.Quant{Count: c, Them: true}, nil
	}
	return &ast.Quant{Count: c, Pattern: target.text}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/sigma/ -run 'TestParse|TestLex' -v`
Expected: PASS. If `TestParseErrors` fails on `"1 of"`, check that `parseQuant` rejects a `tokEOF` target.

- [ ] **Step 6: Add the parser fuzzer with no oracle**

Append to `internal/sigma/parser_test.go`:

```go
func FuzzParseCondition(f *testing.F) {
	for _, s := range []string{
		"a", "a and b", "not (a or b)", "1 of selection_*", "all of them",
		"((((a))))", "a and not b or c",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// The only contract is that no input panics and none recurses
		// without bound. Errors are fine.
		_, _ = ParseCondition(s)
	})
}
```

- [ ] **Step 7: Run the fuzzer briefly**

Run: `go test ./internal/sigma/ -run FuzzParseCondition -fuzz FuzzParseCondition -fuzztime 60s`
Expected: no crashers. A stack overflow on deeply nested parens means `parseNot` and `parseOr` need a depth counter capped at 100 returning an error. Add it if the fuzzer finds it.

- [ ] **Step 8: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/sigma/ast internal/sigma/parser.go internal/sigma/parser_test.go
git commit -m "feat(sigma): add AST and precedence-climbing condition parser"
```

---

### Task 4: Quantifier expansion

**Files:**
- Create: `internal/sigma/expand.go`
- Test: `internal/sigma/expand_test.go`

**Interfaces:**
- Consumes: `ast.Node`, `ast.Quant`, `ast.Ident`, `ParseCondition`.
- Produces: `func Expand(n ast.Node, names []string) (ast.Node, error)`. `names` is the set of selection identifiers defined in the rule's detection block. The result contains no `Quant` nodes. An `Ident` naming an unknown selection is an error.

- [ ] **Step 1: Write the failing test**

Create `internal/sigma/expand_test.go`:

```go
package sigma

import (
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/sigma/ast"
)

func expandStr(t *testing.T, cond string, names ...string) string {
	t.Helper()
	n, err := ParseCondition(cond)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	e, err := Expand(n, names)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	return ast.String(e)
}

func TestExpandQuantifiers(t *testing.T) {
	names := []string{"filter_a", "filter_b", "selection_1", "selection_2"}
	cases := []struct{ cond, want string }{
		{"1 of selection_*", "(or selection_1 selection_2)"},
		{"all of selection_*", "(and selection_1 selection_2)"},
		{"all of them", "(and filter_a filter_b selection_1 selection_2)"},
		{"1 of them", "(or filter_a filter_b selection_1 selection_2)"},
		{"selection_1 and not 1 of filter_*", "(and selection_1 (not (or filter_a filter_b)))"},
	}
	for _, c := range cases {
		t.Run(c.cond, func(t *testing.T) {
			if got := expandStr(t, c.cond, names...); got != c.want {
				t.Fatalf("expand %q = %s want %s", c.cond, got, c.want)
			}
		})
	}
}

func TestExpandSingleMatchCollapses(t *testing.T) {
	if got := expandStr(t, "1 of selection_*", "selection_1"); got != "selection_1" {
		t.Fatalf("got %s want selection_1", got)
	}
}

func TestExpandIsOrderIndependent(t *testing.T) {
	a := expandStr(t, "all of them", "b", "a", "c")
	b := expandStr(t, "all of them", "c", "b", "a")
	if a != b {
		t.Fatalf("expansion depends on input order: %s vs %s", a, b)
	}
}

func TestExpandErrors(t *testing.T) {
	n, _ := ParseCondition("1 of nomatch_*")
	if _, err := Expand(n, []string{"selection"}); err == nil ||
		!strings.Contains(err.Error(), "nomatch_*") {
		t.Fatalf("expected an error naming the pattern, got %v", err)
	}
	n2, _ := ParseCondition("undefined_selection")
	if _, err := Expand(n2, []string{"selection"}); err == nil {
		t.Fatal("expected an error for an undefined selection name")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sigma/ -run TestExpand`
Expected: FAIL, undefined: Expand.

- [ ] **Step 3: Write the implementation**

Create `internal/sigma/expand.go`:

```go
package sigma

import (
	"fmt"
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/sigma/ast"
)

// Expand resolves quantifiers into plain boolean nodes and verifies that
// every identifier names a defined selection. Doing this at parse time
// means an evaluator only ever sees And, Or, Not, and Pred.
//
// names is copied and sorted, so the caller's order cannot affect the
// resulting tree.
func Expand(n ast.Node, names []string) (ast.Node, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	defined := make(map[string]bool, len(sorted))
	for _, s := range sorted {
		defined[s] = true
	}
	return expand(n, sorted, defined)
}

func expand(n ast.Node, sorted []string, defined map[string]bool) (ast.Node, error) {
	switch n := n.(type) {
	case *ast.And:
		kids, err := expandAll(n.Children, sorted, defined)
		if err != nil {
			return nil, err
		}
		return &ast.And{Children: kids}, nil
	case *ast.Or:
		kids, err := expandAll(n.Children, sorted, defined)
		if err != nil {
			return nil, err
		}
		return &ast.Or{Children: kids}, nil
	case *ast.Not:
		c, err := expand(n.Child, sorted, defined)
		if err != nil {
			return nil, err
		}
		return &ast.Not{Child: c}, nil
	case *ast.Ident:
		if !defined[n.Name] {
			return nil, fmt.Errorf("condition refers to %q, which is not defined in the detection block", n.Name)
		}
		return n, nil
	case *ast.Quant:
		return expandQuant(n, sorted)
	}
	return nil, fmt.Errorf("unexpected node %T in expansion", n)
}

func expandAll(in []ast.Node, sorted []string, defined map[string]bool) ([]ast.Node, error) {
	out := make([]ast.Node, len(in))
	for i, c := range in {
		e, err := expand(c, sorted, defined)
		if err != nil {
			return nil, err
		}
		out[i] = e
	}
	return out, nil
}

func expandQuant(q *ast.Quant, sorted []string) (ast.Node, error) {
	var picked []ast.Node
	for _, name := range sorted {
		if q.Them || matchSelectionGlob(q.Pattern, name) {
			picked = append(picked, &ast.Ident{Name: name})
		}
	}
	if len(picked) == 0 {
		target := q.Pattern
		if q.Them {
			target = "them"
		}
		return nil, fmt.Errorf("quantifier over %q matches no selection in the detection block", target)
	}
	if len(picked) == 1 {
		return picked[0], nil
	}
	if q.Count == ast.QuantAll {
		return &ast.And{Children: picked}, nil
	}
	return &ast.Or{Children: picked}, nil
}

// matchSelectionGlob implements the prefix glob in the condition grammar:
// an identifier optionally ending in a single star.
func matchSelectionGlob(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sigma/ -run TestExpand -v`
Expected: PASS, four tests.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/sigma/expand.go internal/sigma/expand_test.go
git commit -m "feat(sigma): expand quantifiers at parse time"
```

---

### Task 5: Wildcard matcher

**Files:**
- Create: `internal/sigma/match/wildcard.go`
- Test: `internal/sigma/match/wildcard_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `match.Wildcard` with `func CompileWildcard(pattern string) *Wildcard`, method `(w *Wildcard) MatchString(s string) bool`, and `func HasWildcard(pattern string) bool`. Matching is case insensitive. `*` matches any run including empty, `?` matches exactly one character, and `\*`, `\?`, `\\` are literals.

- [ ] **Step 1: Write the failing test**

Create `internal/sigma/match/wildcard_test.go`:

```go
package match

import "testing"

func TestWildcard(t *testing.T) {
	cases := []struct {
		pat, in string
		want    bool
	}{
		{"abc", "abc", true},
		{"abc", "ABC", true},
		{"abc", "abcd", false},
		{"*abc", "xxabc", true},
		{"abc*", "abcxx", true},
		{"*abc*", "xxabcxx", true},
		{"*", "", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{`a\*c`, "a*c", true},
		{`a\*c`, "abc", false},
		{`a\\c`, `a\c`, true},
		{`C:\Windows\*\rundll32.exe`, `C:\Windows\System32\rundll32.exe`, true},
		{"*.*.*.*", "1.2.3.4", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXcYYb", false},
		// A regex metacharacter is a literal here. This is the reason the
		// matcher exists instead of a translation to regex.
		{"cmd.exe (x86)", "cmd.exe (x86)", true},
		{"c+d", "ccccd", false},
	}
	for _, c := range cases {
		t.Run(c.pat+"|"+c.in, func(t *testing.T) {
			if got := CompileWildcard(c.pat).MatchString(c.in); got != c.want {
				t.Fatalf("CompileWildcard(%q).MatchString(%q) = %v want %v", c.pat, c.in, got, c.want)
			}
		})
	}
}

func TestHasWildcard(t *testing.T) {
	if !HasWildcard("a*b") || !HasWildcard("a?b") {
		t.Fatal("expected wildcards to be detected")
	}
	if HasWildcard(`a\*b`) || HasWildcard("ab") {
		t.Fatal("escaped star and plain text are not wildcards")
	}
}

func FuzzWildcard(f *testing.F) {
	f.Add("a*b", "aXb")
	f.Add(`a\*b`, "a*b")
	f.Fuzz(func(t *testing.T, pat, in string) {
		_ = CompileWildcard(pat).MatchString(in)
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sigma/match/`
Expected: FAIL, undefined: CompileWildcard, HasWildcard.

- [ ] **Step 3: Write the implementation**

Create `internal/sigma/match/wildcard.go`:

```go
// Package match implements Sigma value comparison. Wildcards are matched
// directly rather than translated to regex, because Windows command lines
// are full of regex metacharacters and the naive translation of * to .*
// changes the meaning of the pattern.
package match

import "strings"

type tokenClass uint8

const (
	classLiteral tokenClass = iota
	classAny            // *
	classOne            // ?
)

type wtok struct {
	class tokenClass
	r     rune
}

type Wildcard struct {
	toks []wtok
	// exact is set when the pattern has no wildcards, which is the common
	// case and lets MatchString short circuit to a case-insensitive compare.
	exact string
	plain bool
}

// CompileWildcard parses a Sigma wildcard pattern. Escapes are \*, \?, and
// \\. A backslash before anything else is a literal backslash, which is what
// Windows paths in the rule corpus rely on.
func CompileWildcard(pattern string) *Wildcard {
	w := &Wildcard{plain: true}
	rs := []rune(strings.ToLower(pattern))
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '\\':
			if i+1 < len(rs) && (rs[i+1] == '*' || rs[i+1] == '?' || rs[i+1] == '\\') {
				i++
				w.toks = append(w.toks, wtok{classLiteral, rs[i]})
			} else {
				w.toks = append(w.toks, wtok{classLiteral, '\\'})
			}
		case '*':
			w.plain = false
			w.toks = append(w.toks, wtok{class: classAny})
		case '?':
			w.plain = false
			w.toks = append(w.toks, wtok{class: classOne})
		default:
			w.toks = append(w.toks, wtok{classLiteral, rs[i]})
		}
	}
	if w.plain {
		var b strings.Builder
		for _, t := range w.toks {
			b.WriteRune(t.r)
		}
		w.exact = b.String()
	}
	return w
}

// HasWildcard reports whether the pattern contains an unescaped * or ?.
func HasWildcard(pattern string) bool {
	return !CompileWildcard(pattern).plain
}

// MatchString runs the classic linear-backtracking wildcard match over the
// lowercased input. The star pointer means backtracking is bounded by the
// number of stars rather than exponential.
func (w *Wildcard) MatchString(s string) bool {
	low := strings.ToLower(s)
	if w.plain {
		return low == w.exact
	}
	in := []rune(low)
	ti, si := 0, 0
	starT, starS := -1, 0
	for si < len(in) {
		switch {
		case ti < len(w.toks) && w.toks[ti].class == classOne:
			ti++
			si++
		case ti < len(w.toks) && w.toks[ti].class == classLiteral && w.toks[ti].r == in[si]:
			ti++
			si++
		case ti < len(w.toks) && w.toks[ti].class == classAny:
			starT, starS = ti, si
			ti++
		case starT >= 0:
			ti = starT + 1
			starS++
			si = starS
		default:
			return false
		}
	}
	for ti < len(w.toks) && w.toks[ti].class == classAny {
		ti++
	}
	return ti == len(w.toks)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sigma/match/ -v`
Expected: PASS.

- [ ] **Step 5: Fuzz for panics**

Run: `go test ./internal/sigma/match/ -run FuzzWildcard -fuzz FuzzWildcard -fuzztime 60s`
Expected: no crashers.

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/sigma/match
git commit -m "feat(match): add case-insensitive wildcard matcher without regex"
```

---

### Task 6: Core string modifiers

**Files:**
- Create: `internal/sigma/match/string.go`
- Test: `internal/sigma/match/string_test.go`

**Interfaces:**
- Consumes: `Wildcard` from Task 5, `event.Value`, `event.Event`.
- Produces: matcher constructors, each returning a type satisfying `Match(v event.Value, ev *event.Event) bool`:
  - `func Equals(pattern string) Matcher` (wildcard-aware, case insensitive)
  - `func Contains(sub string) Matcher`
  - `func StartsWith(prefix string) Matcher`
  - `func EndsWith(suffix string) Matcher`
  - `func Regex(pattern string, caseInsensitive bool) (Matcher, error)`
  - `func Null() Matcher`
  - `func Any(ms []Matcher) Matcher`, `func All(ms []Matcher) Matcher`
  - Local interface `Matcher` declared in this package with the same method set as `ast.Matcher`.

- [ ] **Step 1: Write the failing test**

Create `internal/sigma/match/string_test.go`:

```go
package match

import (
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

func hit(t *testing.T, m Matcher, v event.Value) bool {
	t.Helper()
	return m.Match(v, &event.Event{Fields: map[string]event.Value{}})
}

func TestStringMatchersAreCaseInsensitive(t *testing.T) {
	if !hit(t, Equals("PowerShell.exe"), event.String("powershell.EXE")) {
		t.Fatal("equals must fold case")
	}
	if !hit(t, Contains("comsvcs"), event.String("rundll32 COMSVCS.dll,MiniDump")) {
		t.Fatal("contains must fold case")
	}
	if !hit(t, StartsWith(`C:\Win`), event.String(`c:\windows\system32`)) {
		t.Fatal("startswith must fold case")
	}
	if !hit(t, EndsWith(`\rundll32.exe`), event.String(`C:\Windows\System32\RUNDLL32.EXE`)) {
		t.Fatal("endswith must fold case")
	}
}

func TestEqualsHonorsWildcards(t *testing.T) {
	if !hit(t, Equals(`*\rundll32.exe`), event.String(`C:\Windows\rundll32.exe`)) {
		t.Fatal("equals with a star behaves as a wildcard match")
	}
}

func TestNumbersAndBoolsCompareAsText(t *testing.T) {
	if !hit(t, Equals("4688"), event.Int(4688)) {
		t.Fatal("int should compare against its decimal text")
	}
	if !hit(t, Equals("true"), event.Bool(true)) {
		t.Fatal("bool should compare against its text")
	}
}

func TestRegexCaseSensitivityDefault(t *testing.T) {
	m, err := Regex(`^powershell`, false)
	if err != nil {
		t.Fatal(err)
	}
	if hit(t, m, event.String("PowerShell")) {
		t.Fatal("re is case sensitive by default, unlike every other string modifier")
	}
	mi, err := Regex(`^powershell`, true)
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, mi, event.String("PowerShell")) {
		t.Fatal("re|i must fold case")
	}
}

func TestNullMatchesAbsentAndExplicitNull(t *testing.T) {
	if !hit(t, Null(), event.Null()) {
		t.Fatal("null matcher must match a null value")
	}
	if hit(t, Null(), event.String("")) {
		t.Fatal("null must not match an empty string")
	}
	if hit(t, Equals(""), event.Null()) {
		t.Fatal("empty string must not match null")
	}
	if !hit(t, Equals(""), event.String("")) {
		t.Fatal("empty string matches a present empty string")
	}
}

func TestAnyAll(t *testing.T) {
	ms := []Matcher{Contains("a"), Contains("b")}
	if !hit(t, Any(ms), event.String("xxa")) {
		t.Fatal("any is an OR over values")
	}
	if hit(t, All(ms), event.String("xxa")) {
		t.Fatal("all is an AND over values")
	}
	if !hit(t, All(ms), event.String("xxab")) {
		t.Fatal("all matches when every value is present")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sigma/match/ -run 'TestString|TestEquals|TestNumbers|TestRegex|TestNull|TestAny'`
Expected: FAIL, undefined: Matcher, Equals, Contains, StartsWith, EndsWith, Regex, Null, Any, All.

- [ ] **Step 3: Write the implementation**

Create `internal/sigma/match/string.go`:

```go
package match

import (
	"regexp"
	"strings"

	"github.com/atontalapur/signalman/internal/event"
)

// Matcher is the value test at a leaf predicate. It has the same method set
// as ast.Matcher, which it satisfies structurally, so this package does not
// import ast.
type Matcher interface {
	Match(v event.Value, ev *event.Event) bool
}

type funcMatcher struct {
	f func(v event.Value, ev *event.Event) bool
}

func (m funcMatcher) Match(v event.Value, ev *event.Event) bool { return m.f(v, ev) }

// onText lifts a string test into a Matcher. Null and list values have no
// text form and never match a string test.
func onText(f func(s string) bool) Matcher {
	return funcMatcher{func(v event.Value, _ *event.Event) bool {
		if v.Kind == event.KindList {
			for _, item := range v.L {
				if s, ok := item.Text(); ok && f(s) {
					return true
				}
			}
			return false
		}
		s, ok := v.Text()
		return ok && f(s)
	}}
}

// Equals is Sigma's plain "field: value". It honors wildcards, because an
// unmodified value containing * is a wildcard match in the specification.
func Equals(pattern string) Matcher {
	w := CompileWildcard(pattern)
	return onText(w.MatchString)
}

func Contains(sub string) Matcher   { return Equals("*" + escapeWildcards(sub) + "*") }
func StartsWith(pre string) Matcher { return Equals(escapeWildcards(pre) + "*") }
func EndsWith(suf string) Matcher   { return Equals("*" + escapeWildcards(suf)) }

// escapeWildcards is a no-op for the star and question mark the author wrote
// deliberately: Sigma allows wildcards inside contains values, so only a
// trailing lone backslash needs care, otherwise it would escape the star we
// are about to append.
func escapeWildcards(s string) string {
	if strings.HasSuffix(s, `\`) && !strings.HasSuffix(s, `\\`) {
		return s + `\`
	}
	return s
}

// Regex is case sensitive unless the |i modifier was present. This is the
// one string modifier whose default differs from the rest of Sigma.
func Regex(pattern string, caseInsensitive bool) (Matcher, error) {
	if caseInsensitive {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return onText(re.MatchString), nil
}

// Null matches an absent field or a field present with a null value. It does
// not match an empty string.
func Null() Matcher {
	return funcMatcher{func(v event.Value, _ *event.Event) bool {
		return v.Kind == event.KindNull
	}}
}

// Any is the OR that "field: [a, b]" means.
func Any(ms []Matcher) Matcher {
	if len(ms) == 1 {
		return ms[0]
	}
	return funcMatcher{func(v event.Value, ev *event.Event) bool {
		for _, m := range ms {
			if m.Match(v, ev) {
				return true
			}
		}
		return false
	}}
}

// All is the AND that "field|all: [a, b]" means. The modifier applies to the
// list, not to the value.
func All(ms []Matcher) Matcher {
	if len(ms) == 1 {
		return ms[0]
	}
	return funcMatcher{func(v event.Value, ev *event.Event) bool {
		for _, m := range ms {
			if !m.Match(v, ev) {
				return false
			}
		}
		return true
	}}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sigma/match/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/sigma/match/string.go internal/sigma/match/string_test.go
git commit -m "feat(match): add core string modifiers with Sigma case semantics"
```

---

### Task 7: Encoding modifiers

**Files:**
- Create: `internal/sigma/match/encode.go`
- Test: `internal/sigma/match/encode_test.go`

**Interfaces:**
- Consumes: `Contains`, `Equals`, `Any` from Task 6.
- Produces: value transformers applied before the comparison is built:
  - `func UTF16LE(s string) string`, `func UTF16BE(s string) string`, `func UTF16(s string) string` (BOM + LE)
  - `func Base64(s string) string`
  - `func Base64Offsets(s string) [3]string` (the three byte alignments)
  - `func WinDashVariants(s string) []string` (five variants)

- [ ] **Step 1: Write the failing test**

Create `internal/sigma/match/encode_test.go`:

```go
package match

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestUTF16LE(t *testing.T) {
	got := UTF16LE("ab")
	want := "a\x00b\x00"
	if got != want {
		t.Fatalf("UTF16LE = %q want %q", got, want)
	}
	if UTF16BE("ab") != "\x00a\x00b" {
		t.Fatalf("UTF16BE = %q", UTF16BE("ab"))
	}
	if !strings.HasPrefix(UTF16("a"), "\xff\xfe") {
		t.Fatal("utf16 carries a little endian BOM")
	}
}

func TestBase64(t *testing.T) {
	if Base64("hello") != base64.StdEncoding.EncodeToString([]byte("hello")) {
		t.Fatal("base64 must be standard encoding with padding")
	}
}

func TestBase64OffsetsFindEmbeddedPlaintext(t *testing.T) {
	plain := "MiniDump"
	offs := Base64Offsets(plain)
	// Every alignment of the plaintext inside a longer buffer must be found
	// by at least one of the three offset encodings.
	for pad := 0; pad < 3; pad++ {
		full := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("X", pad) + plain + "TAIL"))
		found := false
		for _, o := range offs {
			if o != "" && strings.Contains(full, o) {
				found = true
			}
		}
		if !found {
			t.Fatalf("pad %d: none of %q found in %q", pad, offs, full)
		}
	}
}

func TestWinDashHasFiveVariants(t *testing.T) {
	got := WinDashVariants("-Enc")
	want := []string{"-Enc", "/Enc", "\u2013Enc", "\u2014Enc", "\u2015Enc"}
	if len(got) != len(want) {
		t.Fatalf("got %d variants %q, want 5", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("variant %d = %q want %q", i, got[i], want[i])
		}
	}
}

func TestWinDashLeavesNonDashAlone(t *testing.T) {
	if got := WinDashVariants("Enc"); len(got) != 1 || got[0] != "Enc" {
		t.Fatalf("got %q, want the input unchanged", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sigma/match/ -run 'TestUTF16|TestBase64|TestWinDash'`
Expected: FAIL, undefined functions.

- [ ] **Step 3: Write the implementation**

Create `internal/sigma/match/encode.go`:

```go
package match

import (
	"encoding/base64"
	"strings"
	"unicode/utf16"
)

// UTF16LE encodes as little endian UTF-16 with no BOM. Chained before
// base64, which is the order the modifier list is written in and the order
// that matters.
func UTF16LE(s string) string { return utf16Bytes(s, true, false) }

// UTF16BE encodes as big endian UTF-16 with no BOM.
func UTF16BE(s string) string { return utf16Bytes(s, false, false) }

// UTF16 encodes as little endian UTF-16 with a BOM.
func UTF16(s string) string { return utf16Bytes(s, true, true) }

func utf16Bytes(s string, little, bom bool) string {
	units := utf16.Encode([]rune(s))
	var b strings.Builder
	b.Grow(len(units)*2 + 2)
	write := func(u uint16) {
		if little {
			b.WriteByte(byte(u))
			b.WriteByte(byte(u >> 8))
		} else {
			b.WriteByte(byte(u >> 8))
			b.WriteByte(byte(u))
		}
	}
	if bom {
		write(0xFEFF)
	}
	for _, u := range units {
		write(u)
	}
	return b.String()
}

func Base64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Base64Offsets returns the three encodings of s that correspond to the
// three possible byte alignments of the plaintext inside a longer buffer.
// The leading and trailing characters of each encoding are trimmed because
// they carry bits of the neighbouring plaintext, which is unknown.
//
// The start and end offsets are the ones pySigma uses. Keeping them
// identical matters, because pySigma is the oracle in Task 14.
func Base64Offsets(s string) [3]string {
	starts := [3]int{0, 2, 3}
	ends := [3]int{0, -3, -2} // indexed by (len(s)+i)%3; 0 means no trim
	var out [3]string
	for i := 0; i < 3; i++ {
		enc := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(" ", i) + s))
		end := len(enc)
		if e := ends[(len(s)+i)%3]; e != 0 {
			end += e
		}
		if starts[i] >= end {
			out[i] = ""
			continue
		}
		out[i] = enc[starts[i]:end]
	}
	return out
}

// WinDashVariants expands a leading dash into the five characters Windows
// command line parsers accept: hyphen, slash, en dash, em dash, and
// horizontal bar. Five, not two, which is the usual mistake.
func WinDashVariants(s string) []string {
	if !strings.HasPrefix(s, "-") {
		return []string{s}
	}
	rest := s[1:]
	return []string{
		"-" + rest,
		"/" + rest,
		"\u2013" + rest,
		"\u2014" + rest,
		"\u2015" + rest,
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sigma/match/ -run 'TestUTF16|TestBase64|TestWinDash' -v`
Expected: PASS. `TestBase64OffsetsFindEmbeddedPlaintext` is the one that will catch an off-by-one in the trim arithmetic. If it fails, print the three offsets and the full encoding and fix the `hi` computation rather than loosening the test.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/sigma/match/encode.go internal/sigma/match/encode_test.go
git commit -m "feat(match): add utf16, base64, base64offset, and windash expansions"
```

---

### Task 8: Comparison, cidr, and fieldref modifiers

**Files:**
- Create: `internal/sigma/match/compare.go`
- Test: `internal/sigma/match/compare_test.go`

**Interfaces:**
- Consumes: `Matcher`, `funcMatcher`, `onText` from Task 6.
- Produces:
  - `func Compare(op string, want int64) (Matcher, error)` for `lt`, `lte`, `gt`, `gte`
  - `func CIDR(prefix string) (Matcher, error)`
  - `func FieldRef(otherField string) Matcher`

- [ ] **Step 1: Write the failing test**

Create `internal/sigma/match/compare_test.go`:

```go
package match

import (
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

func TestCompareNumeric(t *testing.T) {
	m, err := Compare("gt", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, m, event.Int(101)) {
		t.Fatal("101 > 100")
	}
	if hit(t, m, event.Int(100)) {
		t.Fatal("100 is not > 100")
	}
	if !hit(t, m, event.String("101")) {
		t.Fatal("numeric strings parse")
	}
}

func TestCompareUnparsableStringIsNoMatchNotError(t *testing.T) {
	m, _ := Compare("lt", 5)
	if hit(t, m, event.String("not a number")) {
		t.Fatal("an unparsable string must not match")
	}
	if hit(t, m, event.Null()) {
		t.Fatal("null must not match a numeric comparison")
	}
}

func TestCIDR(t *testing.T) {
	m, err := CIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, m, event.String("10.1.2.3")) {
		t.Fatal("10.1.2.3 is in 10.0.0.0/8")
	}
	if hit(t, m, event.String("11.1.2.3")) {
		t.Fatal("11.1.2.3 is not in 10.0.0.0/8")
	}
	if hit(t, m, event.String("garbage")) {
		t.Fatal("an unparsable address must not match")
	}
	if _, err := CIDR("not/a/prefix"); err == nil {
		t.Fatal("a bad prefix must fail at compile time, not at eval time")
	}
}

func TestFieldRef(t *testing.T) {
	ev := &event.Event{Fields: map[string]event.Value{
		"User":        event.String("SYSTEM"),
		"TargetUser":  event.String("system"),
		"OtherUser":   event.String("alice"),
	}}
	if !FieldRef("TargetUser").Match(ev.Field("User"), ev) {
		t.Fatal("fieldref compares case insensitively like other string comparison")
	}
	if FieldRef("OtherUser").Match(ev.Field("User"), ev) {
		t.Fatal("different values must not match")
	}
	if FieldRef("Missing").Match(ev.Field("User"), ev) {
		t.Fatal("a reference to an absent field must not match a present value")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sigma/match/ -run 'TestCompare|TestCIDR|TestFieldRef'`
Expected: FAIL, undefined: Compare, CIDR, FieldRef.

- [ ] **Step 3: Write the implementation**

Create `internal/sigma/match/compare.go`:

```go
package match

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/atontalapur/signalman/internal/event"
)

// Compare implements lt, lte, gt, and gte. A field whose value is a string
// that does not parse as a number is not a match and not an error, which is
// the behavior the data contract fixes.
func Compare(op string, want int64) (Matcher, error) {
	var test func(got int64) bool
	switch op {
	case "lt":
		test = func(got int64) bool { return got < want }
	case "lte":
		test = func(got int64) bool { return got <= want }
	case "gt":
		test = func(got int64) bool { return got > want }
	case "gte":
		test = func(got int64) bool { return got >= want }
	default:
		return nil, fmt.Errorf("unknown comparison modifier %q", op)
	}
	return funcMatcher{func(v event.Value, _ *event.Event) bool {
		switch v.Kind {
		case event.KindInt:
			return test(v.I)
		case event.KindString:
			n, err := strconv.ParseInt(strings.TrimSpace(v.S), 10, 64)
			return err == nil && test(n)
		default:
			return false
		}
	}}, nil
}

// CIDR parses the prefix once, at compile time, never per event.
func CIDR(prefix string) (Matcher, error) {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("cidr %q: %w", prefix, err)
	}
	return funcMatcher{func(v event.Value, _ *event.Event) bool {
		s, ok := v.Text()
		if !ok {
			return false
		}
		addr, err := netip.ParseAddr(s)
		return err == nil && p.Contains(addr)
	}}, nil
}

// FieldRef compares the value against another field on the same event. It
// breaks the assumption that a leaf predicate has a constant right side,
// which is why Matcher takes the event.
func FieldRef(otherField string) Matcher {
	return funcMatcher{func(v event.Value, ev *event.Event) bool {
		got, ok := v.Text()
		if !ok {
			return false
		}
		want, ok := ev.Field(otherField).Text()
		if !ok {
			return false
		}
		return strings.EqualFold(got, want)
	}}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sigma/match/ -v`
Expected: PASS, all match package tests.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/sigma/match/compare.go internal/sigma/match/compare_test.go
git commit -m "feat(match): add numeric, cidr, and fieldref modifiers"
```

---

### Task 9: Modifier chain to matcher

**Files:**
- Create: `internal/sigma/match/build.go`
- Test: `internal/sigma/match/build_test.go`

**Interfaces:**
- Consumes: everything in `match` from Tasks 5 to 8.
- Produces: `func Build(mods []string, vals []event.Value) (Matcher, error)`. `mods` is the modifier list from a detection key, already split on `|` with the field name removed. `vals` is one or more values. `Build` applies encoding transforms in written order, picks the comparison, and combines values with `Any` unless `all` is present, in which case `All`. Unknown modifiers return an error naming the modifier.

- [ ] **Step 1: Write the failing test**

Create `internal/sigma/match/build_test.go`:

```go
package match

import (
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

func build(t *testing.T, mods string, vals ...string) Matcher {
	t.Helper()
	var vs []event.Value
	for _, v := range vals {
		vs = append(vs, event.String(v))
	}
	var ms []string
	if mods != "" {
		ms = strings.Split(mods, "|")
	}
	m, err := Build(ms, vs)
	if err != nil {
		t.Fatalf("Build(%q): %v", mods, err)
	}
	return m
}

func TestBuildListIsOr(t *testing.T) {
	m := build(t, "contains", "alpha", "beta")
	if !hit(t, m, event.String("xxbetaxx")) {
		t.Fatal("a value list is an OR")
	}
}

func TestBuildAllIsAnd(t *testing.T) {
	m := build(t, "contains|all", "alpha", "beta")
	if hit(t, m, event.String("xxbetaxx")) {
		t.Fatal("all requires every value")
	}
	if !hit(t, m, event.String("alpha beta")) {
		t.Fatal("all matches when every value is present")
	}
}

func TestBuildBase64OffsetContains(t *testing.T) {
	m := build(t, "base64offset|contains", "MiniDump")
	if !hit(t, m, event.String(Base64("cmd /c MiniDump 624"))) {
		t.Fatal("base64offset|contains must find the encoded plaintext")
	}
}

func TestBuildUTF16ThenBase64OrderMatters(t *testing.T) {
	m := build(t, "utf16le|base64offset|contains", "IEX")
	encoded := Base64(UTF16LE("xIEX payload"))
	if !hit(t, m, event.String(encoded)) {
		t.Fatal("utf16le is applied before base64 when chained")
	}
}

func TestBuildWindash(t *testing.T) {
	m := build(t, "contains|windash", "-encodedcommand")
	if !hit(t, m, event.String("powershell \u2013EncodedCommand SQBFAFgA")) {
		t.Fatal("windash must accept an en dash")
	}
}

func TestBuildRegexDefaultsCaseSensitive(t *testing.T) {
	m := build(t, "re", "^Power")
	if hit(t, m, event.String("powershell")) {
		t.Fatal("re is case sensitive by default")
	}
	mi := build(t, "re|i", "^Power")
	if !hit(t, mi, event.String("powershell")) {
		t.Fatal("re|i folds case")
	}
}

func TestBuildRejectsUnknownModifier(t *testing.T) {
	if _, err := Build([]string{"expandvar"}, []event.Value{event.String("x")}); err == nil ||
		!strings.Contains(err.Error(), "expandvar") {
		t.Fatalf("expected an error naming the modifier, got %v", err)
	}
}

func TestBuildNullValue(t *testing.T) {
	m, err := Build(nil, []event.Value{event.Null()})
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, m, event.Null()) {
		t.Fatal("a null value builds a null matcher")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sigma/match/ -run TestBuild`
Expected: FAIL, undefined: Build.

- [ ] **Step 3: Write the implementation**

Create `internal/sigma/match/build.go`:

```go
package match

import (
	"fmt"
	"strconv"

	"github.com/atontalapur/signalman/internal/event"
)

// Build turns one detection entry into a Matcher. mods is the modifier list
// from the key, in written order, with the field name already stripped.
//
// The pipeline is: encoding transforms in written order, then one
// comparison, then the combination across values.
func Build(mods []string, vals []event.Value) (Matcher, error) {
	var (
		transforms []func(string) []string
		comparison = "equals"
		reInsens   bool
		conjoin    bool
		fieldref   bool
	)

	for _, m := range mods {
		switch m {
		case "contains", "startswith", "endswith", "re", "cidr", "lt", "lte", "gt", "gte":
			comparison = m
		case "all":
			conjoin = true
		case "i":
			reInsens = true
		case "fieldref":
			fieldref = true
		case "utf16le", "wide":
			transforms = append(transforms, single(UTF16LE))
		case "utf16be":
			transforms = append(transforms, single(UTF16BE))
		case "utf16":
			transforms = append(transforms, single(UTF16))
		case "base64":
			transforms = append(transforms, single(Base64))
		case "base64offset":
			transforms = append(transforms, func(s string) []string {
				o := Base64Offsets(s)
				return []string{o[0], o[1], o[2]}
			})
		case "windash":
			transforms = append(transforms, WinDashVariants)
		default:
			return nil, fmt.Errorf("unsupported modifier %q", m)
		}
	}

	perValue := make([]Matcher, 0, len(vals))
	for _, v := range vals {
		m, err := buildOne(v, transforms, comparison, reInsens, fieldref)
		if err != nil {
			return nil, err
		}
		perValue = append(perValue, m)
	}
	if len(perValue) == 0 {
		return nil, fmt.Errorf("detection entry has no values")
	}
	if conjoin {
		return All(perValue), nil
	}
	return Any(perValue), nil
}

func single(f func(string) string) func(string) []string {
	return func(s string) []string { return []string{f(s)} }
}

func buildOne(v event.Value, transforms []func(string) []string, comparison string, reInsens, fieldref bool) (Matcher, error) {
	if v.Kind == event.KindNull {
		return Null(), nil
	}
	text, ok := v.Text()
	if !ok {
		return nil, fmt.Errorf("a detection value must be a scalar, got kind %d", v.Kind)
	}

	if fieldref {
		return FieldRef(text), nil
	}

	switch comparison {
	case "cidr":
		return CIDR(text)
	case "lt", "lte", "gt", "gte":
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s modifier needs an integer, got %q", comparison, text)
		}
		return Compare(comparison, n)
	case "re":
		return Regex(text, reInsens)
	}

	// Encoding transforms fan out: each one may produce several variants,
	// and any variant matching is a match.
	variants := []string{text}
	for _, tr := range transforms {
		var next []string
		for _, s := range variants {
			for _, out := range tr(s) {
				if out != "" {
					next = append(next, out)
				}
			}
		}
		variants = next
	}

	ms := make([]Matcher, 0, len(variants))
	for _, s := range variants {
		switch comparison {
		case "contains":
			ms = append(ms, Contains(s))
		case "startswith":
			ms = append(ms, StartsWith(s))
		case "endswith":
			ms = append(ms, EndsWith(s))
		default:
			ms = append(ms, Equals(s))
		}
	}
	return Any(ms), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sigma/match/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/sigma/match/build.go internal/sigma/match/build_test.go
git commit -m "feat(match): build matchers from Sigma modifier chains"
```

---

### Task 10: Detection block compilation

**Files:**
- Create: `internal/sigma/detection.go`
- Test: `internal/sigma/detection_test.go`

**Interfaces:**
- Consumes: `ast`, `match.Build`, `event.Value`.
- Produces:
  - `func CompileDetection(raw map[string]any) (map[string]ast.Node, []string, error)` returning one subtree per selection name plus the sorted selection names, excluding the `condition` key.
  - `func toValue(x any) (event.Value, error)` converting decoded YAML scalars into `event.Value`.

- [ ] **Step 1: Write the failing test**

Create `internal/sigma/detection_test.go`:

```go
package sigma

import (
	"testing"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma/ast"
	"gopkg.in/yaml.v3"
)

func compileYAML(t *testing.T, src string) (map[string]ast.Node, []string) {
	t.Helper()
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(src), &raw); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	sels, names, err := CompileDetection(raw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return sels, names
}

func evalSel(t *testing.T, n ast.Node, fields map[string]event.Value) bool {
	t.Helper()
	ev := &event.Event{Fields: fields}
	return walkForTest(n, ev)
}

// walkForTest is a local tree walker. The real evaluator arrives in Plan B.
func walkForTest(n ast.Node, ev *event.Event) bool {
	switch n := n.(type) {
	case *ast.And:
		for _, c := range n.Children {
			if !walkForTest(c, ev) {
				return false
			}
		}
		return true
	case *ast.Or:
		for _, c := range n.Children {
			if walkForTest(c, ev) {
				return true
			}
		}
		return false
	case *ast.Not:
		return !walkForTest(n.Child, ev)
	case *ast.Pred:
		return n.Match(ev)
	}
	panic("unexpected node in test walker")
}

func TestDetectionMapIsAndAcrossFields(t *testing.T) {
	sels, names := compileYAML(t, `
selection:
  Image|endswith: '\rundll32.exe'
  CommandLine|contains: comsvcs
condition: selection
`)
	if len(names) != 1 || names[0] != "selection" {
		t.Fatalf("names = %v", names)
	}
	both := map[string]event.Value{
		"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
		"CommandLine": event.String("rundll32 comsvcs.dll,MiniDump"),
	}
	one := map[string]event.Value{
		"Image": event.String(`C:\Windows\System32\rundll32.exe`),
	}
	if !evalSel(t, sels["selection"], both) {
		t.Fatal("both fields present should match")
	}
	if evalSel(t, sels["selection"], one) {
		t.Fatal("fields combine with AND")
	}
}

func TestDetectionValueListIsOr(t *testing.T) {
	sels, _ := compileYAML(t, `
selection:
  EventID:
    - 1
    - 4688
condition: selection
`)
	if !evalSel(t, sels["selection"], map[string]event.Value{"EventID": event.Int(4688)}) {
		t.Fatal("a value list is an OR")
	}
	if evalSel(t, sels["selection"], map[string]event.Value{"EventID": event.Int(9)}) {
		t.Fatal("a value not in the list should not match")
	}
}

func TestDetectionListOfMapsIsOrOfAnds(t *testing.T) {
	sels, _ := compileYAML(t, `
selection:
  - Image|endswith: '\a.exe'
    User: SYSTEM
  - Image|endswith: '\b.exe'
condition: selection
`)
	if !evalSel(t, sels["selection"], map[string]event.Value{
		"Image": event.String(`c:\b.exe`),
	}) {
		t.Fatal("the second map alone should match")
	}
	if evalSel(t, sels["selection"], map[string]event.Value{
		"Image": event.String(`c:\a.exe`),
	}) {
		t.Fatal("the first map needs both of its fields")
	}
}

func TestDetectionNullVersusEmptyString(t *testing.T) {
	sels, _ := compileYAML(t, `
missing:
  ParentImage: null
empty:
  ParentImage: ''
condition: missing
`)
	absent := map[string]event.Value{}
	explicitNull := map[string]event.Value{"ParentImage": event.Null()}
	emptyStr := map[string]event.Value{"ParentImage": event.String("")}

	if !evalSel(t, sels["missing"], absent) {
		t.Fatal("null matches an absent field")
	}
	if !evalSel(t, sels["missing"], explicitNull) {
		t.Fatal("null matches an explicit null")
	}
	if evalSel(t, sels["missing"], emptyStr) {
		t.Fatal("null must not match an empty string")
	}
	if evalSel(t, sels["empty"], absent) {
		t.Fatal("empty string must not match an absent field")
	}
	if !evalSel(t, sels["empty"], emptyStr) {
		t.Fatal("empty string matches a present empty string")
	}
}

func TestDetectionKeywordsListIsOrOverAllFields(t *testing.T) {
	sels, _ := compileYAML(t, `
keywords:
  - MiniDump
  - lsass
condition: keywords
`)
	if !evalSel(t, sels["keywords"], map[string]event.Value{
		"CommandLine": event.String("procdump -ma lsass.exe out.dmp"),
	}) {
		t.Fatal("a bare keyword list searches every field value")
	}
}

func TestDetectionIsDeterministic(t *testing.T) {
	src := `
selection:
  A: 1
  B: 2
  C: 3
condition: selection
`
	first, _ := compileYAML(t, src)
	want := ast.String(first["selection"])
	for i := 0; i < 20; i++ {
		got, _ := compileYAML(t, src)
		if ast.String(got["selection"]) != want {
			t.Fatalf("tree shape varies across runs: %s vs %s", ast.String(got["selection"]), want)
		}
	}
}
```

- [ ] **Step 2: Add the YAML dependency and run the test**

```bash
go get gopkg.in/yaml.v3@v3.0.1
go test ./internal/sigma/ -run TestDetection
```
Expected: FAIL, undefined: CompileDetection.

- [ ] **Step 3: Write the implementation**

Create `internal/sigma/detection.go`:

```go
package sigma

import (
	"fmt"
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma/ast"
	"github.com/atontalapur/signalman/internal/sigma/match"
)

// CompileDetection turns the detection block into one predicate subtree per
// selection. The condition key is skipped; the caller parses it separately.
//
// Map keys are sorted before the tree is built. Nothing here may depend on
// Go map iteration order, because the tree shape feeds the rule set hash.
func CompileDetection(raw map[string]any) (map[string]ast.Node, []string, error) {
	sels := make(map[string]ast.Node)
	var names []string
	for k := range raw {
		if k == "condition" {
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)

	for _, name := range names {
		n, err := compileSelection(raw[name])
		if err != nil {
			return nil, nil, fmt.Errorf("selection %q: %w", name, err)
		}
		sels[name] = n
	}
	return sels, names, nil
}

func compileSelection(raw any) (ast.Node, error) {
	switch v := raw.(type) {
	case map[string]any:
		return compileMap(v)
	case []any:
		// A list of maps is an OR across the maps. A list of scalars is a
		// keyword search: an OR over all field values.
		var kids []ast.Node
		for i, item := range v {
			switch item := item.(type) {
			case map[string]any:
				n, err := compileMap(item)
				if err != nil {
					return nil, fmt.Errorf("item %d: %w", i, err)
				}
				kids = append(kids, n)
			default:
				val, err := toValue(item)
				if err != nil {
					return nil, fmt.Errorf("item %d: %w", i, err)
				}
				kids = append(kids, keywordPred(val))
			}
		}
		if len(kids) == 0 {
			return nil, fmt.Errorf("empty selection")
		}
		if len(kids) == 1 {
			return kids[0], nil
		}
		return &ast.Or{Children: kids}, nil
	default:
		val, err := toValue(raw)
		if err != nil {
			return nil, err
		}
		return keywordPred(val), nil
	}
}

func compileMap(m map[string]any) (ast.Node, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	kids := make([]ast.Node, 0, len(keys))
	for _, key := range keys {
		parts := strings.Split(key, "|")
		field, mods := parts[0], parts[1:]

		vals, err := valueList(m[key])
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", key, err)
		}
		matcher, err := match.Build(mods, vals)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", key, err)
		}
		kids = append(kids, &ast.Pred{Field: field, Desc: describe(key, vals), M: matcher})
	}
	if len(kids) == 0 {
		return nil, fmt.Errorf("empty map in selection")
	}
	if len(kids) == 1 {
		return kids[0], nil
	}
	return &ast.And{Children: kids}, nil
}

// keywordPred implements a bare keyword: the value must appear in some field
// value on the event. The field is empty, which the evaluator reads as "any
// field", so keywordPred carries its own matcher over the whole event.
func keywordPred(v event.Value) ast.Node {
	text, _ := v.Text()
	inner := match.Contains(text)
	return &ast.Pred{
		Field: "",
		Desc:  fmt.Sprintf("keyword %q", text),
		M: keywordMatcher{inner: inner},
	}
}

type keywordMatcher struct{ inner ast.Matcher }

func (k keywordMatcher) Match(_ event.Value, ev *event.Event) bool {
	names := make([]string, 0, len(ev.Fields))
	for n := range ev.Fields {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if k.inner.Match(ev.Fields[n], ev) {
			return true
		}
	}
	return false
}

func valueList(raw any) ([]event.Value, error) {
	if list, ok := raw.([]any); ok {
		out := make([]event.Value, 0, len(list))
		for _, item := range list {
			v, err := toValue(item)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	v, err := toValue(raw)
	if err != nil {
		return nil, err
	}
	return []event.Value{v}, nil
}

// toValue converts a decoded YAML scalar into an event.Value.
func toValue(x any) (event.Value, error) {
	switch v := x.(type) {
	case nil:
		return event.Null(), nil
	case string:
		return event.String(v), nil
	case int:
		return event.Int(int64(v)), nil
	case int64:
		return event.Int(v), nil
	case float64:
		if v == float64(int64(v)) {
			return event.Int(int64(v)), nil
		}
		return event.String(fmt.Sprintf("%v", v)), nil
	case bool:
		return event.Bool(v), nil
	default:
		return event.Value{}, fmt.Errorf("unsupported value type %T", x)
	}
}

func describe(key string, vals []event.Value) string {
	texts := make([]string, 0, len(vals))
	for _, v := range vals {
		if s, ok := v.Text(); ok {
			texts = append(texts, "'"+s+"'")
		} else {
			texts = append(texts, "null")
		}
	}
	return key + " " + strings.Join(texts, ", ")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sigma/ -run TestDetection -v`
Expected: PASS, six tests.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/sigma/detection.go internal/sigma/detection_test.go go.mod go.sum
git commit -m "feat(sigma): compile detection blocks into predicate trees"
```

---

### Task 11: Taxonomy loader

**Files:**
- Create: `internal/sigma/taxonomy.go`, `config/taxonomy/sysmon.yml`
- Test: `internal/sigma/taxonomy_test.go`, `internal/sigma/testdata/taxonomy/sysmon.yml`

**Interfaces:**
- Consumes: `event`, `ast`, `match`.
- Produces:
  - `type LogSource struct{ Category, Product, Service string }`
  - `type TaxonomyEntry struct{ LogSource LogSource; Match map[string]event.Value; Fields map[string]string }`
  - `type Taxonomy struct{ Version string }` with `func LoadTaxonomy(dir string) (*Taxonomy, error)`, `func (t *Taxonomy) Resolve(ls LogSource) (*TaxonomyEntry, bool)`, and `func (t *Taxonomy) MatcherFor(e *TaxonomyEntry) LogSourceMatcher`
  - `type LogSourceMatcher struct{ Node ast.Node }` with `func (m LogSourceMatcher) Matches(ev *event.Event) bool`

- [ ] **Step 1: Write the fixture and the failing test**

Create `internal/sigma/testdata/taxonomy/sysmon.yml`:

```yaml
logsource:
  product: windows
  category: process_creation
match:
  channel: Microsoft-Windows-Sysmon/Operational
  event_id: 1
fields:
  Image: Image
  CommandLine: CommandLine
  ParentImage: ParentImage
  User: User
  OriginalFileName: OriginalFileName
  Hashes: Hashes
```

Create `internal/sigma/taxonomy_test.go`:

```go
package sigma

import (
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

func loadTax(t *testing.T) *Taxonomy {
	t.Helper()
	tax, err := LoadTaxonomy("testdata/taxonomy")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return tax
}

func TestTaxonomyResolve(t *testing.T) {
	tax := loadTax(t)
	e, ok := tax.Resolve(LogSource{Product: "windows", Category: "process_creation"})
	if !ok {
		t.Fatal("expected the sysmon entry to resolve")
	}
	if e.Fields["Image"] != "Image" {
		t.Fatalf("field mapping = %v", e.Fields)
	}
	if _, ok := tax.Resolve(LogSource{Product: "linux", Category: "process_creation"}); ok {
		t.Fatal("an unmapped logsource must not resolve")
	}
}

func TestTaxonomyMatcher(t *testing.T) {
	tax := loadTax(t)
	e, _ := tax.Resolve(LogSource{Product: "windows", Category: "process_creation"})
	m := tax.MatcherFor(e)

	good := &event.Event{Fields: map[string]event.Value{
		"channel":  event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id": event.Int(1),
	}}
	wrongID := &event.Event{Fields: map[string]event.Value{
		"channel":  event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id": event.Int(3),
	}}
	if !m.Matches(good) {
		t.Fatal("matching channel and event id should match")
	}
	if m.Matches(wrongID) {
		t.Fatal("a different event id must not match")
	}
}

func TestTaxonomyVersionIsStableAndContentSensitive(t *testing.T) {
	a := loadTax(t)
	b := loadTax(t)
	if a.Version != b.Version {
		t.Fatal("TaxonomyV must be stable across loads of identical content")
	}
	if a.Version == "" {
		t.Fatal("TaxonomyV must not be empty")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sigma/ -run TestTaxonomy`
Expected: FAIL, undefined: LoadTaxonomy, Taxonomy, LogSource.

- [ ] **Step 3: Write the implementation**

Create `internal/sigma/taxonomy.go`:

```go
package sigma

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma/ast"
	"github.com/atontalapur/signalman/internal/sigma/match"
	"gopkg.in/yaml.v3"
)

// LogSource is the abstract source a rule declares. It means nothing until
// the taxonomy binds it to concrete field names and match criteria.
type LogSource struct {
	Category string
	Product  string
	Service  string
}

func (ls LogSource) String() string {
	return fmt.Sprintf("product=%s category=%s service=%s", ls.Product, ls.Category, ls.Service)
}

type TaxonomyEntry struct {
	LogSource LogSource
	Match     map[string]event.Value
	Fields    map[string]string
}

type Taxonomy struct {
	// Version is TaxonomyV: the content hash of every loaded file. It is
	// carried on every verdict, because a taxonomy change can silently
	// change what a rule matches.
	Version string
	entries []TaxonomyEntry
}

type taxonomyFile struct {
	LogSource struct {
		Category string `yaml:"category"`
		Product  string `yaml:"product"`
		Service  string `yaml:"service"`
	} `yaml:"logsource"`
	Match  map[string]any    `yaml:"match"`
	Fields map[string]string `yaml:"fields"`
}

// LoadTaxonomy reads every .yml file in dir. Files are read in sorted order
// and hashed in that order, so the version is reproducible.
func LoadTaxonomy(dir string) (*Taxonomy, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no taxonomy files in %s", dir)
	}

	h := sha256.New()
	t := &Taxonomy{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		h.Write([]byte(filepath.Base(p)))
		h.Write(b)

		var f taxonomyFile
		if err := yaml.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		m := make(map[string]event.Value, len(f.Match))
		for k, v := range f.Match {
			val, err := toValue(v)
			if err != nil {
				return nil, fmt.Errorf("%s: match %q: %w", p, k, err)
			}
			m[k] = val
		}
		t.entries = append(t.entries, TaxonomyEntry{
			LogSource: LogSource{
				Category: f.LogSource.Category,
				Product:  f.LogSource.Product,
				Service:  f.LogSource.Service,
			},
			Match:  m,
			Fields: f.Fields,
		})
	}
	t.Version = hex.EncodeToString(h.Sum(nil))[:16]
	return t, nil
}

// Resolve finds the entry for a rule's logsource. All three components must
// agree, treating an empty component in the rule as a wildcard.
func (t *Taxonomy) Resolve(ls LogSource) (*TaxonomyEntry, bool) {
	for i := range t.entries {
		e := &t.entries[i]
		if ls.Category != "" && ls.Category != e.LogSource.Category {
			continue
		}
		if ls.Product != "" && ls.Product != e.LogSource.Product {
			continue
		}
		if ls.Service != "" && ls.Service != e.LogSource.Service {
			continue
		}
		return e, true
	}
	return nil, false
}

// LogSourceMatcher is the logsource test, kept separate from the condition
// tree so that a logsource mismatch can emit an explicit false verdict
// without walking the condition.
type LogSourceMatcher struct{ Node ast.Node }

func (m LogSourceMatcher) Matches(ev *event.Event) bool {
	if m.Node == nil {
		return true
	}
	return walkNode(m.Node, ev)
}

// MatcherFor builds the logsource test from an entry's match criteria.
func (t *Taxonomy) MatcherFor(e *TaxonomyEntry) LogSourceMatcher {
	keys := make([]string, 0, len(e.Match))
	for k := range e.Match {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	kids := make([]ast.Node, 0, len(keys))
	for _, k := range keys {
		v := e.Match[k]
		m, err := match.Build(nil, []event.Value{v})
		if err != nil {
			// Build with no modifiers on a scalar cannot fail. A panic here
			// would mean the taxonomy carries a value kind toValue accepted
			// and Build did not, which is a programming error.
			panic(fmt.Sprintf("taxonomy match %q: %v", k, err))
		}
		kids = append(kids, &ast.Pred{Field: k, Desc: describe(k, []event.Value{v}), M: m})
	}
	if len(kids) == 0 {
		return LogSourceMatcher{}
	}
	if len(kids) == 1 {
		return LogSourceMatcher{Node: kids[0]}
	}
	return LogSourceMatcher{Node: &ast.And{Children: kids}}
}

// walkNode is a minimal evaluator used by the logsource matcher and by
// tests. Plan B replaces the general case with internal/engine/v1.
func walkNode(n ast.Node, ev *event.Event) bool {
	switch n := n.(type) {
	case *ast.And:
		for _, c := range n.Children {
			if !walkNode(c, ev) {
				return false
			}
		}
		return true
	case *ast.Or:
		for _, c := range n.Children {
			if walkNode(c, ev) {
				return true
			}
		}
		return false
	case *ast.Not:
		return !walkNode(n.Child, ev)
	case *ast.Pred:
		return n.Match(ev)
	}
	panic(fmt.Sprintf("unexpected node %T", n))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sigma/ -run TestTaxonomy -v`
Expected: PASS, three tests.

- [ ] **Step 5: Copy the fixture into the real config directory**

```bash
mkdir -p config/taxonomy
cp internal/sigma/testdata/taxonomy/sysmon.yml config/taxonomy/sysmon.yml
```

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/sigma/taxonomy.go internal/sigma/taxonomy_test.go internal/sigma/testdata config/taxonomy
git commit -m "feat(sigma): add taxonomy loader with content-hashed version"
```

---

### Task 12: Rule loader and rule set

**Files:**
- Create: `internal/sigma/rule.go`, `internal/sigma/ruleset.go`
- Test: `internal/sigma/rule_test.go`, `internal/sigma/testdata/rules/*.yml`

**Interfaces:**
- Consumes: everything from Tasks 1 to 11.
- Produces:
  - `type Rule struct{ ID, Title, Level, Status, Path string; LogSource LogSourceMatcher; Cond ast.Node; Fields []string }`
  - `type LoadError struct{ Path, RuleID, Code, Reason string; Line int }` with `Error() string`
  - `func LoadRule(path string, tax *Taxonomy) (*Rule, *LoadError)`
  - `type RuleSet struct{ Rules []Rule; Version, TaxonomyV string }`
  - `func LoadRuleSet(dir string, tax *Taxonomy) (*RuleSet, []LoadError, error)`
  - Error codes: `aggregation`, `no-taxonomy`, `condition`, `detection`, `modifier`, `yaml`, `missing-id`.

- [ ] **Step 1: Write the fixtures**

```bash
mkdir -p internal/sigma/testdata/rules
```

Create `internal/sigma/testdata/rules/proc_dump.yml`:

```yaml
title: LSASS Memory Dump via comsvcs
id: 1f1a1f1a-0001-4000-8000-000000000001
status: test
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection_img:
    Image|endswith: '\rundll32.exe'
  selection_cli:
    CommandLine|contains:
      - 'comsvcs.dll'
      - 'MiniDump'
  filter_backup:
    ParentImage|endswith: '\veeam.exe'
  condition: selection_img and selection_cli and not filter_backup
```

Create `internal/sigma/testdata/rules/aggregated.yml`:

```yaml
title: Failed logon burst
id: 1f1a1f1a-0002-4000-8000-000000000002
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4625
  condition: selection | count() > 5 by User
```

Create `internal/sigma/testdata/rules/unmapped.yml`:

```yaml
title: Something on an unmapped source
id: 1f1a1f1a-0003-4000-8000-000000000003
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|endswith: '/curl'
  condition: selection
```

- [ ] **Step 2: Write the failing test**

Create `internal/sigma/rule_test.go`:

```go
package sigma

import (
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

func TestLoadRuleBindsFieldsAndCondition(t *testing.T) {
	tax := loadTax(t)
	r, lerr := LoadRule("testdata/rules/proc_dump.yml", tax)
	if lerr != nil {
		t.Fatalf("load: %v", lerr)
	}
	if r.ID != "1f1a1f1a-0001-4000-8000-000000000001" {
		t.Fatalf("id = %q", r.ID)
	}
	if r.Level != "high" {
		t.Fatalf("level = %q", r.Level)
	}

	match := &event.Event{Fields: map[string]event.Value{
		"channel":     event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id":    event.Int(1),
		"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
		"CommandLine": event.String(`rundll32.exe comsvcs.dll, MiniDump 624 C:\t.dmp full`),
		"ParentImage": event.String(`C:\Windows\explorer.exe`),
	}}
	if !r.LogSource.Matches(match) {
		t.Fatal("logsource should match")
	}
	if !walkNode(r.Cond, match) {
		t.Fatal("rule should match the comsvcs minidump event")
	}

	filtered := &event.Event{Fields: map[string]event.Value{
		"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
		"CommandLine": event.String(`rundll32.exe comsvcs.dll, MiniDump 624 C:\t.dmp full`),
		"ParentImage": event.String(`C:\Program Files\veeam.exe`),
	}}
	if walkNode(r.Cond, filtered) {
		t.Fatal("the veeam filter should suppress the match")
	}
}

func TestLoadRuleRejectsAggregationLoudly(t *testing.T) {
	tax := loadTax(t)
	_, lerr := LoadRule("testdata/rules/aggregated.yml", tax)
	if lerr == nil {
		t.Fatal("an aggregation rule must fail to load")
	}
	if lerr.Code != "aggregation" {
		t.Fatalf("code = %q want aggregation", lerr.Code)
	}
	if !strings.Contains(lerr.Reason, "aggregation is not supported") {
		t.Fatalf("reason = %q", lerr.Reason)
	}
	if lerr.RuleID == "" || lerr.Line == 0 {
		t.Fatalf("an aggregation error must carry the rule id and the condition line: %+v", lerr)
	}
}

func TestLoadRuleRejectsUnmappedLogsource(t *testing.T) {
	tax := loadTax(t)
	_, lerr := LoadRule("testdata/rules/unmapped.yml", tax)
	if lerr == nil || lerr.Code != "no-taxonomy" {
		t.Fatalf("expected a no-taxonomy failure, got %+v", lerr)
	}
}

func TestLoadRuleSetIsDeterministic(t *testing.T) {
	tax := loadTax(t)
	a, aerrs, err := LoadRuleSet("testdata/rules", tax)
	if err != nil {
		t.Fatal(err)
	}
	b, berrs, err := LoadRuleSet("testdata/rules", tax)
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != b.Version {
		t.Fatal("RuleSetV must be stable across loads")
	}
	if a.TaxonomyV != tax.Version {
		t.Fatal("the rule set must carry the taxonomy version")
	}
	if len(a.Rules) != 1 {
		t.Fatalf("expected 1 loadable rule, got %d", len(a.Rules))
	}
	if len(aerrs) != 2 || len(berrs) != 2 {
		t.Fatalf("expected 2 rejections, got %d and %d", len(aerrs), len(berrs))
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/sigma/ -run TestLoadRule`
Expected: FAIL, undefined: LoadRule, LoadRuleSet, Rule, LoadError.

- [ ] **Step 4: Write the rule loader**

Create `internal/sigma/rule.go`:

```go
package sigma

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/sigma/ast"
	"gopkg.in/yaml.v3"
)

type Rule struct {
	ID        string
	Title     string
	Level     string
	Status    string
	Path      string
	LogSource LogSourceMatcher
	Cond      ast.Node
	// Fields lists every field the rule reads, sorted. Later phases use it
	// for presence gating; it is cheap to compute here and awkward later.
	Fields []string
}

// LoadError is a structured rejection. Every rejection is reported, counted,
// and attributable to a rule, because a silently skipped rule is a missed
// detection with no signal attached to it.
type LoadError struct {
	Path   string
	RuleID string
	Code   string
	Reason string
	Line   int
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("%s:%d [%s] rule %s: %s", e.Path, e.Line, e.Code, e.RuleID, e.Reason)
}

type ruleFile struct {
	Title     string `yaml:"title"`
	ID        string `yaml:"id"`
	Status    string `yaml:"status"`
	Level     string `yaml:"level"`
	LogSource struct {
		Category string `yaml:"category"`
		Product  string `yaml:"product"`
		Service  string `yaml:"service"`
	} `yaml:"logsource"`
	Detection map[string]any `yaml:"detection"`
}

func LoadRule(path string, tax *Taxonomy) (*Rule, *LoadError) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, &LoadError{Path: path, Code: "yaml", Reason: err.Error()}
	}

	var f ruleFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, &LoadError{Path: path, Code: "yaml", Reason: err.Error()}
	}
	fail := func(code, reason string, line int) *LoadError {
		return &LoadError{Path: path, RuleID: f.ID, Code: code, Reason: reason, Line: line}
	}
	if f.ID == "" {
		return nil, fail("missing-id", "rule has no id", 1)
	}

	condRaw, _ := f.Detection["condition"].(string)
	if condRaw == "" {
		return nil, fail("condition", "detection block has no condition", conditionLine(b))
	}

	entry, ok := tax.Resolve(LogSource{
		Category: f.LogSource.Category,
		Product:  f.LogSource.Product,
		Service:  f.LogSource.Service,
	})
	if !ok {
		return nil, fail("no-taxonomy",
			fmt.Sprintf("no taxonomy entry for %s", LogSource{
				Category: f.LogSource.Category,
				Product:  f.LogSource.Product,
				Service:  f.LogSource.Service,
			}), 1)
	}

	sels, names, err := CompileDetection(f.Detection)
	if err != nil {
		code := "detection"
		if strings.Contains(err.Error(), "unsupported modifier") {
			code = "modifier"
		}
		return nil, fail(code, err.Error(), 1)
	}

	parsed, err := ParseCondition(condRaw)
	if err != nil {
		code := "condition"
		if errors.Is(err, ErrAggregation) {
			code = "aggregation"
		}
		return nil, fail(code, err.Error(), conditionLine(b))
	}

	expanded, err := Expand(parsed, names)
	if err != nil {
		return nil, fail("condition", err.Error(), conditionLine(b))
	}

	bound := bind(expanded, sels)
	renamed, fields := rename(bound, entry.Fields)

	return &Rule{
		ID:        f.ID,
		Title:     f.Title,
		Level:     f.Level,
		Status:    f.Status,
		Path:      path,
		LogSource: tax.MatcherFor(entry),
		Cond:      renamed,
		Fields:    fields,
	}, nil
}

// bind substitutes each selection's compiled subtree for its identifier.
func bind(n ast.Node, sels map[string]ast.Node) ast.Node {
	switch n := n.(type) {
	case *ast.And:
		return &ast.And{Children: bindAll(n.Children, sels)}
	case *ast.Or:
		return &ast.Or{Children: bindAll(n.Children, sels)}
	case *ast.Not:
		return &ast.Not{Child: bind(n.Child, sels)}
	case *ast.Ident:
		// Expand has already verified that the name is defined.
		return sels[n.Name]
	default:
		return n
	}
}

func bindAll(in []ast.Node, sels map[string]ast.Node) []ast.Node {
	out := make([]ast.Node, len(in))
	for i, c := range in {
		out[i] = bind(c, sels)
	}
	return out
}

// rename rewrites predicate field names through the taxonomy mapping and
// collects the sorted set of fields the rule reads. A field with no mapping
// keeps its name, which is what an event source that already uses Sigma
// field names needs.
func rename(n ast.Node, mapping map[string]string) (ast.Node, []string) {
	seen := map[string]bool{}
	out := renameNode(n, mapping, seen)
	fields := make([]string, 0, len(seen))
	for f := range seen {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	return out, fields
}

func renameNode(n ast.Node, mapping map[string]string, seen map[string]bool) ast.Node {
	switch n := n.(type) {
	case *ast.And:
		kids := make([]ast.Node, len(n.Children))
		for i, c := range n.Children {
			kids[i] = renameNode(c, mapping, seen)
		}
		return &ast.And{Children: kids}
	case *ast.Or:
		kids := make([]ast.Node, len(n.Children))
		for i, c := range n.Children {
			kids[i] = renameNode(c, mapping, seen)
		}
		return &ast.Or{Children: kids}
	case *ast.Not:
		return &ast.Not{Child: renameNode(n.Child, mapping, seen)}
	case *ast.Pred:
		field := n.Field
		if to, ok := mapping[field]; ok && to != "" {
			field = to
		}
		if field != "" {
			seen[field] = true
		}
		return &ast.Pred{Field: field, Desc: n.Desc, M: n.M}
	}
	return n
}

// conditionLine finds the 1-based line of the condition key, so the error
// points at something an author can open.
func conditionLine(src []byte) int {
	for i, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "condition:") {
			return i + 1
		}
	}
	return 1
}
```

- [ ] **Step 5: Write the rule set loader**

Create `internal/sigma/ruleset.go`:

```go
package sigma

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/atontalapur/signalman/internal/sigma/ast"
)

type RuleSet struct {
	// Rules is sorted by ID, so iteration order is fixed regardless of how
	// the filesystem returned the files.
	Rules []Rule
	// Version is RuleSetV: a hash over each rule's ID and its bound tree.
	// Two loads of the same rules produce the same version, and a change to
	// any rule's semantics changes it.
	Version   string
	TaxonomyV string
}

// LoadRuleSet loads every .yml file under dir. Rejections are returned
// rather than raised, because a corpus run needs the full list, but no rule
// is ever dropped without an entry here.
func LoadRuleSet(dir string, tax *Taxonomy) (*RuleSet, []LoadError, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(p); ext == ".yml" || ext == ".yaml" {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(paths)

	rs := &RuleSet{TaxonomyV: tax.Version}
	var errs []LoadError
	for _, p := range paths {
		r, lerr := LoadRule(p, tax)
		if lerr != nil {
			errs = append(errs, *lerr)
			continue
		}
		rs.Rules = append(rs.Rules, *r)
	}
	sort.Slice(rs.Rules, func(i, j int) bool { return rs.Rules[i].ID < rs.Rules[j].ID })

	h := sha256.New()
	for _, r := range rs.Rules {
		h.Write([]byte(r.ID))
		h.Write([]byte(ast.String(r.Cond)))
	}
	h.Write([]byte(tax.Version))
	rs.Version = hex.EncodeToString(h.Sum(nil))[:16]
	return rs, errs, nil
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/sigma/ -v`
Expected: PASS, every test in the package.

- [ ] **Step 7: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/sigma/rule.go internal/sigma/ruleset.go internal/sigma/rule_test.go internal/sigma/testdata/rules
git commit -m "feat(sigma): add rule and rule set loaders with structured rejections"
```

---

### Task 13: SigmaHQ corpus acceptance report

**Files:**
- Create: `cmd/corpusaccept/main.go`, `docs/corpus-acceptance.md`
- Test: `internal/sigma/corpus_test.go`

**Interfaces:**
- Consumes: `LoadRuleSet`, `LoadTaxonomy`.
- Produces: a binary that prints per-code rejection counts and writes the report, plus a test that runs against a vendored slice of the corpus and asserts every rule ends in exactly one of two buckets.

- [ ] **Step 1: Vendor the corpus**

```bash
mkdir -p corpora
git clone --depth 1 https://github.com/SigmaHQ/sigma corpora/sigmahq
ls corpora/sigmahq/rules/windows/process_creation | head
```

`corpora/` is already in `.gitignore`, so the corpus stays out of the repository.

- [ ] **Step 2: Write the failing test**

Create `internal/sigma/corpus_test.go`:

```go
package sigma

import (
	"os"
	"testing"
)

// TestCorpusEveryRuleIsAcceptedOrRejectedWithAReason is the gate for Plan A.
// There is no third outcome: a rule either loads or produces exactly one
// LoadError carrying a code.
func TestCorpusEveryRuleIsAcceptedOrRejectedWithAReason(t *testing.T) {
	const dir = "../../corpora/sigmahq/rules/windows/process_creation"
	if _, err := os.Stat(dir); err != nil {
		t.Skip("SigmaHQ corpus not vendored, see Task 13 step 1")
	}
	tax, err := LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	rs, errs, err := LoadRuleSet(dir, tax)
	if err != nil {
		t.Fatal(err)
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var want int
	for _, f := range files {
		if !f.IsDir() {
			want++
		}
	}
	if got := len(rs.Rules) + len(errs); got != want {
		t.Fatalf("accounted for %d rules but the directory has %d", got, want)
	}
	for _, e := range errs {
		if e.Code == "" || e.Reason == "" {
			t.Fatalf("rejection without a code or reason: %+v", e)
		}
	}
	t.Logf("loaded %d, rejected %d", len(rs.Rules), len(errs))
}
```

- [ ] **Step 3: Run the test**

Run: `go test ./internal/sigma/ -run TestCorpus -v`
Expected: PASS, with a log line giving the two counts. If it fails on the accounting, a rule produced neither a `Rule` nor a `LoadError`, which is the bug this test exists to catch.

- [ ] **Step 4: Write the report command**

Create `cmd/corpusaccept/main.go`:

```go
// Command corpusaccept loads a rule directory and reports how many rules
// were accepted and why the rest were rejected. The output is the input to
// docs/corpus-acceptance.md, which is the Plan A gate.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/atontalapur/signalman/internal/sigma"
)

func main() {
	rules := flag.String("rules", "corpora/sigmahq/rules", "rule directory")
	taxonomy := flag.String("taxonomy", "config/taxonomy", "taxonomy directory")
	samples := flag.Int("samples", 3, "example rejections to print per code")
	flag.Parse()

	tax, err := sigma.LoadTaxonomy(*taxonomy)
	if err != nil {
		fmt.Fprintln(os.Stderr, "taxonomy:", err)
		os.Exit(1)
	}
	rs, errs, err := sigma.LoadRuleSet(*rules, tax)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rules:", err)
		os.Exit(1)
	}

	byCode := map[string][]sigma.LoadError{}
	for _, e := range errs {
		byCode[e.Code] = append(byCode[e.Code], e)
	}
	codes := make([]string, 0, len(byCode))
	for c := range byCode {
		codes = append(codes, c)
	}
	sort.Strings(codes)

	total := len(rs.Rules) + len(errs)
	fmt.Printf("ruleset %s taxonomy %s\n", rs.Version, rs.TaxonomyV)
	fmt.Printf("accepted %d of %d (%.1f%%)\n\n", len(rs.Rules), total,
		100*float64(len(rs.Rules))/float64(total))
	for _, c := range codes {
		list := byCode[c]
		fmt.Printf("%-14s %5d\n", c, len(list))
		for i, e := range list {
			if i >= *samples {
				break
			}
			fmt.Printf("               %s\n", e.Error())
		}
	}
}
```

- [ ] **Step 5: Run it and write the report**

```bash
go run ./cmd/corpusaccept -rules corpora/sigmahq/rules > /tmp/accept.txt
cat /tmp/accept.txt
```

Then write `docs/corpus-acceptance.md` containing the run date, the command, the accepted and rejected counts, the per-code table from the output, and one paragraph per code explaining whether that rejection is intended (aggregation, unmapped logsource) or a gap to close in a later plan. Do not paste raw output without the commentary; the commentary is the deliverable.

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./...
git add cmd/corpusaccept internal/sigma/corpus_test.go docs/corpus-acceptance.md
git commit -m "feat(cmd): add corpus acceptance report and document the results"
```

---

### Task 14: pySigma differential fuzzer

**Files:**
- Create: `test/fuzz/pysigma_eval.py`, `test/fuzz/oracle.go`, `test/fuzz/differential_test.go`, `test/fuzz/requirements.txt`
- Test: the fuzzer is the test.

**Interfaces:**
- Consumes: `sigma.LoadTaxonomy`, `sigma.LoadRule`, `walkNode` behavior via a new exported helper.
- Produces:
  - `func sigma.EvalOnce(ruleYAML []byte, ev *event.Event) (matched bool, err error)` added to `internal/sigma/rule.go`.
  - `oracle.Eval(ruleYAML []byte, eventJSON []byte) (matched bool, err error)` in `test/fuzz`, backed by a long-lived Python subprocess speaking newline-delimited JSON.

**Oracle design note.** pySigma is a rule conversion library, not an event evaluator. The bridge converts the rule to a SQLite `WHERE` clause with `pySigma-backend-sqlite`, materializes the event as a single-row table, and runs the query. This is the approach Zircolite uses and it is a genuinely independent implementation path: a different parser, a different modifier expansion, and a different comparison engine. It also has known semantic gaps against Sigma proper, mainly around null handling and case folding in SQLite. Keep a list of them in `test/fuzz/KNOWN_DIVERGENCES.md` with a one-line justification each, and treat any divergence not on that list as a Signalman bug until proven otherwise. The list is a deliverable, not a workaround.

**As built (SIG-21).** Four things came out differently, each for a reason
worth keeping:

- `EvalOnce` lives in `test/fuzz`, not `internal/sigma`. `internal/sigma`
  cannot import `internal/engine/v1`, and the fuzzer has to test the
  evaluator that ships rather than a second walker written for it. It loads
  through `sigma.LoadRuleBytes`, which SIG-19 added, so no temp file.
- The rule is generated, not mutated. A free-text fuzz over rule YAML reached
  684,594 executions with zero verdict comparisons: every mutation broke the
  YAML or the rule, and both engines rejected it. The target now drives
  values, a modifier chain, a field, and a condition shape into a valid
  skeleton. The rule-level acceptance divergences it can no longer reach are
  pinned by `TestKnownAcceptanceDivergences`.
- Outcomes are counted and flushed to disk per worker
  (`make fuzz-differential`, `scripts/fuzz_stats.py`). Fuzzing runs in worker
  processes, so the only number the coordinator reports is executions, and
  that number said nothing about whether anything was compared.
- The oracle call has a five second deadline and the subprocess is replaced
  on timeout. Python's regex engine backtracks and cannot be interrupted, so
  one generated pattern used to stall a worker for the rest of the run.

The oracle also declines more than the plan anticipated: `cidr`, the numeric
comparisons, `fieldref`, value-only expressions, a NUL in a value, a regex
against a value with a newline, and any query the backend generates with
`NOT` outside parentheses, which is a defect in
`pySigma-backend-sqlite`. Every one has a section in
`test/fuzz/KNOWN_DIVERGENCES.md`.

Three of the Task 14 review amendments were not built as written:

- Events are strings only. The generated fields are the four string fields
  both process_creation bindings map, so ints, bools and nulls are not
  exercised, and the bool column-type decision never came up. Typed values
  stay covered by unit tests in `internal/sigma/match`; extending the
  generator to them is open.
- Generated strings are not restricted to ASCII. A non-ASCII case
  difference is left as a real divergence with no suppression, so the
  fuzzer can still find a Unicode folding question instead of being kept
  away from one.
- There is no `SIGNALMAN_PYTHON`. The oracle runs from
  `test/fuzz/.venv`, which CI builds from the hash-locked
  `requirements.txt`. With `CI=true` a missing venv fails the test rather
  than skipping it, and a venv whose oracle will not start fails the fuzz
  target.

After the pre-merge review, every suppression keys on a code or an error
type rather than message text; `KNOWN_DIVERGENCES.md` says how.

- [x] **Step 1: Set up the Python side**

```bash
python3 -m venv test/fuzz/.venv
test/fuzz/.venv/bin/pip install pysigma pysigma-backend-sqlite
printf 'pysigma\npysigma-backend-sqlite\n' > test/fuzz/requirements.txt
```

- [x] **Step 2: Write the oracle subprocess**

Create `test/fuzz/pysigma_eval.py`:

```python
"""Evaluate one Sigma rule against one event, as an oracle for the Go engine.

Reads newline-delimited JSON on stdin, one object per request:
    {"rule": "<yaml>", "event": {"Field": "value", ...}}
Writes one object per response:
    {"matched": true} or {"error": "..."}

The rule is converted to a SQLite WHERE clause by pySigma, then run against a
single-row table built from the event. The conversion path is completely
separate from the Go implementation, which is the point.
"""

import json
import sqlite3
import sys

from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend


def where_clause(rule_yaml: str) -> str:
    collection = SigmaCollection.from_yaml(rule_yaml)
    queries = sqliteBackend().convert(collection)
    if len(queries) != 1:
        raise ValueError(f"expected 1 query, got {len(queries)}")
    return queries[0]


def evaluate(rule_yaml: str, event: dict) -> bool:
    clause = where_clause(rule_yaml)
    fields = sorted(event.keys())
    conn = sqlite3.connect(":memory:")
    cols = ", ".join(f'"{f}"' for f in fields)
    conn.execute(f"CREATE TABLE events ({cols})")
    placeholders = ", ".join("?" for _ in fields)
    conn.execute(
        f"INSERT INTO events ({cols}) VALUES ({placeholders})",
        [event[f] for f in fields],
    )
    cur = conn.execute(f"SELECT count(*) FROM events WHERE {clause}")
    return cur.fetchone()[0] > 0


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            out = {"matched": evaluate(req["rule"], req["event"])}
        except Exception as exc:  # the Go side classifies acceptance mismatches
            out = {"error": f"{type(exc).__name__}: {exc}"}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
```

- [x] **Step 3: Write the Go side of the bridge**

Create `test/fuzz/oracle.go`:

```go
package fuzz

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
)

// Oracle wraps a long-lived pySigma subprocess. Starting Python per case
// would make the fuzzer far too slow to reach a useful execution count.
type Oracle struct {
	mu  sync.Mutex
	cmd *exec.Cmd
	in  *bufio.Writer
	out *bufio.Scanner
}

type oracleReq struct {
	Rule  string            `json:"rule"`
	Event map[string]string `json:"event"`
}

type oracleResp struct {
	Matched bool   `json:"matched"`
	Error   string `json:"error"`
}

// StartOracle runs the subprocess with paths relative to this package
// directory, which is where go test sets the working directory.
func StartOracle() (*Oracle, error) {
	cmd := exec.Command("./.venv/bin/python", "pysigma_eval.py")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &Oracle{
		cmd: cmd,
		in:  bufio.NewWriter(stdin),
		out: bufio.NewScanner(stdout),
	}, nil
}

func (o *Oracle) Eval(ruleYAML string, ev map[string]string) (bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	b, err := json.Marshal(oracleReq{Rule: ruleYAML, Event: ev})
	if err != nil {
		return false, err
	}
	if _, err := o.in.Write(append(b, '\n')); err != nil {
		return false, err
	}
	if err := o.in.Flush(); err != nil {
		return false, err
	}
	if !o.out.Scan() {
		return false, fmt.Errorf("oracle died: %v", o.out.Err())
	}
	var resp oracleResp
	if err := json.Unmarshal(o.out.Bytes(), &resp); err != nil {
		return false, err
	}
	if resp.Error != "" {
		return false, fmt.Errorf("%s", resp.Error)
	}
	return resp.Matched, nil
}

func (o *Oracle) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cmd.Process != nil {
		_ = o.cmd.Process.Kill()
	}
	return o.cmd.Wait()
}
```

- [x] **Step 4: Add EvalOnce to the sigma package**

Append to `internal/sigma/rule.go`:

```go
// EvalOnce loads one rule from YAML and evaluates it against one event. It
// is the entry point the differential fuzzer uses; production code loads a
// rule set once and reuses it.
func EvalOnce(ruleYAML []byte, tax *Taxonomy, ev *event.Event) (bool, error) {
	f, err := os.CreateTemp("", "rule-*.yml")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(ruleYAML); err != nil {
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	r, lerr := LoadRule(f.Name(), tax)
	if lerr != nil {
		return false, lerr
	}
	if !r.LogSource.Matches(ev) {
		return false, nil
	}
	return walkNode(r.Cond, ev), nil
}
```

Add `"github.com/atontalapur/signalman/internal/event"` to that file's imports.

- [x] **Step 5: Write the differential fuzzer**

Create `test/fuzz/differential_test.go`:

```go
package fuzz

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

func FuzzAgainstPySigma(f *testing.F) {
	if _, err := os.Stat(".venv/bin/python"); err != nil {
		f.Skip("pySigma venv not built, see Task 14 step 1")
	}
	oracle, err := StartOracle()
	if err != nil {
		f.Skipf("oracle unavailable: %v", err)
	}
	f.Cleanup(func() { _ = oracle.Close() })

	tax, err := sigma.LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		f.Fatal(err)
	}

	seedRule := `title: seed
id: 00000000-0000-4000-8000-000000000000
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\rundll32.exe'
  condition: selection
`
	f.Add(seedRule, `{"Image":"C:\\Windows\\rundll32.exe"}`)
	f.Add(seedRule, `{"Image":"C:\\Windows\\notepad.exe"}`)

	f.Fuzz(func(t *testing.T, ruleYAML, eventJSON string) {
		var raw map[string]string
		if err := json.Unmarshal([]byte(eventJSON), &raw); err != nil {
			t.Skip()
		}
		fields := map[string]event.Value{}
		for k, v := range raw {
			fields[k] = event.String(v)
		}
		ev := &event.Event{Fields: fields}

		got, errG := sigma.EvalOnce([]byte(ruleYAML), tax, ev)
		want, errP := oracle.Eval(ruleYAML, raw)

		if (errG == nil) != (errP == nil) {
			// An acceptance mismatch is only interesting when Signalman
			// accepts a rule the oracle rejects, or the reverse for a
			// reason not on the known list.
			if known(errG, errP) {
				t.Skip()
			}
			t.Fatalf("acceptance mismatch: go=%v py=%v\nrule:\n%s", errG, errP, ruleYAML)
		}
		if errG == nil && got != want {
			t.Fatalf("verdict mismatch: go=%v py=%v\nrule:\n%s\nevent: %s", got, want, ruleYAML, eventJSON)
		}
	})
}

// known suppresses the documented semantic gaps between Signalman and the
// SQLite oracle. Every entry here must have a line in KNOWN_DIVERGENCES.md.
func known(errG, errP error) bool {
	if errG != nil && strings.Contains(errG.Error(), "no taxonomy entry") {
		return true // the oracle has no taxonomy concept at all
	}
	if errG != nil && strings.Contains(errG.Error(), "aggregation is not supported") {
		return true // deliberate scope cut, the oracle converts these
	}
	return false
}
```

- [x] **Step 6: Create the known divergences document**

Create `test/fuzz/KNOWN_DIVERGENCES.md` with one section per suppression in `known()`. Start with the two above: the oracle has no taxonomy layer, so unmapped logsources are a Signalman-only rejection; and aggregation rules convert cleanly in pySigma but are a deliberate scope cut here. Add a row every time a suppression is added, never a suppression without a row.

- [x] **Step 7: Run the fuzzer**

```bash
go test ./test/fuzz/ -run FuzzAgainstPySigma -fuzz FuzzAgainstPySigma -fuzztime 300s
```
Expected: no failures. Every failure is either a Signalman bug or a new entry in `KNOWN_DIVERGENCES.md` with a written justification. Do not add a suppression without first convincing yourself which side is wrong.

- [x] **Step 8: Run the long fuzz and record the count**

```bash
go test ./test/fuzz/ -run FuzzAgainstPySigma -fuzz FuzzAgainstPySigma -fuzztime 30m
```
Record the execution count in `docs/corpus-acceptance.md`. Plan A's gate wants 1e6 executions clean; spec gate G0 later wants 1e8, which runs in CI over time rather than in one sitting.

- [x] **Step 9: Commit**

```bash
gofmt -l . && go vet ./...
git add test/fuzz internal/sigma/rule.go docs/corpus-acceptance.md
git commit -m "test(fuzz): add pySigma differential fuzzer with a documented oracle"
```

---

## Plan A exit

Each story ships through `/ship`, which runs `make check`, bumps `VERSION`, updates `CHANGELOG.md`, and opens the PR. Never `gh pr create` by hand. The plan is done when the gate passes, checked on the last story's branch:

```bash
make check
go test ./internal/sigma/ -run TestCorpus -v
go test ./test/fuzz/ -run '^$' -fuzz FuzzAgainstPySigma -fuzztime 30m
```

The gate: every rule in the corpus either parses or is rejected with a specific reason, the counts and the corpus commit SHA are in `docs/corpus-acceptance.md` with commentary, and the differential fuzzer has run 1e6 executions clean with every suppression documented in `test/fuzz/KNOWN_DIVERGENCES.md`.

## What Plan B consumes from this

- `sigma.RuleSet` with `Rules []Rule`, `Version`, `TaxonomyV`.
- `Rule.LogSource.Matches(ev)` and `Rule.Cond`, which together give the v1 evaluator its two-step shape: a logsource test that emits an explicit `false` verdict, and a condition tree of only `And`, `Or`, `Not`, and `Pred`.
- `Rule.Fields`, for the field presence gating v2 needs in Plan G.
- `ast.Eval`, the single tree walker. Plan B's v1 may wrap it or reimplement it as its own obviously-correct walker; decide there.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | — | — |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | CLEAR | 13 issues, 0 critical gaps, all resolved; 14 test gaps folded into amendments |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | no UI |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **CROSS-MODEL:** A fresh Claude subagent (same family, cold read) surfaced 15 findings during `/office-hours`; all 15 were resolved in issues 1 to 13 or folded into the amendments. No open tension.
- **VERDICT:** ENG CLEARED — ready to implement. Execution order and per-task amendments above are authoritative.

NO UNRESOLVED DECISIONS
