# Known divergences between Signalman and the pySigma oracle

The differential fuzzer treats every disagreement as a Signalman bug until
proven otherwise. This file is the list of the exceptions, and it is a
deliverable rather than a workaround: a suppression without an entry here is
how a differential fuzzer quietly stops finding things.

Each section names the suppression that implements it. The Signalman-side and
oracle-side load suppressions live in `known()` in `oracle.go`; the oracle's
own refusals are raised in `pysigma_eval.py`; the verdict-level suppressions
are in the fuzz body in `differential_test.go`.

## How the oracle works, and what that costs

pySigma converts rules, it does not evaluate events. The oracle converts the
rule to a SQLite query, materializes the event as a single-row table, and
runs the query. That gives a genuinely independent parser, modifier
expansion, and comparison engine, which is the whole point. It also inherits
SQL's semantics where they differ from Sigma's, which is what most of this
file is about.

Two deliberate adjustments to make the comparison meaningful:

- **`COLLATE NOCASE` on every column.** Sigma string comparison is case
  insensitive by default. SQLite's `LIKE` already ignores ASCII case but its
  `=` does not, so without the collation the same rule would be case
  insensitive through `contains` and case sensitive through a plain equals.
  NOCASE folds ASCII only. A case difference outside ASCII is still a real
  divergence and has no suppression; if the fuzzer finds one, it is a
  question about Signalman's Unicode folding, not noise.
- **A `regexp` function registered from Python's `re`.** SQLite ships no
  REGEXP implementation, so `|re` would otherwise fail to run at all.

## Signalman loads a rule the oracle will not

### No taxonomy layer

Signalman rejects a rule whose logsource has no binding (`no-taxonomy`).
pySigma has no taxonomy concept: a logsource is metadata it carries and does
not act on. This is not a semantic difference but a missing layer, so the
rejection is suppressed.

The fuzzer also always stamps the entry's match criteria on the event, so a
generated field cannot push the event out of the logsource its rule
declares. A logsource mismatch is a correct `false` verdict in Signalman and
an unrepresentable state in the oracle.

### A rule with no id

Signalman requires an `id`; pySigma does not. Verdicts are keyed on the rule
id, so a rule without one cannot be reported on or compared across engines.
Recorded in `docs/corpus-acceptance.md` as `missing-id`.

### A rule whose id is not a UUID

The mirror of the case above, and a separate suppression
(`SigmaIdentifierError`). pySigma requires the id to parse as a UUID and
rejects `id: not-a-uuid`; Signalman requires only that an id exist, because
what it needs from the id is a stable key for verdicts, not a format.

### Aggregation and correlation

A `|` in the condition is rejected at load with the rule id, the line number,
and "aggregation is not supported". pySigma converts these. The scope cut is
in the spec and in `CLAUDE.md`; it is not up for revision by a fuzzer.

### A regular expression RE2 rejects

Go's `regexp` is RE2: no backreferences, no lookaround. Python's engine has
both. A pattern using them loads in the oracle and is a load error in
Signalman.

## The oracle will not answer

These are refused in `pysigma_eval.py` before conversion, so the failure is
one clear sentence rather than whatever the backend raises.

### `cidr`

The sqlite backend converts `DestinationIp|cidr: 10.0.0.0/8` to
`DestinationIp LIKE '10.%'`. That is a string prefix, not a network match:
it is wrong for any prefix length that is not a multiple of 8, and it
matches `10.` inside other text. Signalman parses the network and compares
addresses.

### `lt`, `lte`, `gt`, `gte`

The event is materialized as text, and SQLite compares a TEXT value to an
integer by type rank rather than by value, so `Port > 1024` is true for
every string. Numeric comparison is covered by unit tests in
`internal/sigma/match` instead.

### `fieldref`

The backend has no column-to-column comparison form.

### Value-only expressions

A search identifier that is a bare value or a list of bare values is a
keyword search in Sigma. Signalman supports it as a match over every field's
value. The backend has no full-text form and fails in more than one way
depending on the value's type, so the oracle declines it up front.

### A value carrying a NUL

SQLite refuses a query containing a NUL, and the rule values end up in the
query. Signalman compares bytes and has no such limit.

### A query SQLite will not parse

`windash` fans out over five dash characters per switch-introducing dash, so
a value with four of them is 625 variants and a rule repeating that across
three search identifiers is 1875 `OR` terms. SQLite refuses an expression
tree deeper than 1000. Signalman caps the fan-out at five dash positions
(3125 variants) and rejects beyond that, which is a budget, not a parser
limit.

### `NOT` outside parentheses

For a negated selection with more than one variant, the backend emits
`NOT a LIKE x OR a LIKE y` with no parentheses. `NOT` binds tighter than
`OR` in SQL, so the query means `(NOT a) OR b`, which is not what the rule
says. This is a backend defect, and the oracle cannot answer a query it has
mis-generated. Detected on the generated SQL, not guessed from the rule.

### `base64offset` on a non-ASCII value

The three offset encodings are trimmed at each end because the leading and
trailing base64 characters carry bits of the neighbouring plaintext. How much
to trim depends on how many **bytes** the plaintext occupies. pySigma indexes
its trim table by the string's **character** count, so for U+2029 it trims
three characters off an encoding that needed no trim at all and produces `4`
where the whole encoding `4oCp` is correct. The two agree on ASCII, where
bytes and characters coincide, and disagree on everything else.

`Base64Offsets` in `internal/sigma/match/encode.go` says its offsets are the
ones pySigma uses. That is true of the table and not of the indexing.

### A modifier pySigma does not carry

Suppressed on `Unknown modifier`. `utf16le` is a Sigma modifier name pySigma
does not know; it spells the same transform `wide`. The fuzzer generates the name both engines share, and the
suppression covers any other name that turns out to be missing.

### `wide` and `utf16` on anything but ASCII

pySigma's implementation encodes to UTF-16 and then decodes the result as
UTF-8, so these modifiers raise for most non-ASCII input. Signalman encodes
the text and compares bytes, which is what the modifier means.

### A wildcard inside an encoded value

pySigma refuses `CommandLine|base64|contains: '*'`, on the grounds that a
wildcard cannot survive encoding. Signalman encodes the `*` as a literal
byte and matches the encoding of it.

This one is a live design question, not a settled difference: an author who
writes `|base64|contains: '*foo*'` expecting a wildcard gets a silently
literal match here and a load error from pySigma. Signalman's own habit is
to reject a rule that can never mean what it says. Carried in `TODOS.md`
rather than decided inside the fuzzer's story.

### A pattern Python's engine rejects

The mirror of the RE2 case above: `0$*` is a valid RE2 pattern and a syntax
error in Python's engine.

### A regex using a character class shorthand

`\s`, `\S`, `\w`, `\W`, `\d`, `\D`, `\b` and `\B` do not name the same
sets in the two engines. Python's `\s` includes U+001C to U+001F and its
`\w` and `\d` are Unicode-aware; RE2's `\s` is `[\t\n\f\r ]` and its `\w`
and `\d` are ASCII. So `\S` matches a FILE SEPARATOR under RE2 and not under
Python. Which dialect a Sigma `|re` means is a question about Sigma, not
about Signalman, and the oracle cannot settle it by answering from its own
engine.

### A regex using a repetition brace

RE2 parses only a canonical repetition count and treats anything else as
literal text. `0{00}` is the five-character string `0{00}` in Go and a
zero-width repetition in Python, and `{,3}` and `{}` split the same way. The
braced forms the two engines agree on are not worth the ones they do not, so
the oracle declines any braced pattern.

### A regex compared against a value containing a newline

Python's `$` matches at the end of the text and also just before a trailing
newline; RE2's matches only at the end. So `$^` matches `"\n"` in the oracle
and not in Signalman, and the same split affects `^` and the newline class.
The oracle declines a `|re` comparison when the event value carries a
newline, because it cannot arbitrate between its own dialect and RE2. Go's
anchor behavior is covered by unit tests in `internal/sigma/match`.

### A pattern that does not finish

Python's engine backtracks and RE2 does not, so a pattern such as `(a+)+$`
answers in microseconds on one side and runs for minutes on the other, and
is not interruptible from inside Python. The oracle call has a five second
deadline; a timeout replaces the subprocess and counts the case as
unevaluated. The generator also declines to build nested quantifiers, so
these are rare rather than routine.

## Both engines evaluate, and the verdicts differ

### An absent field under a negation

SQL is three-valued. A comparison against a column the event does not carry
is NULL, and `NOT NULL` is NULL, which returns no row. Sigma says an absent
field does not match, so a negated condition over an absent field is true.

Suppressed only when the oracle reports that the rule read a field the event
does not carry, which is why the oracle returns the field list with every
verdict. The generator populates every mapped field, so this is a guard
rather than a routine skip.

### An empty encoded variant

`base64offset` of a very short plaintext determines no complete base64
character at some alignments, so one of the three variants is empty.
pySigma keeps it and emits `LIKE '%'`, which matches every event: the rule
alerts on everything. Signalman drops empty variants and rejects a chain
whose variants are all empty, which `docs/modifiers.md` records as a
deliberate divergence.

The oracle flags a query carrying a match-anything term so the Go side
recognizes the shape instead of reporting a decision as a bug.

## The bridge cannot express the case

Counted as skipped, not as agreement.

### A value that is not valid UTF-8

The bridge is newline-delimited JSON, and JSON cannot carry a string that is
not valid UTF-8; encoding one substitutes U+FFFD, so the oracle would answer
a different question. `yaml.Marshal` also renders such a value as a
`!!binary` node, which pySigma reads as bytes and refuses. Signalman's own
handling of invalid UTF-8 is covered by unit tests in `internal/sigma`.

### Values whose YAML rendering the two parsers read differently

The generator emits every value as a double-quoted scalar. Left to itself
`yaml.Marshal` picks the shortest form, and the shortest form of `=` is a
bare `=`, which PyYAML reads as the `tag:yaml.org,2002:value` tag and
refuses. Those are differences between two YAML libraries, not between two
Sigma engines.
