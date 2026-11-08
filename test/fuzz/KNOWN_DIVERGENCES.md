# Known divergences between Signalman and the pySigma oracle

The differential fuzzer treats every disagreement as a Signalman bug until
proven otherwise. This file is the list of the exceptions, and it is a
deliverable rather than a workaround: a suppression without an entry here is
how a differential fuzzer quietly stops finding things.

Each section names the suppression that implements it. The Signalman-side and
oracle-side load suppressions live in `known()` in `oracle.go`; the oracle's
own refusals are raised in `pysigma_eval.py`; the verdict-level suppressions
are in the fuzz body in `differential_test.go`.

Every suppression keys on a code or an error type, never on message text.
Signalman's rejections are matched on `LoadError.Code` or, for RE2, on
`*syntax.Error` through `Unwrap`. The oracle's refusals carry a code from a
closed set (`refusalCodes` in `oracle.go`); pySigma and SQLite exceptions get
their code in `refusal_code()` from the exception class and the fixed start
of its message, which comes before any quoted value. Error messages quote
rule values and the fuzzer controls rule values, so a text match is one a
generated value can trigger. An oracle error without a code, or a broken
bridge (`ErrOracleBroken`), fails the case.

Checks on the generated SQL run with every string literal blanked first
(`strip_literals`), and checks about one modifier look only at that
modifier's values, for the same reason.

## How the oracle works, and what that costs

pySigma converts rules, it does not evaluate events. The oracle converts the
rule to a SQLite query, materializes the event as a single-row table, and
runs the query. That gives a genuinely independent parser, modifier
expansion, and comparison engine, which is the whole point. It also inherits
SQL's semantics where they differ from Sigma's, which is what most of this
file is about.

Three deliberate adjustments to make the comparison meaningful:

- **`COLLATE NOCASE` on every column.** Sigma string comparison is case
  insensitive by default. SQLite's `LIKE` already ignores ASCII case but its
  `=` does not, so without the collation the same rule would be case
  insensitive through `contains` and case sensitive through a plain equals.
  NOCASE folds ASCII only, so the oracle declines a case-insensitive
  comparison between two non-ASCII letters that differ only by case
  (below). An ASCII letter against a non-ASCII one is still compared, and
  that is how the fuzzer found Go lowercasing `İ` (U+0130) to `i`, so that
  `contains: İ` matched every `i` (inputs `6c2f3783bbcc1257`,
  `af3c814fc5bfa650`). Signalman's fold now never crosses the ASCII
  boundary (`match.Fold`, `docs/modifiers.md`).
- **A `regexp` function registered from Python's `re`.** SQLite ships no
  REGEXP implementation, so `|re` would otherwise fail to run at all.
- **`TEXT` affinity on every column.** The fuzzer sends integer and null
  event values as well as strings. Sigma compares a rule value against an
  event value as a string, so an integer is stored as its digits: `"443"`
  matches 443 and `"0443"` does not. `INTEGER` affinity would make SQLite
  coerce `"0443"` to 443 and agree with a comparison Sigma does not make.

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

### A rule with no level

Signalman requires a `level` from the five Sigma levels; pySigma allows a
rule without one. The alerts table stores severity as an enum, so a rule
with no level could not produce a storable alert. Recorded in
`docs/rule-loading.md` as `level`. The generator always writes one.

A rule whose id is not a UUID used to be listed here. Both sides now reject
it (Signalman as `invalid-id`), so it is agreement, not a divergence, and
`id-not-uuid` is no longer a suppressed refusal code.

### Aggregation and correlation

A `|` in the condition is rejected at load with the rule id, the line number,
and "aggregation is not supported". pySigma converts these. The scope cut is
in the spec and in `CLAUDE.md`; it is not up for revision by a fuzzer.

### A regular expression RE2 rejects

Go's `regexp` is RE2: no backreferences, no lookaround. Python's engine has
both. A pattern using them loads in the oracle and is a load error in
Signalman.

### A modifier chain over its fan-out budget

`windash` on a value with more than five switch-introducing dashes, or any
chain that expands to more than 4096 variants, is a `modifier` load error
here. pySigma has no budget and expands it. The limit is deliberate
(`docs/modifiers.md`): every variant is a matcher scanned on every event
that does not match. Keyed on `match.ErrFanOut`, which only those two
budgets wrap. The G0 fuzz matrix found it first, with
`-0ϳ-0ϳ-0ϳ-0ϳ-0ϳ-0`, input `0771b852e8440357`.

## The oracle will not answer

Some are refused in `pysigma_eval.py` before or after conversion, so the
failure is one clear sentence rather than whatever the backend raises. The
rest are raised by pySigma or SQLite and given a refusal code in
`refusal_code()`. Either way the Go side sees a code; each section names
which.

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
mis-generated. Detected on the generated SQL, not guessed from the rule:
refused only when a bare `NOT` is followed by an `OR` in its own
parenthesis group, with literals blanked. Code `unparenthesized-not`.

### `base64offset` on a non-ASCII value

The three offset encodings are trimmed at each end because the leading and
trailing base64 characters carry bits of the neighbouring plaintext. How much
to trim depends on how many **bytes** the plaintext occupies. pySigma indexes
its trim table by the string's **character** count, so for U+2029 it trims
three characters off an encoding that needed no trim at all and produces `4`
where the whole encoding `4oCp` is correct. The two agree on ASCII, where
bytes and characters coincide, and disagree on everything else.

`Base64Offsets` in `internal/sigma/match/encode.go` uses pySigma's table and
documents why its indexing is by bytes instead.

### A modifier pySigma does not carry

Suppressed on `Unknown modifier`. `utf16le` is a Sigma modifier name pySigma
does not know; it spells the same transform `wide`. The fuzzer generates the name both engines share, and the
suppression covers any other name that turns out to be missing.

### `wide` and `utf16` on anything but ASCII

pySigma's implementation encodes to UTF-16 and then decodes the result as
UTF-8, so these modifiers raise for most non-ASCII input. Signalman encodes
the text and compares bytes, which is what the modifier means.

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

### A case-insensitive regex on a character the engines fold differently

Measured over the whole BMP, `(?i)` in RE2 and `re.IGNORECASE` in Python
disagree on sixteen ordered pairs. Python treats `I`, `i`, `İ` (U+0130) and
`ı` (U+0131) as one case class; RE2 pairs only `I` and `i`. Go's Unicode
tables also case-pair U+A7CE to U+A7D5, which Python 3.14's do not yet.
`|re` is RE2 by design, and RE2 not matching `İ` to `I` agrees with the
string fold (`docs/modifiers.md`). The oracle declines with
`regex-casefold` when a `re|i` value or the event field it is matched
against holds one of those characters, or when a range in the value may
cover one without naming it (`[x-٬]` holds both Turkish i's; an escaped
endpoint is not decoded and counts as covering). The G0 fuzz matrix found
it first: `ParentImage|re|i: I` against `İ`, input `bbda9a31f50d0616`, then
`User|re|i: [x-٬]` against `I`, input `6821c336d738065b`.

### A case difference between two non-ASCII letters

SQLite's NOCASE and `LIKE` fold ASCII only, so `contains: Ώ` (U+038F)
against `ώ` (U+03CE) is no match in the oracle and a match in Signalman,
which folds Unicode as Sigma's case-insensitive default requires. The oracle
declines with `unicode-case` when a rule value and the event field it is
compared against hold two distinct non-ASCII characters that Python pairs
by `lower()` or `upper()`, or two of U+A7CE to U+A7D5, which Go's tables
pair and Python's do not yet. A key under `re` or `cased` is case sensitive and
is still compared. Teaching the oracle Unicode folding was rejected: it
would copy Signalman's own rule into the oracle, and Python's and Go's case
tables differ. Signalman's folding is covered by unit tests in
`internal/sigma/match`. The G0 fuzz matrix found it twice, under
`windash|contains` and `startswith`: inputs `c59e4d290ef6243b` and
`487f37ef076fc1bf`.

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
unevaluated. The fuzz target also skips patterns with a quantifier inside a
group (`reSafe`), so these are rare rather than routine.

## Both engines evaluate, and the verdicts differ

### An absent field under a negation

SQL is three-valued. A comparison against a column the event does not carry
is NULL, and `NOT NULL` is NULL, which returns no row. Sigma says an absent
field does not match, so a negated condition over an absent field is true.

Not suppressed: excluded by construction. The generator populates every
field a rule can read, and the fuzz target fails the case if the oracle
reports a field the event does not carry, since that means the generator
changed. `TestOracleReportsAbsentFieldGap` pins that the gap still exists.

### A null field under a negation

The same gap with a present field whose value is null. The generator does
produce nulls, so this one is suppressed: only when the condition contains
`not` and the oracle reports that the rule reads a field whose value is
null (`nullUnderNegation`). A null under a plain selection is not
suppressed, and both engines answer no match there. Every null case under
`not` lands here. The suppressed share with typed values was 0.233 over a
20 minute run and 0.30 over a 90 second one, where the early seeds weigh
more; nightly caps it at 0.40.

### An empty encoded variant

`base64offset` of a very short plaintext determines no complete base64
character at some alignments, so one of the three variants is empty.
pySigma keeps it and emits `LIKE '%'`, which matches every event: the rule
alerts on everything. Signalman drops empty variants and rejects a chain
whose variants are all empty, which `docs/modifiers.md` records as a
deliberate divergence.

The oracle flags a query carrying a match-anything term so the Go side
recognizes the shape instead of reporting a decision as a bug. Only under
`base64offset`, and only outside string literals: SQL writes a `'` in a
value as `''`, so a value such as `a='` used to read as an empty comparison
and suppress a real mismatch.

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
