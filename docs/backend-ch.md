# ClickHouse SQL backend

`internal/backend/ch` compiles a loaded rule into a ClickHouse WHERE
expression, so a rule can be run over events that already happened
(retro-hunt). v1 is the oracle: a retro-hunt over a window must return the
same `(partition, seq)` rows as a v1 replay of the same events over the same
window. That is the Plan D gate.

The compiler is pure. It reads the bound tree and returns a string.
`RetroHunt` runs the query through `database/sql`, so the package imports no
driver; the integration test brings `clickhouse-go`.

## The events table

The spec fixes the `alerts` table, not an events table, so the schema is
defined here (`ch.CreateTableSQL`). It keeps the alert table's key,
`(partition, seq)`, and its 90 day retention, but partitions by day and
expires on `ingest_time`, not `event_time`. `event_time` comes from the
source: an old or skewed value would be deleted by the TTL as it arrives,
and one insert spread over more than 100 days of `event_time` would be
refused for touching too many partitions. `ingest_time` is set by the
pipeline and stays near now. `event_time` appears only in the hunt's WHERE
clause. The alert table's `fields Map(String, String)` is
replaced by one column per comparison family, each holding what v1 would
compute at match time, computed once in Go by `ch.Encode`:

| Column | Holds | Used by |
|---|---|---|
| `f_present Array(String)` | fields whose value is not null | `field: null` |
| `f_folded Map(String, Array(String))` | `strings.ToLower(Value.Text)` | equals, contains, startswith, endswith, wildcards, keywords |
| `f_text Map(String, Array(String))` | `Value.Text`, each invalid UTF-8 byte replaced by U+FFFD | `re` |
| `f_eqfold Map(String, Array(String))` | each rune replaced by the least rune of its `unicode.SimpleFold` orbit | `fieldref` |
| `f_ints Map(String, Array(Int64))` | values `strconv.ParseInt(strings.TrimSpace(s))` accepts, and ints | `lt` `lte` `gt` `gte` |
| `f_ips Map(String, Array(String))` | `netip.ParseAddr` results without a zone, as `4`+8 hex or `6`+32 hex | `cidr` |

Each map entry has one element per scalar, or one per text-bearing list
element. Null elements and nested lists are not stored, because v1 never
matches them.

The rule behind the table: the SQL never re-implements a Sigma semantic that
ClickHouse implements differently. Every leak below was resolved the same
way: compute the value in Go with the function v1 uses, store it, and leave
SQL only byte comparisons, set membership, and integer comparisons. The cost
is storage: five derived copies of every field.

The alternative, querying the alert table's `Map(String, String)` with
`lowerUTF8`, `ILIKE`, and `toInt64OrNull`, was rejected. It cannot represent
null, absence, or lists, and it would disagree with v1 on the leaks below,
so the retro-hunt would approximate.

## Compilation

| Node or modifier | SQL |
|---|---|
| `and`, `or`, `not` | `AND`, `OR`, `NOT`, every operand parenthesized |
| equals without wildcard | `has(f_folded[F], v)`; several values share one `hasAny` |
| `*lit`, `lit*`, `*lit*` | `endsWith`, `startsWith`, `position(...) > 0` inside `arrayExists` |
| any other wildcard | `LIKE`, with `%`, `_`, `\` escaped |
| `all` | `AND` across values |
| `re`, `re\|i` | `match(x, p)` over `f_text`, with `p` re-emitted from Go's parse tree |
| `cidr` | a byte range over `f_ips` |
| `lt` `lte` `gt` `gte` | `arrayExists(x -> x < N, f_ints[F])` |
| `base64` `base64offset` `utf16*` `wide` `windash` | expanded at compile time by `match.Plan`, then compiled as patterns |
| `field: null` | `NOT has(f_present, F)` |
| `fieldref` | `hasAny(f_eqfold[F], f_eqfold[G])` |
| keyword | the pattern over `arrayFlatten(mapValues(f_folded))` |
| logsource | the taxonomy's match criteria, `AND`ed in front of the condition |

The compiler reads `ast.Pred.Mods` and `Pred.Vals` and calls `match.Plan`,
the same function `match.Build` uses to make v1's closures. Wildcards are
read through `match.Wildcard.Parts`, so the backend never re-parses Sigma
escapes.

## Rejections

A `*ch.Rejection` carries the rule id, a code, and a reason. Nothing is
approximated.

| Code | When |
|---|---|
| `unbound-node` | an `Ident` or `Quant` left in the tree |
| `unknown-node` | a nil node |
| `pred-without-source` | a `Pred` with no `Vals`, so nothing to compile but a closure |
| `plan` | an entry `match.Plan` rejects |
| `regex` | a regex with no RE2 rendering |
| `too-large` | a WHERE clause over 256 KiB, ClickHouse's default `max_query_size` |

Every rule the frontend loads from the repo's test rules and from the
SigmaHQ corpus (1236 rules against `config/taxonomy`) compiles. The first
four codes are reachable only from hand-built trees. `too-large` is reached
by two `windash` values at the five-dash limit (6250 variants).

## Injection

Rule text never reaches the query except as a letter, a digit, a small set of
punctuation (` _.,:/@+=-%#&()`), or hex. Any value with another byte becomes
`unhex('...')`. No quote and no backslash is ever written inside a literal,
so a literal cannot end early and no escape is interpreted. The table name
is the only caller-supplied identifier and must match
`[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?`. Tests feed quotes,
backslashes, NUL, comments, and statement separators through every value
position and check the query's alphabet.

## Dialect leaks

Written down in the order they were found. "Docs" means the ClickHouse
documentation states the behavior; "unverified" means it has not yet been
checked against a server (see Gaps).

### String literal escapes swallow hex digits (docs)

`\xHH` in a ClickHouse string literal takes "any number of hex digits", so
`'\x5ccmd'` is not `\cmd`. Escaping was dropped in favour of `unhex`.

### `lowerUTF8` is not `strings.ToLower` (docs)

`lowerUTF8` is undefined on invalid UTF-8, and the case functions are
documented as possibly wrong for code points whose upper and lower forms have
different UTF-8 lengths. Go's `strings.ToLower` changes length freely: `İ` (2
bytes) to `i`, `K` (U+212A, 3 bytes) to `k`, `Ⱥ` (2 bytes) to `ⱥ` (3), and it
maps each invalid byte to U+FFFD. `ILIKE` and `positionCaseInsensitiveUTF8`
fold with their own rules. `caseFoldUTF8` does full folding (`ß` to `ss`),
which v1 does not: `contains: STRASSE` does not match `straße` in v1.
Resolved by `f_folded`.

### `fieldref` is not a lowercase comparison

v1 uses `strings.EqualFold`, which is simple-fold orbit equality, not
`ToLower` equality: `ſ` (U+017F) lowercases to itself but is `EqualFold` to
`s`. Comparing `f_folded` would be wrong, so `f_eqfold` stores each rune's
orbit minimum. Equal keys are exactly `EqualFold` (fuzzed).

### `.` matches newline in `match()` (docs)

ClickHouse sets RE2's `dot_nl`; Go does not. Passing the pattern through
would make `a.b` match `a\nb`. Resolved by re-emitting the regex from Go's
parse tree with no `.` in it: `.` becomes `[^\x{a}]`, `(?s).` becomes the
full rune range.

### Regex Unicode tables are versioned separately

`(?i)` folding and `\p{...}` classes come from each library's Unicode
tables, and Go and ClickHouse's RE2 ship different Unicode versions. The
re-emitted pattern contains neither: Go's parser has already expanded every
class into rune ranges, and each case-folded literal is written as the class
of its `SimpleFold` orbit. RE2 needs no table to agree with Go.

### `match()` is undefined on invalid UTF-8 (docs)

Go's regexp reads each invalid byte as U+FFFD. `f_text` stores exactly that
substitution, one byte for one rune, so RE2 sees valid UTF-8 with the rune
sequence Go saw.

### `match()` forbids NUL in the pattern (docs)

Every rune in the emitted pattern is written `\x{...}`, so the pattern is
ASCII with no NUL.

### Named captures are newer syntax

`(?<name>...)` is accepted by Go and only by recent RE2. A match test never
reads a group, so every capture is emitted as `(?:...)`.

### SQL NULL is three-valued; absence is not

In v1 an absent field reads as null, and `not (Image: x)` on an event with no
`Image` is true. Over a `Nullable` column, `NOT (NULL = 'x')` is NULL and the
row is dropped. A `Map(String, String)` lookup of a missing key returns `''`,
so `Image: ''` would match events that have no `Image`, and an explicit null
is indistinguishable from both. Resolved by having no `Nullable` column:
`f_present` answers null and absence, and a missing map key reads as an empty
array, which no `arrayExists` or `has` matches.

### Number parsing is not `strconv.ParseInt`

v1 trims with `strings.TrimSpace` (Unicode spaces), accepts a leading `+`,
and rejects overflow, hex, and underscores. ClickHouse's `toInt64OrNull`
family is not documented to agree on any of these, so it is not used.
Resolved by `f_ints`. A bare `-9223372036854775808` is unary minus on a
UInt64 literal, so integers are written `toInt64('N')`.

### Address parsing is not `netip`

`netip.ParseAddr` rejects IPv4 octets with leading zeros, a zoned address is
never inside a prefix, and an IPv4-mapped IPv6 address is not inside an IPv4
prefix. ClickHouse's `toIPv4`, `toIPv6`, and `isIPAddressInRange` are not
documented to agree. Resolved by `f_ips`: the family digit keeps v4 and v6
apart, and fixed-width hex makes byte order numeric order.

### Int and bool values compare as text

v1 compares an int field as its decimal text and a bool as `true`/`false`
(a documented divergence from pySigma). `f_folded` stores `Value.Text`, so
`EventID: 4688` matches an int and a string alike, as in v1.

### Lists

v1 matches a list field when any element matches. `Map(String, String)`
cannot hold one. Every column is an array per field.

### LIKE is code points only on valid UTF-8 (docs)

`_` is one code point, matching `?`, only on valid UTF-8. `f_folded` is
valid UTF-8 by construction, because `strings.ToLower` replaces invalid
bytes, and the folded pattern is too. `%`, `_`, and `\` in a literal are
escaped. The wildcard shapes are fuzzed against `match.Wildcard` through a
model of LIKE written from the documentation.

### ReplacingMergeTree holds duplicates until it merges

At-least-once delivery writes a batch twice. `SELECT DISTINCT` returns each
event once, before and after a merge.

### Query size

A `windash` value at the five-dash limit expands to 3125 patterns. Two of
them exceed ClickHouse's default 256 KiB `max_query_size`, so the compiler
rejects with `too-large` rather than fail at run time. The limit covers the
whole statement, so `HuntQuery` checks the full SELECT as well: a WHERE
clause just under the limit can still be rejected once wrapped.

### Event time precision

`event_time` is `DateTime64(3)`. `Encode` truncates to the millisecond and
the window is compared as `toUnixTimestamp64Milli`, so the query and the
replay read the same instant.

## Found in the frontend

`fieldref` names its target field in the rule value, and the taxonomy rename
rewrites `Pred.Field` but not the value. Under a mapping such as
`Image: NewProcessName`, `ParentImage|fieldref: Image` compares against a
field the event does not have, so v1 never matches. The backend mirrors v1,
because v1 is the oracle; the fix belongs in the rule loader. Recorded in
`TODOS.md`.

## Gaps

The integration test (`-tags integration`, `SIGNALMAN_CLICKHOUSE_DSN`) runs
against the compose server in CI's `integration` job, which fails the test if
the DSN is missing, and it passes. No ClickHouse was available when it was
written, so these started as assumptions, each exercised by its fixture:

- RE2 and Go agree on the emitted subset (`\x{...}`, classes, `\A`, `\z`,
  `(?m:^)`, `\b`, repeats).
- ClickHouse's own pattern analysis for `match()`, which extracts required
  substrings before calling RE2, reads `\x{...}` correctly.
- `LIKE '%'` crosses newlines.
- `clickhouse-go` inserts `Map(String, Array(String))` and
  `Map(String, Array(Int64))` through `database/sql` as written.
