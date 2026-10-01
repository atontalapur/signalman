# Sigma modifiers in Signalman

What `internal/sigma/match` supports, what it rejects, and where it diverges
from pySigma. The matcher is a pure function of the value it is given: it
holds no clock, no cache, and no state between events.

A detection key is a field name followed by modifiers separated by `|`:

```yaml
CommandLine|windash|utf16le|base64offset|contains:
  - "-EncodedCommand"
```

`match.Build` receives the modifier list with the field name already
stripped, plus the rule values, and returns one `Matcher`.

## The pipeline

Every chain is evaluated in three stages, in this order:

1. **Encoding transforms**, applied to the rule value in written order.
   Each transform may fan out into several variants; any variant matching is
   a match.
2. **One comparison**, chosen by the comparison modifier, defaulting to
   equals.
3. **Combination across values**: `Any` (OR) unless `all` is present, in
   which case `All` (AND).

Written order is the contract for stage 1. `utf16le|base64offset` encodes the
text as UTF-16LE and then base64s those bytes. The reverse order base64s the
text and then treats the base64 as UTF-16, which matches nothing real.

Transforms are applied to the **rule value at load time**, never to the event
value at match time. A chain that produces 3125 variants produces 3125
matchers once, at load, and the per-event path stays a flat OR. That keeps
the hot path free of decoding and keeps the verdict a pure function of the
event.

## Comparisons

| Modifier | Meaning | Notes |
|---|---|---|
| none | equals | Case insensitive; honors `*` and `?` in the value |
| `contains` | substring | Wraps the value in `*` on both sides |
| `startswith` | prefix | Appends `*` |
| `endswith` | suffix | Prepends `*` |
| `re` | regular expression | **Case sensitive** unless `re|i` |
| `cidr` | IP prefix containment | Prefix parsed once, at load time |
| `lt` `lte` `gt` `gte` | signed integer comparison | Rule value must parse as an integer |
| `fieldref` | compare against another field on the same event | Case insensitive |

Exactly one comparison per chain. Two is a load error.

### Case sensitivity

Sigma string matching is case insensitive by default, and that is what this
package does. `re` is the one exception: it is case sensitive unless `i` is
present. `i` without `re` is a load error rather than a no-op, because a rule
author who writes it believes it is doing something.

### Numeric comparison on dirty data

A numeric comparison against an event value that does not parse as an integer
is **a no-match, not an error**. The data contract fixes this: one malformed
field must never stop the pipeline. A non-numeric value in the *rule* is a
different matter and fails at load time, because that is an author mistake
and there is a human to tell.

`null` and booleans never satisfy a numeric comparison.

### cidr

The prefix is parsed once with `netip.ParsePrefix` and masked at load time,
so per-event work is one `ParseAddr` and one `Contains`. IPv4 and IPv6 both
work, and they do not match across families: `10.1.2.3` is not inside
`2001:db8::/32`. An event value that is not an address is a no-match.

### List-valued event fields

A field can hold a list. Every comparison treats it as an OR: the field
matches if any element does. That holds for the string comparisons, for
`lt`/`lte`/`gt`/`gte`, for `cidr`, and for `fieldref` on both sides.

The alternative, having only the string comparisons reach inside lists, was
rejected: a `cidr` rule against a multi-valued IP field would then never
match, and a silent never-match is indistinguishable from a clean no-match.
That is the exact failure this engine exists to rule out.

A list nested inside a list does not match, and what the decoder does with
one is an open ingest-side question recorded in `TODOS.md`.

### fieldref

`fieldref` compares the event field against another field on the same event,
named by the rule value. It is the reason `Matcher.Match` takes the event as
well as the value.

Absence is not a value: if either side is absent, there is no match, even
when both are absent. Two fields are not equal because neither exists.

## Encoding transforms

| Modifier | Effect |
|---|---|
| `base64` | Standard base64 with padding |
| `base64offset` | The three byte alignments of the plaintext inside a larger blob |
| `utf16le`, `wide` | UTF-16 little endian, no BOM (`wide` is an alias) |
| `utf16be` | UTF-16 big endian, no BOM |
| `utf16` | UTF-16 little endian with a BOM |
| `windash` | Every switch-introducing dash replaced by each of five characters |

### base64offset

A plaintext string inside a longer base64 blob starts at one of three byte
alignments, and each alignment produces a different encoding. The leading and
trailing characters of each encoding carry bits of the neighbouring
plaintext, which is unknown, so they are trimmed. The start offsets are
`0, 2, 3` and the end trims are indexed by `(len(value)+i) % 3`. These are
pySigma's numbers, deliberately, because pySigma is the differential oracle.
The length is in bytes. pySigma counts characters, so the two agree on ASCII
and trim a multi-byte plaintext differently.

A plaintext of one to three bytes determines no complete base64 character at
a shifted alignment, so some of the three encodings come back empty. That is
correct and pySigma does the same. Empty variants are dropped; a chain where
*every* variant is empty is a load error, because the entry could never
match.

Because the encoding happens before the case fold, an encoded rule value is
effectively case sensitive: `MINIDUMP` and `MiniDump` encode to different
base64 characters. Rule authors have to write the case the attacker used.
This follows from the encoding, not from a choice made here.

### windash

A Windows command line parser accepts five characters where a rule author
wrote a hyphen: hyphen, slash, en dash, em dash, and horizontal bar.
`windash` finds every dash that introduces a switch and returns the cartesian
product over those five characters.

"Introduces a switch" means a `-` or `/` preceded by a non-word character and
followed by a word character, which is pySigma's rule (`\B[-/]\b`). A dash
inside a word is left alone, so `well-known` expands to one variant, not
five.

The expansion is capped at five dash positions, which is already 3125
matchers for one detection value. Above the cap the chain is rejected as an
unsupported modifier, with the count and the value in the message.

## Detection block shapes

`sigma.CompileDetection` turns the detection block into one predicate subtree
per selection name, and the shapes combine as the spec's implicit table says:

| Shape | Meaning |
|---|---|
| A map of field keys | AND across the keys |
| A list of values under one key | OR across the values, AND with `all` |
| A list of maps | OR across the maps, each map an AND |
| A list of bare scalars | keyword search: OR over every field value |
| A bare scalar | one keyword |

Map keys are sorted before the tree is built, so twenty compiles of the same
block produce the same tree. That matters because the tree feeds the rule set
hash, and a hash that moved with map iteration order would make two identical
rule sets look different.

`field: null` is the only null form, and it matches an absent field and an
explicit null but never an empty string. An empty string matches only a
present empty string.

A keyword predicate carries no field name. Its matcher ignores the value it
is handed and walks every field on the event in sorted order, reaching inside
list-valued fields. A null keyword is a load error, because `Contains("")`
would match every event carrying any field at all.

## Chain validation

Validated before anything is built, so a nonsensical chain is a load error
naming the chain rather than a matcher that quietly ignores half of it. Every
one of these wraps `match.ErrUnsupportedModifier`, which the rule loader
classifies on with `errors.Is` and never by error text:

- An unknown modifier.
- More than one comparison (`contains|startswith`, `lt|gt`, `cidr|contains`).
- `i` without `re`.
- An encoding transform feeding `re`, `cidr`, a numeric comparison, or
  `fieldref`. Encoded bytes are not a regex, an address, a number, or a field
  name.
- A chain whose transforms expand to more than 4096 variants in total. Each
  transform caps its own fan-out, but the counts multiply: `windash` at its
  five-position limit is 3125 variants, and chaining `base64offset` makes
  that 9375, every one a matcher scanned on every event that does not match.
  No rule in the SigmaHQ corpus chains `windash` with an encoding, so the
  budget rejects nothing real; it exists so a rule that would do it fails at
  load instead of quietly costing the pipeline orders of magnitude.
- `fieldref` beside a comparison.
- Any modifier chain on a `null` rule value. `field: null` is the only null
  form.

A rule value that is a list where a scalar belongs is a separate error naming
the kind, and a detection entry with no values at all is an error.

## Deliberate divergences from pySigma

Where the differential fuzzer can reach one of these, its suppression has a
section in `test/fuzz/KNOWN_DIVERGENCES.md`, alongside the divergences the
fuzzer found on its own.

| Divergence | Why |
|---|---|
| `fieldref` beside a comparison is rejected | pySigma allows it. Rejecting with a code beats silently picking one of the two. The corpus acceptance report carries the count. |
| `windash` above five dash positions is rejected | Unbounded load-time fan-out. 3125 matchers for one value is already generous. |
| A chain whose variants are all empty is rejected | pySigma would build an entry that can never match. The verdict invariant prefers a loud load error. |
| Int and bool event values compare by their decimal and `true`/`false` text | pySigma types its columns. The differential fuzzer covers the gap. |
| A bare keyword is `contains` over every field value, not a whole-value match | The spec reads whole-value. Every real corpus rule means substring, and a whole-value keyword matches almost nothing. |
| A null keyword is rejected | It would compile to a matcher that fires on every event with any field. |
| `base64offset` trims by byte length, not character count | base64 encodes bytes. pySigma's character count trims a non-ASCII plaintext wrongly. |

## Where this is enforced

- `internal/sigma/match/build.go` — chain parsing, validation, fan-out
- `internal/sigma/match/string.go` — the comparisons and the value combinators
- `internal/sigma/match/wildcard.go` — the wildcard matcher, never a regex translation
- `internal/sigma/match/encode.go` — the encoding transforms
- `internal/sigma/match/compare.go` — numeric, cidr, and fieldref
- `internal/sigma/detection.go` — detection block shapes, keywords, YAML scalars
