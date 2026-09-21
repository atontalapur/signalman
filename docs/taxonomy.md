# Taxonomy and logsource binding

A Sigma rule names an abstract logsource and abstract field names. Neither
means anything on its own: `process_creation` is not a channel, and `Image`
is not a column. The taxonomy is the versioned config that binds them to a
real event stream.

Files live in `config/taxonomy/*.yml`, one logsource per file:

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
```

- `logsource` is the key a rule resolves against.
- `match` says which events belong to this logsource. It compiles into a
  `LogSourceMatcher`, an AND over the criteria, evaluated with the same
  matchers and the same walker as the rule condition.
- `fields` maps the rule's abstract field name to the event's field name.
  Sysmon calls it `Image`; the Security channel calls the same thing
  `NewProcessName`.

## Resolution is exact

All three components of the logsource must agree, and **a blank component is
a value, not a wildcard**. A rule declaring `product: windows, category:
process_creation` resolves to the Sysmon entry. A rule that also declares
`service: security` resolves to a different entry with a different field
mapping. A rule naming a service nobody mapped does not resolve at all and
fails to load with code `no-taxonomy`.

The alternative, treating a blank rule component as "any", was rejected: it
makes resolution depend on which entry the loader happens to reach first, and
a rule silently binding to the wrong channel is exactly the failure mode this
config exists to prevent.

Two files declaring the same logsource is a load error naming both paths, for
the same reason.

## Why the version is hashed into every verdict

`Taxonomy.Version` is `TaxonomyV`: a SHA-256 over every taxonomy file's name
and bytes, read in sorted order, truncated to 16 hex characters. It rides on
every verdict beside `RuleSetV`.

Change `event_id: 1` to `event_id: 2` and no rule has changed, but every rule
bound to that logsource now sees a different slice of the stream. Without a
version in the verdict, that shows up as an unexplained shift in alert
volume, and during the v1-to-v2 cutover it shows up as a digest divergence
with no cause. With it, the two verdict streams carry visibly different
`TaxonomyV` and the comparison is invalid by construction rather than
mysteriously wrong.

Sorted-order reading is what makes the hash reproducible across machines.

## A logsource mismatch is a verdict, not a silence

`LogSourceMatcher` is deliberately separate from the condition tree. When an
event does not belong to a rule's logsource, the engine emits an explicit
`false` verdict without walking the condition. That is the invariant: every
admitted event yields exactly one verdict per enabled rule, or exactly one
drop ledger entry. An absent verdict is never an acceptable answer, because
"no alert" and "never evaluated" have to be distinguishable when a detection
turns out to have been missing.

The zero `LogSourceMatcher` admits every event, which is what an entry with
no match criteria means.

## Where this is enforced

- `internal/sigma/taxonomy.go` — loading, hashing, resolution, matcher build
- `internal/sigma/testdata/taxonomy/` — fixtures, mirrored in `config/taxonomy/`
