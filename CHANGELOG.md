# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versions follow SemVer. `/ship` appends entries.

## [0.8.0] - 2026-10-21

### Added

- `signalman`, the rule author CLI. Every command takes `--taxonomy` and
  exits 0 on pass, 1 on a failed check, 2 when it could not run.
- `signalman test`: each rule ships a sibling `<rule>.test.yml` of match and
  no-match cases, run through the v1 evaluator. A disagreeing case, a
  missing fixture, or a fixture without both kinds of case fails.
- `signalman explain <rule> <event.json>`: the condition tree with each
  node's result, each leaf's observed value, and the logsource test. Its
  walker is held equal to v1 by a test over every shipped rule and fixture.
- `signalman lint`: every `LoadError` in structured form, or JSON with
  `--json`, duplicate ids across files included.
- `signalman bench`: p50, p99 and max per rule over a corpus or the
  fixtures; a p99 over the threshold (50us by default) fails.
- `signalman noise`: one rule over a corpus, with matches per 100k events
  and the first ten matches. A rule may declare `budget:` in matches per
  100k; noise fails above it. The budget does not enter RuleSetV.
- `rules/`: twenty hand-written rules, 56 fixture cases, all passing.
- The loader keeps each rule's expanded condition, selections and tags for
  `explain`. The bound tree and RuleSetV are unchanged.

### Fixed

- A YAML integer above MaxInt64 no longer wraps to a negative Int, and a
  float at or beyond 2^63 no longer converts differently per platform. Both
  stay as text.
- An event file or corpus line with a key given twice in one object is
  rejected instead of keeping the last copy. An empty object `{}` adds no
  fields; that is now documented and tested.
- A fixture file with a second YAML document is rejected instead of
  silently ignoring the second document's cases.
- One rule file named both relative and absolute loads once instead of
  reporting a false duplicate id.
- RuleSetV now covers each rule's logsource test and its renamed fields, and
  hashes predicate values quoted. A rule with and without
  `service: security` used to share a RuleSetV while giving different
  verdicts. Every RuleSetV value changes.

## [0.7.1] - 2026-10-01

### Changed

- The first-party GitHub Actions are pinned to commit SHAs too:
  `actions/checkout` v7.0.1, `actions/setup-go` v7.0.0,
  `actions/setup-python` v7.0.0, `actions/upload-artifact` v7.0.1. Every
  action in the CI, nightly and release workflows now runs a fixed commit,
  and Dependabot keeps the pins current.

## [0.7.0] - 2026-10-01

### Added

- A differential fuzzer that checks Signalman's verdicts against pySigma.
  Rules are generated from fuzz input (values, a modifier chain, a field, a
  condition shape), converted to SQLite by `pySigma-backend-sqlite`, and run
  against the same event; any disagreement fails. `make fuzz-differential`
  runs it and reports how many cases both engines actually evaluated, since
  executions are not comparisons. The Plan A gate run: 1,798,175
  executions, 673,225 verdict comparisons, no mismatches.
- The fuzzer also sends integer and null event values, so it checks how
  each engine compares a string rule value against them. A 20 minute run
  with them: 2,898,084 executions, 1,043,565 comparisons, no mismatches. The oracle stores
  every value as text, matching Sigma's string comparison, so `"0443"`
  does not match 443.
- Pass or fail thresholds on a fuzz run: a floor on verdict comparisons and
  caps on the share of cases suppressed or timed out
  (`FUZZMINCOMPARED`, `FUZZMAXSUPPRESSED`, `FUZZMAXTIMEOUT`). Nightly sets
  all three (100000, 0.40, 0.01), so a run that checked little, or one
  where a suppression grew, fails instead of reporting green.
- `test/fuzz/KNOWN_DIVERGENCES.md`: every case the fuzzer suppresses, why,
  and which code implements it. The fuzzer found two bugs in pySigma along
  the way: an unparenthesized `NOT` over modifier variants in the SQLite
  backend, and a `base64offset` trim indexed by characters instead of bytes.
- `docs/results.md`: measured numbers in one place, with the command and
  commit behind each, kept apart from targets that have not been measured.
- `LoadError` keeps the underlying cause of a detection error, so a caller
  can recognize an RE2 syntax rejection by type.

### Fixed

- The fuzzer's suppressions key on a code or an error type, never on
  message text. Earlier checks matched text inside generated rule values,
  so a value containing `='` or `NOT ... OR` could turn a real mismatch into
  a skip.
- A hung or crashed oracle is replaced and the case fails, instead of a late
  answer being read as the next case's verdict or a crash counting as both
  engines rejecting the rule.
- Fuzz counters are written atomically per process, so a worker killed
  mid-write no longer loses everything it counted.
- An oracle stuck in a backtracking regex no longer outlives a killed fuzz
  worker: a watcher process kills it once its parent is gone.

### Changed

- CI builds the pySigma oracle, so its tests run on every PR; with
  `CI=true` a missing oracle fails instead of skipping. The oracle's
  dependencies are hash-locked and installed with `--require-hashes`, and
  nightly and CI use Python 3.14.
- `make fuzz` leaves the differential target to `make fuzz-differential`,
  which is the one that checks its counts.

## [0.6.1] - 2026-10-01

### Changed

- Third-party GitHub Actions are pinned to commit SHAs, with the release
  version in a comment: `amannn/action-semantic-pull-request` v6.1.1,
  `docker/setup-qemu-action` v4.4.0, `docker/setup-buildx-action` v4.4.1,
  `docker/login-action` v4.6.0, `goreleaser/goreleaser-action` v7.2.3. A
  tag can be moved to different code; a SHA cannot, and the release job
  can write packages. Dependabot keeps the pins current.

### Added

- `.github/CODEOWNERS`: changes to CI, release config, the Makefile, and
  `scripts/` (which call Jira with a token) request the owner's review.

## [0.5.0] - 2026-09-21

### Added

- Every remaining Sigma modifier. Encoding transforms (`base64`,
  `base64offset`, `utf16le`, `utf16be`, `utf16`, `wide`, `windash`) expand a
  rule value at load time into the variants an attacker could have written,
  so the per-event path stays a flat OR with no decoding on it.
  `base64offset` uses pySigma's start offsets and end trims, because pySigma
  is the differential oracle; `windash` follows pySigma's rule for which
  dashes introduce a switch and expands each over five dash characters.
- Numeric comparison (`lt`, `lte`, `gt`, `gte`), `cidr`, and `fieldref`. A
  numeric comparison against an event value that does not parse is a
  no-match rather than an error, so one malformed field cannot stop the
  pipeline; an unparsable rule value is a load error, because that is an
  author mistake and there is somebody to tell. `cidr` parses and masks its
  prefix once, at load. `fieldref` compares two fields on the same event and
  treats absence as not a value, so two absent fields are not equal.
- A list-valued event field is an OR under every comparison, including the
  numeric operators, `cidr`, and `fieldref` on both sides. A `cidr` rule
  against a multi-valued IP field used to never match, and a silent
  never-match reads exactly like a clean no-match.
- `docs/modifiers.md`: the supported modifier surface, the three-stage chain
  pipeline, every validation rule, and the deliberate divergences from
  pySigma.

### Changed

- Modifier chains are validated before anything is built, so a nonsensical
  chain fails at load naming the chain instead of producing a matcher that
  ignores half of it. Rejected: two comparisons, `i` without `re`, a
  transform feeding `re`/`cidr`/a numeric comparison/`fieldref`, `fieldref`
  beside a comparison, any chain on a null value, and a chain whose variants
  are all empty. Every one wraps `ErrUnsupportedModifier`, which callers
  classify on with `errors.Is` rather than by error text.
- A modifier chain may not expand to more than 4096 variants in total.
  Per-transform caps could not see the multiplication across a chain, where
  `windash|base64offset` reaches 9375 matchers, each scanned on every
  non-matching event. No rule in the SigmaHQ corpus chains `windash` with an
  encoding, so nothing in practice is rejected.

## [0.4.0] - 2026-09-19

### Added

- `internal/sigma`: the condition frontend. `lex` tokenizes a condition
  string, folding keyword case and treating `*` as an identifier rune so
  `selection_*` stays one token; a `|` anywhere returns `ErrAggregation`,
  since an aggregation rule silently skipped is a missed detection with no
  signal attached.
- `ParseCondition`, recursive descent with one function per precedence
  level, giving `not` over `and` over `or`, left associative, with
  parentheses. `And` and `Or` are n-ary. Nesting is capped at 100 levels so
  a hostile condition cannot overflow the stack. A fuzz target asserts no
  input panics.
- `internal/sigma/ast`: the node types, plus `Eval`, the single walker over
  a bound tree, which panics on `Ident` and `Quant` because those reaching
  an evaluator is a binding bug, not bad input. `String` renders a node for
  explain output; `Canonical` quotes every name so a crafted selection name
  cannot collide with the tree structure when hashed.
- `Expand` rewrites `1 of`, `any of`, and `all of` into `And` and `Or` over
  the rule's defined selections, and rejects an identifier naming no
  selection. Names are copied and sorted first, so YAML key order and map
  iteration cannot reach the tree shape.

## [0.3.0] - 2026-09-16

### Added

- `internal/sigma/match`: Sigma value comparison. A purpose-built wildcard
  matcher (`*`, `?`, and the spec's backslash escapes) that never translates
  to regex, so metacharacters in command lines stay literal. String
  modifiers `contains`, `startswith`, `endswith` fold case; `re` is case
  sensitive unless `re|i`; `null` matches absent and explicit null, never
  the empty string. A list-valued event field matches when any element does.
- `match.Build` turns a detection key's modifier chain into one matcher,
  combining values with OR, or AND under `all`. Unknown modifiers, two
  comparisons, `i` without `re`, and a comparison on a null value are load
  errors wrapping `ErrUnsupportedModifier`. Encoding modifiers arrive in
  the next story.
- `event.ValueKind.String`, so errors name the kind.

## [0.2.0] - 2026-09-16

### Added

- `internal/event`, the first Go package: `Value`, a closed sum type over
  null, string, int, bool, and list; `Event`, the unit of work, whose
  `Field` reads an absent name as null so Sigma `field: null` matches both
  absence and an explicit null; and `Verdict`, the per (event, rule) record
  the v1 to v2 cutover compares.
- Go module `github.com/atontalapur/signalman` on Go 1.27. The `go` CI job
  now runs `make check` on every PR.

### Changed

- Toolchain moved from Go 1.23 to Go 1.27; staticcheck and govulncheck pins
  updated to versions that build on it.

## [0.1.0] - 2026-09-10

### Added

- `make check` runs the same gofmt, vet, tidy, build, race test, staticcheck,
  and govulncheck pass locally and in CI, so a green PR means a green machine.
- Nightly fuzzing with a ten minute budget per target; crashers are kept as
  workflow artifacts.
- Tag-driven releases: a `v*` tag builds every `cmd/*` binary for linux and
  darwin, publishes archives with checksums, and pushes the daemon image to
  GHCR. The tag must match `VERSION`.
- Dependabot for Go modules and GitHub Actions.
- PR policy: Conventional Commit titles and a `SIG-<n>` Jira reference are
  required to merge.
- `scripts/backlog_check.py` validates `docs/backlog.yml` before it is synced
  to Jira.
- Project `CLAUDE.md` with the spec invariants and a table of which gstack
  and superpowers skills to use at each point in the workflow; `.claude/`
  settings with a gofmt-on-write hook.
