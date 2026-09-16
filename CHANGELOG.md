# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versions follow SemVer. `/ship` appends entries.

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
