# Signalman

Sigma detection engine and event pipeline in Go. The point of the project is
the v1 to v2 engine cutover under live traffic; everything else exists to make
that cutover provable. Read `README.md` first, then the roadmap.

- Spec: `docs/spec/signalman-v1.html`
- Roadmap and per-plan task lists: `docs/superpowers/plans/`
- Backlog (Jira source of truth): `docs/backlog.yml`, synced by `scripts/jira_sync.py`

## Invariants that override convenience

Copied from the spec. Do not trade any of these for a shortcut.

- A verdict is a pure function of `(Event, RuleSetV, TaxonomyV)`. No wall
  clock, no randomness, no map iteration order, no rule load order.
- Every admitted event yields exactly one verdict per enabled rule or exactly
  one drop ledger entry. Logsource mismatch is an explicit `false` verdict.
- Aggregation and correlation rules (`|` in the condition) are rejected at
  load time with rule ID, line number, and "aggregation is not supported".
- Sigma string matching is case insensitive by default; `|re` is case
  sensitive unless `|re|i`. Wildcards use the purpose-built matcher, never
  regex translation.
- Every stage boundary is a bounded channel. Lag over loss; never shed load.
- Non-goals stay cut: correlations, enrichment, case management, multi-tenancy.

## Commands

- `make check` before every commit. It is what CI runs: gofmt, vet, tidy,
  build, race tests, staticcheck, govulncheck.
- `make integration` needs Redpanda and ClickHouse from `deploy/docker-compose.yml`.
- `make fuzz FUZZTIME=30s` runs every fuzz target; nightly CI runs 10m each.
- `make check-backlog` after editing `docs/backlog.yml`.
- Go 1.23. Module path `github.com/atontalapur/signalman`.

## Workflow

- One Jira story per branch: `feat/SIG-<n>-<slug>`. PR title is a Conventional
  Commit; PR body names the story. CI rejects PRs without a `SIG-<n>`.
- Never commit to `main`. One logical change per commit; ask before committing.
- Tests first. Each plan task in `docs/superpowers/plans/` is written as
  failing test, then implementation. Follow that order.
- A plan is done when its gate in the roadmap passes, not when tasks are ticked.
- No emojis in code, comments, docs, or commits. Keep prose short.

## Skill routing

gstack lives at `~/.claude/skills/gstack`. Install if missing:
`git clone --depth 1 https://github.com/garrytan/gstack.git ~/.claude/skills/gstack && cd ~/.claude/skills/gstack && ./setup`.

Use these at these moments. Do not improvise the workflow they cover.

| When | Skill |
|---|---|
| Starting a new plan (B through H) from the roadmap | `superpowers:brainstorming`, then `superpowers:writing-plans` into `docs/superpowers/plans/` |
| A plan file exists and coding is about to start | `/plan-eng-review` (architecture, data flow, edge cases). `/autoplan` when you want all reviews with auto-decisions. |
| Executing a plan task by task | `superpowers:subagent-driven-development` or `superpowers:executing-plans` |
| Writing any code | `superpowers:test-driven-development` |
| A test fails, a fuzzer finds a crasher, a digest diverges | `/investigate`. No fix without a root cause. |
| Before opening a PR | `/review` on the diff |
| Opening the PR | `/ship`. It runs `make check`, bumps `VERSION`, updates `CHANGELOG.md`, pushes, creates the PR. Do not `gh pr create` by hand. |
| After a PR merges | `/document-release` to sync README, CLAUDE.md, CHANGELOG with what shipped |
| Touching CI, secrets, the Jira token, or `scripts/` that call external APIs | `/cso` |
| Anything touching `deploy/`, Docker volumes, or `git` history | `/careful` first |
| End of a sprint (every two weeks per `docs/backlog.yml`) | `/retro`, then `/health` |
| Filing a new story or splitting one | `/spec`, then add it to `docs/backlog.yml` and run `make check-backlog` |
| "Didn't we hit this before?" | `/learn` |
| Any web browsing | `/browse`. Never `mcp__claude-in-chrome__*`. |
| Rendering a pipeline or cutover diagram for `docs/` | `/diagram` |

Not used here: `/qa`, `/design-*`, `/devex-review`, `/ios-*`, `/land-and-deploy`.
There is no web UI and nothing deploys automatically; releases are `v*` tags.

## Layout

See "Repository layout" in the roadmap. `internal/sigma/match` must not import
`internal/sigma/ast`; the dependency runs one way. `internal/engine/v1` is the
permanent oracle and is never optimized for speed.
