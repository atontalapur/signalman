# Signalman

A Sigma detection engine and event pipeline in Go. Events come in over Kafka
(Redpanda), get normalized, are evaluated against the SigmaHQ rule corpus, and
the alerts land in ClickHouse. The part that makes it worth building is the
cutover: the evaluation core gets replaced by a faster compiled engine while
traffic is live, and the replacement has to be proven equivalent before the
old engine is retired.

## Status

Plan A is in progress. The module exists on Go 1.27 with one package,
`internal/event` (Task 1 of the Sigma frontend plan). The spec, roadmap,
backlog, CI, and release tooling were in place before the first Go code.

| Plan | What it delivers | State |
|---|---|---|
| A. Sigma frontend | event model, lexer, parser, AST, modifiers, taxonomy, rule loader, pySigma differential fuzzer | in progress: event model done, lexer next |
| B. Reference evaluator and CLI | `internal/engine/v1`, verdict digest, `signalman test` and `explain` | not started |
| C. Pipeline | Redpanda ingest, normalizer, bounded stages, drop ledger, invariant audit job | not started |
| D. Sink and SQL backend | ClickHouse alert schema, AST to SQL compiler, retro-hunt | not started |
| E. Observability | metrics, dashboards, canary generator, silence detector | not started |
| F. Load behavior | load harness, seven experiments, `docs/load.md` | not started |
| G. Compiled engine and cutover | `internal/engine/v2`, shadow lane, differ, rollout flags, `docs/cutover.md` | not started |
| H. Author surface | `signalman lint / noise / bench`, rule PR CI gates, `docs/authoring.md` | not started |

A plan is done when its gate in the roadmap passes, not when its tasks are
ticked. Plan G is the point; C through F exist so G has real traffic, real
metrics, and a baseline to compare against.

## How it works

```
Redpanda topic -> ingest -> normalize -> evaluate (v1 | v2 shadow) -> sink -> ClickHouse
                     |          |            |                          |
                     +----------+------ drop ledger ------+-------------+
```

- Every stage boundary is a bounded channel. The pipeline lags rather than
  sheds load.
- A verdict is a pure function of `(Event, RuleSetV, TaxonomyV)`. No wall
  clock, no randomness, no dependence on map iteration or rule load order.
  This is what makes two engines comparable by digest.
- Every admitted event yields exactly one verdict per enabled rule or exactly
  one drop ledger entry. An audit job reconciles ingested count against
  verdicts plus drops.
- `internal/engine/v1` is the reference evaluator and permanent oracle. It is
  never optimized. `internal/engine/v2` is the compiled engine that runs in a
  shadow lane, gets diffed against v1, and is promoted through gates G0 to G6.

## What it deliberately does not do

Sigma correlations and aggregations (rejected at rule load with the rule ID
and line number), enrichment, case management, multi-tenancy. Each of these
will look reasonable around week six. Adding any of them costs the cutover.

## Repository

```
cmd/signalman/          CLI: lint, test, explain, noise, bench
cmd/signalmand/         the pipeline daemon
cmd/differ/             shadow-mode verdict comparison
internal/event/         Event, Value, Verdict
internal/sigma/         lexer, parser, ast, modifiers, taxonomy, rule loader
internal/engine/v1/     reference evaluator, permanent oracle
internal/engine/v2/     compiled evaluator
internal/backend/ch/    AST to ClickHouse SQL
internal/pipe/          stages, bounded queues, drop ledger
internal/obs/           metrics, canary
internal/verdict/       digest
test/fuzz/              differential and parser fuzzers
test/replay/            corpus replay, digest comparison
deploy/                 Dockerfile; docker compose for Redpanda and ClickHouse
docs/spec/              the spec (signalman-v1.html)
docs/superpowers/plans/ roadmap and per-plan task lists
docs/backlog.yml        Jira source of truth, synced by scripts/jira_sync.py
scripts/                backlog validator, Jira sync
```

Directories under `cmd/`, `internal/`, and `test/` are created by the plan
that needs them.

## Working on it

- Go 1.27, module `github.com/atontalapur/signalman`.
- `make check` before every commit: gofmt, vet, `go mod tidy` diff, build,
  race tests, staticcheck, govulncheck. CI runs the same target.
- `make integration` needs Redpanda and ClickHouse from `deploy/docker-compose.yml`.
- `make fuzz FUZZTIME=30s` runs every fuzz target. Nightly CI runs them for
  10 minutes each and uploads any crashers.
- `make check-backlog` after editing `docs/backlog.yml`.
- Debt too small for a story lives in `TODOS.md`.
- Jira project SIG. One story per branch, `feat/SIG-<n>-<slug>`. PR titles are
  Conventional Commits; CI rejects PRs without a `SIG-<n>` in the title or body.
- Releases are `v*` tags. The tag must match `VERSION` and sit on `main`;
  GoReleaser then publishes binaries for linux and darwin (amd64, arm64) and a
  `ghcr.io/atontalapur/signalman` image.
- Sync the backlog to Jira: copy `.env.example` to `.env`, fill it in, then
  `set -a; . ./.env; set +a; scripts/jira_sync.py`.

Agent instructions, including which gstack skills to use when, live in
`CLAUDE.md`.
