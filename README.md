# Signalman

A Sigma detection engine and event pipeline in Go. Events come in over Kafka
(Redpanda), get normalized, are evaluated against the SigmaHQ rule corpus, and
the alerts land in ClickHouse. The part that makes it worth building is the
cutover: the evaluation core gets replaced by a faster compiled engine while
traffic is live, and the replacement has to be proven equivalent before the
old engine is retired.

## Status

Plan A is done. The module exists on Go 1.27 with three packages:
`internal/event` (the event value model), `internal/sigma/match` (the
wildcard matcher, every supported Sigma modifier, and `match.Build`, which
turns a modifier chain into one matcher), and `internal/sigma` (the condition
lexer, parser, quantifier expansion, detection block compilation, the
taxonomy loader, and the rule and rule set loaders) with its `ast`
subpackage.

A rule now goes from YAML to a bound, evaluable tree, or to a rejection
carrying a code, a reason, the rule id, and a line number. `config/taxonomy/`
holds the logsource bindings. `cmd/corpusaccept` reports how much of
the real SigmaHQ corpus loads: 1478 of 3760 live rules against a
three-logsource taxonomy, with three rules using Sigma features this engine
cannot express and the rest rejected as unmapped logsources. The numbers and
the per-code commentary are in `docs/corpus-acceptance.md`.

Loading is not matching, so `test/fuzz` compares the frontend against
pySigma: rules are converted to SQLite queries by
`pySigma-backend-sqlite` and run against the event as a single-row table,
which is an independent parser, modifier expansion, and comparison engine.
The fuzzer drives values, a modifier chain, a field, and a condition shape
into a valid rule skeleton and requires the two to agree, and every
suppression has a section in `test/fuzz/KNOWN_DIVERGENCES.md`. The run
counts are in `docs/results.md`.

Three documents cover the surface: `docs/modifiers.md` (modifiers, chain
rules, divergences), `docs/taxonomy.md` (logsource binding and TaxonomyV),
and `docs/rule-loading.md` (the load pipeline, error codes, RuleSetV).
The spec, roadmap, backlog, CI, and release tooling were in place before
the first Go code.

Plan B is done. `internal/engine/v1` evaluates every rule per event and
`internal/verdict` folds the verdicts into a per-partition digest; the
shuffle property test holds. `cmd/signalman` is the author CLI, and
`rules/` holds twenty hand-written rules, each with a sibling
`<rule>.test.yml` of match and no-match cases, all passing:

```
signalman test    rules/                         # run fixtures through v1
signalman explain rules/proc_dump.yml ev.json    # condition tree, results, observed values
signalman lint    rules/                         # every LoadError, structured (--json too)
signalman bench   rules/ [--corpus dir]          # p50/p99/max per rule, flags p99 over 50us
signalman noise   rules/proc_dump.yml --corpus dir   # matches per 100k, ten samples, budget:
```

Every command takes `--taxonomy` (default `config/taxonomy`). Exit codes
are 0 for pass, 1 for a failed check, 2 when the command could not run.
A corpus is a directory of `.ndjson` or `.jsonl` files, one JSON event per
line, with field names as they appear after the taxonomy. An event with a
key given twice in one object is rejected, and an empty object `{}` adds no
fields. A fixture file is one YAML document. A rule may
declare `budget:` in matches per 100k events; noise exits 1 above it.

| Plan | What it delivers | State |
|---|---|---|
| A. Sigma frontend | event model, lexer, parser, AST, modifiers, taxonomy, rule loader, pySigma differential fuzzer | done: frontend loads 1478 of 3760 corpus rules with coded rejections; differential fuzzer green, gate passed |
| B. Reference evaluator and CLI | `internal/engine/v1`, verdict digest, `signalman test` and `explain` | done: twenty rules pass their fixtures; shuffle property green, gate passed |
| C. Pipeline | Redpanda ingest, normalizer, bounded stages, drop ledger, invariant audit job | not started |
| D. Sink and SQL backend | ClickHouse alert schema, AST to SQL compiler, retro-hunt | not started |
| E. Observability | metrics, dashboards, canary generator, silence detector | not started |
| F. Load behavior | load harness, seven experiments, `docs/load.md` | not started |
| G. Compiled engine and cutover | `internal/engine/v2`, shadow lane, differ, rollout flags, `docs/cutover.md` | not started |
| H. Author surface | `signalman lint / noise / bench`, rule PR CI gates, `docs/authoring.md` | in progress: lint, noise, bench, and `budget:` done; rule PR CI gates and `docs/authoring.md` not started |

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
cmd/signalman/          CLI: test, explain, lint, bench, noise
cmd/signalmand/         the pipeline daemon
cmd/differ/             shadow-mode verdict comparison
cmd/corpusaccept/       corpus acceptance report (dev tool, needs corpora/)
internal/event/         Event, Value, Verdict
internal/sigma/         lexer, parser, ast, detection, taxonomy, rule loader
internal/sigma/match/   wildcard matcher, all Sigma modifiers, modifier chain to Matcher
internal/engine/v1/     reference evaluator, permanent oracle (no index, no cache)
internal/fixture/       <rule>.test.yml loader and runner, through v1
internal/explain/       explain walker and renderer, held equal to v1 by test
internal/engine/v2/     compiled evaluator
internal/backend/ch/    AST to ClickHouse SQL
internal/pipe/          stages, bounded queues, drop ledger
internal/obs/           metrics, canary
internal/verdict/       verdict digest, one rolling hash per partition
test/fuzz/              pySigma differential fuzzer, oracle bridge, KNOWN_DIVERGENCES.md
test/replay/            corpus replay, digest comparison
deploy/                 Dockerfile; docker compose for Redpanda and ClickHouse
docs/spec/              the spec (signalman-v1.html)
docs/modifiers.md       supported Sigma modifiers, chain rules, divergences
docs/taxonomy.md        logsource binding, field mapping, TaxonomyV
docs/rule-loading.md    load pipeline, rejection codes, RuleSetV
docs/corpus-acceptance.md  what loads from SigmaHQ and why the rest does not
docs/evaluation.md      the v1 evaluator and how verdict streams are compared
docs/results.md         measured numbers: fuzzer, corpus, benchmarks
corpora/                third-party rule corpus clone, gitignored
config/taxonomy/        logsource bindings, hashed into every verdict
rules/                  twenty hand-written rules, each with a .test.yml fixture
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
- `make fuzz FUZZTIME=30s` runs every fuzz target except the differential
  one. Nightly CI runs them for 10 minutes each and uploads any crashers.
- `make fuzz-differential FUZZTIME=30m` runs the pySigma differential fuzzer
  and prints how many cases actually reached both engines; executions are not
  comparisons. `FUZZMINCOMPARED`, `FUZZMAXSUPPRESSED` and `FUZZMAXTIMEOUT`
  turn the counts into a pass or fail; nightly sets all three. It needs the oracle's virtualenv, which is gitignored:
  `python3 -m venv test/fuzz/.venv && test/fuzz/.venv/bin/pip install --require-hashes -r test/fuzz/requirements.txt`.
  Without it every case in `test/fuzz` skips, so a green `make check` on a
  machine with no venv says nothing about the fuzzer.
- `make check-backlog` after editing `docs/backlog.yml`.
- Debt too small for a story lives in `TODOS.md`.
- Jira project SIG. One story per branch, `feat/SIG-<n>-<slug>`. PR titles are
  Conventional Commits; CI rejects PRs without a `SIG-<n>` in the title or body.
  `docs/backlog.yml` is the source for what the stories are (`scripts/jira_sync.py`
  pushes it); Jira is the source for where they stand. The GitHub for Jira app
  links branches and PRs to their story, and a Jira automation rule moves the
  story to Done when its PR merges.
- Releases are `v*` tags. The tag must match `VERSION` and sit on `main`;
  GoReleaser then publishes binaries for linux and darwin (amd64, arm64) and a
  `ghcr.io/atontalapur/signalman` image.
- Sync the backlog to Jira: copy `.env.example` to `.env`, fill it in, then
  `set -a; . ./.env; set +a; scripts/jira_sync.py`.

Agent instructions, including which gstack skills to use when, live in
`CLAUDE.md`.
