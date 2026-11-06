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

The compiled engine has started early: `internal/engine/v2` interns every
leaf predicate across the rule set, skips rules with a field presence
bitset and an Aho-Corasick literal prefilter, and evaluates the rest from a
per-event predicate bitset with no allocation. Its verdicts are compared
with v1's one by one and by per-partition digest; over the 1,236 accepted
`rules`-tree rules and 30.6 million generated verdicts they are identical.
In process on an M1 Pro it is about 125 times faster than v1 on the
benchmark event. `docs/evaluation.md` describes it and `docs/results.md`
has the numbers. The shadow lane, differ, and rollout that make up the rest
of Plan G need the pipeline first.

Three documents cover the surface: `docs/modifiers.md` (modifiers, chain
rules, divergences), `docs/taxonomy.md` (logsource binding and TaxonomyV),
and `docs/rule-loading.md` (the load pipeline, error codes, RuleSetV).
`docs/authoring.md` is the rule author's guide that sits on top of them.
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
signalman gates   --set rules rules/proc_dump.yml    # the five PR gates as a markdown report
```

Every command takes `--taxonomy` (default `config/taxonomy`). Exit codes
are 0 for pass, 1 for a failed check, 2 when the command could not run.
A corpus is a directory of `.ndjson` or `.jsonl` files, one JSON event per
line, with field names as they appear after the taxonomy. An event with a
key given twice in one object is rejected, and an empty object `{}` adds no
fields. A fixture file is one YAML document. A rule may
declare `budget:` in matches per 100k events; noise exits 1 above it.

Plan C's code has landed. `cmd/signalmand` consumes `events.raw`, assigns Seq
from the offset, normalizes through the taxonomy, evaluates with v1, and
writes `events.norm`, `verdicts.v1`, `alerts`, and `drops`, committing
offsets only after a batch's outputs are durable. Stages are joined by
bounded channels, rule set reloads land between batches, and an in-process
audit checks invariant 1 against the output topics. `internal/broker` puts
Redpanda (franz-go) and an in-memory broker behind one interface, so the
delivery logic is unit tested without Docker. `docs/pipeline.md` covers
topics, record formats, drop reasons, delivery, and the audit. The gate is
not passed: the audit is green over generated load in test mode, but the
one-hour soak against Redpanda has not been run.

`internal/backend/ch` is the second execution target. It compiles a loaded
rule into a ClickHouse WHERE clause over an events table, and `RetroHunt`
runs it over a time window through `database/sql`. Every node type and
modifier the frontend accepts compiles, and every rule the corpus loads
compiles. Where ClickHouse disagrees with Go (case folding, regex dot and
Unicode tables, NULL, number and address parsing, invalid UTF-8), the event
is stored with the value v1 would compute, so the SQL only compares.
`docs/backend-ch.md` lists each leak. The retro-hunt-equals-replay test is
written but has not yet run against a server.

A pull request that touches `rules/` runs `.github/workflows/rules.yml`:
`signalman gates` checks each changed rule for parse, fixtures, noise
budget, latency budget, and prefilter, and the report lands in one PR
comment and the job summary. A failed gate fails the job; a rule the
v2 prefilter cannot key on (the `Always` set) is a warning. A PR that also
changes `cmd/`, `internal/`, the taxonomy, or the corpus fails without
running the gates, since the gates would run its own code. The noise gate
runs when the repository variable `SIGNALMAN_NOISE_CORPUS` names a corpus
and is skipped otherwise. `docs/authoring.md` covers the supported Sigma
subset, rejection codes, fixtures, explain, budgets, and the gates.

The alert store is the other half of Plan D. `deploy/clickhouse/001_alerts.sql`
is the spec's `alerts` table (ReplacingMergeTree ordered by
`(partition, seq, rule_id)`, 90 day TTL), created by the compose ClickHouse
on first start. `cmd/signalman-sink` consumes the `alerts` topic and inserts
batches through clickhouse-go, committing offsets only after an insert
succeeds; while ClickHouse is down it retries and stops polling, so the
outage is consumer lag, not loss. A record the table cannot hold goes to
the `alerts.dead` topic, counted by `signalman_sink_dead_letters_total`; a
permanent insert error stops the sink with the offsets it holds. A
redelivered batch collapsing on merge is checked against a model of the
merge; the same check against a real ClickHouse is an integration test that
has not been run yet.

| Plan | What it delivers | State |
|---|---|---|
| A. Sigma frontend | event model, lexer, parser, AST, modifiers, taxonomy, rule loader, pySigma differential fuzzer | done: frontend loads 1478 of 3760 corpus rules with coded rejections; differential fuzzer green, gate passed |
| B. Reference evaluator and CLI | `internal/engine/v1`, verdict digest, `signalman test` and `explain` | done: twenty rules pass their fixtures; shuffle property green, gate passed |
| C. Pipeline | Redpanda ingest, normalizer, bounded stages, drop ledger, invariant audit job | in progress: all five stories built, audit green in test mode; one-hour soak on Redpanda not run |
| D. Sink and SQL backend | ClickHouse alert schema, AST to SQL compiler, retro-hunt | in progress: SQL compiler, retro-hunt, alert schema and idempotent sink built; ClickHouse integration tests not run, gate not passed |
| E. Observability | metrics, dashboards, canary generator, silence detector | not started |
| F. Load behavior | load harness, seven experiments, `docs/load.md` | not started |
| G. Compiled engine and cutover | `internal/engine/v2`, shadow lane, differ, rollout flags, `docs/cutover.md` | in progress: v2 engine (interning, prefilter, presence gating, 0 allocs/event) digest-identical to v1 on the corpus; shadow lane, differ, rollout not started |
| H. Author surface | `signalman lint / noise / bench`, rule PR CI gates, `docs/authoring.md` | in progress: lint, noise, bench, `budget:`, `signalman gates`, the rules workflow, and `docs/authoring.md` built; the workflow has not run on a real rule PR yet and no noise corpus is configured |

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
cmd/signalman/          CLI: test, explain, lint, bench, noise, gates
cmd/signalmand/         the pipeline daemon
cmd/signalman-sink/     alerts topic to the ClickHouse alerts table
cmd/differ/             shadow-mode verdict comparison
cmd/corpusaccept/       corpus acceptance report (dev tool, needs corpora/)
internal/event/         Event, Value, Verdict
internal/sigma/         lexer, parser, ast, detection, taxonomy, rule loader
internal/sigma/match/   wildcard matcher, all Sigma modifiers, modifier chain to Matcher
internal/engine/v1/     reference evaluator, permanent oracle (no index, no cache)
internal/fixture/       <rule>.test.yml loader and runner, through v1
internal/explain/       explain walker and renderer, held equal to v1 by test
internal/engine/v2/     compiled evaluator: interned predicates, presence gating, literal prefilter
internal/engine/v2/aho/ Aho-Corasick automaton for the prefilter
internal/backend/ch/    AST to ClickHouse SQL, events table schema, retro-hunt
internal/pipe/          ingest, normalizer, drop ledger, bounded stages, engine slot, invariant 1 audit
internal/pipe/chsink/   ClickHouse alert sink: batch insert, commit after insert, retry with backoff
internal/broker/        broker interface, in-memory implementation; kafka/ is franz-go
internal/obs/           metrics (canary is Plan E)
internal/verdict/       verdict digest, one rolling hash per partition
test/fuzz/              pySigma differential fuzzer, oracle bridge, KNOWN_DIVERGENCES.md
test/replay/            corpus replay, digest comparison
deploy/                 Dockerfile; docker compose for Redpanda, topic setup, and ClickHouse
deploy/clickhouse/      ClickHouse init SQL: the alerts table
docs/spec/              the spec (signalman-v1.html)
docs/modifiers.md       supported Sigma modifiers, chain rules, divergences
docs/taxonomy.md        logsource binding, field mapping, TaxonomyV
docs/rule-loading.md    load pipeline, rejection codes, RuleSetV
docs/corpus-acceptance.md  what loads from SigmaHQ and why the rest does not
docs/evaluation.md      the v1 and v2 evaluators and how verdict streams are compared
docs/pipeline.md        topics, Seq, drop reasons, at-least-once delivery, backpressure, the audit
docs/backend-ch.md      the ClickHouse backend, its schema, rejections, dialect leaks
docs/results.md         measured numbers: fuzzer, corpus, benchmarks
docs/authoring.md       writing rules: supported subset, rejections, fixtures, budgets, PR gates
corpora/                third-party rule corpus clone, gitignored
config/taxonomy/        logsource bindings, hashed into every verdict
rules/                  twenty hand-written rules, each with a .test.yml fixture
docs/superpowers/plans/ roadmap and per-plan task lists
docs/backlog.yml        Jira source of truth, synced by scripts/jira_sync.py
scripts/                backlog validator, Jira sync
.github/workflows/      ci, nightly fuzz, release, rules (the rule PR gates)
```

Directories under `cmd/`, `internal/`, and `test/` are created by the plan
that needs them.

## Working on it

- Go 1.27, module `github.com/atontalapur/signalman`.
- `make check` before every commit: gofmt, vet, `go mod tidy` diff, build,
  race tests, staticcheck, govulncheck. CI runs the same target.
- `make integration` needs Redpanda and ClickHouse from `deploy/docker-compose.yml`:
  `docker compose -f deploy/docker-compose.yml up -d --wait`. Integration tests
  carry the `integration` build tag and reach Redpanda at `localhost:19092`
  (override with `SIGNALMAN_BROKERS`). The ClickHouse tests (retro-hunt and
  alert sink) read a clickhouse-go DSN from `SIGNALMAN_CLICKHOUSE_DSN`, which
  `make integration` sets to the compose server. Without it they skip
  locally and fail when `CI=true`.
- Run the daemon against the compose stack:
  `go run ./cmd/signalmand -rules <dir> -taxonomy config/taxonomy`. It
  serves `/metrics` on `:9464`, reloads rules on `SIGHUP`, and by default
  refuses a rule directory with any rejection (`-strict=false` loads what it
  can). Worker pools, queue size, in-flight batches, and batch size are flags
  with fixed defaults, not derived from the machine.
- Run the alert sink alongside it: `go run ./cmd/signalman-sink`. It
  reads `alerts` as group `signalman-sink`, inserts into ClickHouse
  (`-clickhouse` DSN, defaulting to the compose stack), and serves
  `/metrics` on `:9465`. The table is created when the ClickHouse volume is
  first initialized; after changing the DDL, `docker compose down -v`.
  It needs the `alerts.dead` topic, which compose creates. Reset the
  Redpanda and ClickHouse volumes together: `seq` restarts with a new
  `events.raw` and would collide with stored alerts.
- `TestEndToEndUnderGeneratedLoad` in `internal/pipe` is the test-mode audit
  run; `SIGNALMAN_SOAK_DURATION=1h go test -timeout 2h -run EndToEnd ./internal/pipe`
  lengthens it, memory permitting.
- `make fuzz FUZZTIME=30s` runs every fuzz target except the differential
  one. Nightly CI runs them for 10 minutes each and uploads any crashers.
- `make fuzz-differential FUZZTIME=30m` runs the pySigma differential fuzzer
  and prints how many cases actually reached both engines; executions are not
  comparisons. `FUZZMINCOMPARED`, `FUZZMAXSUPPRESSED` and `FUZZMAXTIMEOUT`
  turn the counts into a pass or fail; nightly sets all three. It needs the oracle's virtualenv, which is gitignored:
  `python3 -m venv test/fuzz/.venv && test/fuzz/.venv/bin/pip install --require-hashes -r test/fuzz/requirements.txt`.
  Without it every case in `test/fuzz` skips, so a green `make check` on a
  machine with no venv says nothing about the fuzzer.
- The corpus tests in `internal/engine/v2` look for the SigmaHQ clone at
  `corpora/sigmahq` or at `SIGNALMAN_CORPUS`, and skip without it, as CI
  does. `SIGNALMAN_EQUIV_PER_RULE` lengthens the equivalence stream and
  `SIGNALMAN_LATENCY=1` turns on the latency report.
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
