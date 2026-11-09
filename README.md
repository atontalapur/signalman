# Signalman

A Sigma detection engine and event pipeline in Go. Events come in over Kafka
(Redpanda), get normalized, are evaluated against the SigmaHQ rule corpus, and
the alerts land in ClickHouse. The part that makes it worth building is the
cutover: the evaluation core gets replaced by a faster compiled engine while
traffic is live, and the replacement has to be proven equivalent before the
old engine is retired.

## Status

Plan A is done. It delivered three packages on Go 1.27:
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
has the numbers.

The shadow lane and differ are built. `signalmand -shadow` evaluates every
normalized event with v2 beside v1, in the same batch, and writes
`verdicts.v2` with no alerts. `cmd/differ` joins `verdicts.v1` and
`verdicts.v2` on `(partition, seq, rule_id)` and classifies every
disagreement into the spec's five classes, writing each to the
`divergences` topic and the log. `signalmand -rollout <file>` hands a
rule's alerts to v2 when `fnv(rule_id) mod 100` is below the file's
percentage, while v1 keeps evaluating and recording every rule; editing the
file is the rollback, and it lands at the next batch. `docs/cutover.md` has
the four arguments, the gate ladder, the retirement criteria, the rollout
design, and the divergence log. G0, offline equivalence, passed on
2026-11-08: the corpus replay digests match on every partition and the
differential fuzzer made 133.6 million clean comparisons on a 12-shard
GitHub Actions matrix (`g0-fuzz.yml`). G1 to G6 need live traffic; shadow
mode and the rollout have only run over the in-memory broker in tests.

The gate tooling is built. `cmd/cutover check` evaluates one gate from its
sources (a corpus replay and the fuzzer's counters for G0, Prometheus for
G1 to G6, a game day result for the rollback timings) and prints every
criterion with its evidence. A gate with a window also checks the window
was scraped for at least 95% of it, and G6 checks the invariant 1 audit ran
throughout. With `-record` it dates a passed gate in `docs/cutover.md`, in
ladder order and never for a window that has not ended. `cmd/cutover gameday` rolls the rollout file back and
forward and times both from metrics. `signalmand -serve v2` is the
configuration after G6: v2 serves every rule, and v1 either shadows as the
oracle or is out of the pipeline. The default is still v1. None of this has
run against real traffic, so no gate past G0 has a date and no game day
has been measured.

Three documents cover the surface: `docs/modifiers.md` (modifiers, chain
rules, divergences), `docs/taxonomy.md` (logsource binding and TaxonomyV),
and `docs/rule-loading.md` (the load pipeline, error codes, RuleSetV).
`docs/authoring.md` is the rule author's guide that sits on top of them.
The spec, roadmap, backlog, CI, and release tooling were in place before
the first Go code.

Plan B is done. `internal/engine/v1` evaluates every rule per event and
`internal/verdict` folds the verdicts into a per-partition digest; the
shuffle property test holds. `cmd/signalman` is the author CLI, and
`rules/` holds twenty hand-written rules (and, since Plan E, the
`signalman-canary` rule), each with a sibling
`<rule>.test.yml` of match and no-match cases, all passing:

```
signalman test    rules/                         # run fixtures through v1
signalman explain rules/proc_dump.yml ev.json    # condition tree, results, observed values
signalman lint    rules/                         # every LoadError, structured (--json too)
signalman bench   rules/ [--corpus dir]          # p50/p99/max per rule, flags p99 over 50us
signalman noise   rules/proc_dump.yml --corpus dir   # matches per 100k, ten samples, budget:
signalman gates   --set rules rules/proc_dump.yml    # the five PR gates as a markdown report
signalman hunt    --from T --to T rules/             # retro-hunt over the ClickHouse events table
```

Every command takes `--taxonomy` (default `config/taxonomy`). Exit codes
are 0 for pass, 1 for a failed check, 2 when the command could not run.
A corpus is a directory of `.ndjson` or `.jsonl` files, one JSON event per
line, with field names as they appear after the taxonomy. An event with a
key given twice in one object is rejected, and an empty object `{}` adds no
fields. A fixture file is one YAML document. A rule may
declare `budget:` in matches per 100k events; noise exits 1 above it.

Plan F has started. `internal/loadtest` runs the pipeline in process over
the in-memory broker behind a tap that checks every batch's outputs, and
`cmd/loadgen` replays a corpus (ndjson, or events generated from a rule
directory) into `events.raw` on Kafka at a multiple of a measured baseline.
All seven spec experiments ran in process: under 2x and 5x overload, a
consumer killed between durable outputs and commit, poison records, rule
reloads every 250 ms, a 30 s output outage, and an offline partition, every
event ended as verdicts or a drop, and the verdict digest matched a clean
replay wherever one is comparable. Overload showed up as broker lag,
never as loss. `docs/load.md` has the answers and lists what still needs Redpanda and ClickHouse.

Plan C's code has landed. `cmd/signalmand` consumes `events.raw`, assigns Seq
from the offset, normalizes through the taxonomy, evaluates with v1, and
writes `events.norm`, `verdicts.v1`, `alerts`, and `drops`, committing
offsets only after a batch's outputs are durable. Stages are joined by
bounded channels, rule set reloads land between batches, and an in-process
audit checks invariant 1 against the output topics. `internal/broker` puts
Redpanda (franz-go) and an in-memory broker behind one interface, so the
delivery logic is unit tested without Docker. `docs/pipeline.md` covers
topics, record formats, drop reasons, delivery, and the audit. The gate
passed on the compose stack: 3.72 million events over 62 minutes at 1,000/s
through the real binaries, 2,992 audit windows, zero violations
(`docs/results.md`).

`internal/backend/ch` is the second execution target. It compiles a loaded
rule into a ClickHouse WHERE clause over an events table, and `RetroHunt`
runs it over a time window through `database/sql`. Every node type and
modifier the frontend accepts compiles, and every rule the corpus loads
compiles. Where ClickHouse disagrees with Go (case folding, regex dot and
Unicode tables, NULL, number and address parsing, invalid UTF-8), the event
is stored with the value v1 would compute, so the SQL only compares.
`docs/backend-ch.md` lists each leak. `signalman-sink -lane events` stores
`events.norm` in that table (`deploy/clickhouse/003_events.sql`), and
`signalman hunt --from --to rules/` runs rules over it. In CI's
`integration` job, against the compose ClickHouse,
`TestRetroHuntEqualsReplay` checks every node type over synthetic rules, and
`TestHuntEqualsReplayOverTheRuleDirectory` runs `signalman hunt` over every
fixture event of every rule in `rules/` and requires each rule's rows to
equal a v1 replay; both pass. That is the Plan D gate.

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
merge; `TestReingestCollapsesInClickHouse` makes the same check against the
compose ClickHouse in CI's `integration` job and passes.

Plan E's code has landed. Every metric in the spec's core metrics table is
exported with its type and labels, and a test holds the registered set to
the table. `signalman_event_staleness_seconds` (now minus the newest event
time) is separate from consumer lag. A canary generator in `signalmand`
writes a synthetic event to every `events.raw` partition every 30 seconds;
`rules/signalman_canary.yml` turns it into an alert. Two ages track it:
`signalman_canary_age_seconds` in signalmand resets when the alert is
durable on the `alerts` topic, and `signalman_sink_canary_age_seconds` in
signalman-sink resets when it is stored in ClickHouse, so a dead sink or
ClickHouse pages too and the pair says which half failed.
`deploy/prometheus/` scrapes both binaries and has the alert rules:
`SignalmanCanaryStalled`, `SignalmanCanaryAbsent`, and their `SignalmanSink`
counterparts page, `SignalmanRuleWentSilent` files a ticket. `deploy/grafana/` has the
dashboard. In-process tests kill the consumer under a fake clock and show
the page fires within two minutes, and show a taxonomy field rename
silencing exactly the rules that read the field. On the compose stack a
`kill -9` of signalmand paged in 51 s and a paused Redpanda in 95 s, both
through Prometheus, so the gate passed (`docs/results.md`).
`docs/pipeline.md` covers the metrics, the canary, and the silence
detector.

| Plan | What it delivers | State |
|---|---|---|
| A. Sigma frontend | event model, lexer, parser, AST, modifiers, taxonomy, rule loader, pySigma differential fuzzer | done: frontend loads 1478 of 3760 corpus rules with coded rejections; differential fuzzer green, gate passed |
| B. Reference evaluator and CLI | `internal/engine/v1`, verdict digest, `signalman test` and `explain` | done: twenty rules pass their fixtures; shuffle property green, gate passed |
| C. Pipeline | Redpanda ingest, normalizer, bounded stages, drop ledger, invariant audit job | done: one-hour soak on Redpanda, 3.72M events, audit green throughout, gate passed |
| D. Sink and SQL backend | ClickHouse alert schema, AST to SQL compiler, retro-hunt | done: SQL compiler, alert and events sinks, `signalman hunt`; the hunt over `rules/` equals a v1 replay on a real ClickHouse, gate passed |
| E. Observability | metrics, dashboards, canary generator, silence detector | done: a killed signalmand pages in 51 s and a stalled one in 95 s on the compose stack, gate passed |
| F. Load behavior | load harness, seven experiments, `docs/load.md` | in progress: `cmd/loadgen` and `internal/loadtest` built; v1 baseline 2,465 events/s on 1,236 rules in process; all seven experiments run in process over the in-memory broker (zero drops at 2x, digest unchanged after consumer kills); on Redpanda and ClickHouse, overload, five kills, a 10-minute ClickHouse outage, poison records, and reloads lost nothing; one partition offline needs a multi-broker cluster, not run |
| G. Compiled engine and cutover | `internal/engine/v2`, shadow lane, differ, rollout flags, gate checker, game day, `docs/cutover.md` | in progress: v2 engine digest-identical to v1 on the corpus; shadow lane, differ, per-rule rollout with file-driven rollback, the G0 to G6 gate checker, the game day tool, and `-serve v2` built and tested in memory; G0 passed (offline); G1 to G6 not run against traffic, no game day run |
| H. Author surface | `signalman lint / noise / bench`, rule PR CI gates, `docs/authoring.md` | in progress: lint, noise, bench, `budget:`, `signalman gates`, the rules workflow, and `docs/authoring.md` built; the workflow passed on its first real rule PR (`signalman-canary`, #44); a synthetic benign noise corpus (`testdata/noise`) on which no shipped rule fires |

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
cmd/signalman/          CLI: test, explain, lint, bench, noise, gates, hunt
cmd/signalmand/         the pipeline daemon
cmd/loadgen/            replays a corpus into events.raw at a multiple of a baseline rate
cmd/signalman-sink/     alerts topic to the ClickHouse alerts table; -lane events: events.norm to the events table
cmd/differ/             shadow-mode verdict comparison: verdicts.v1 x verdicts.v2 -> divergences
cmd/cutover/            gate ladder checker (check -record) and rollback game day (gameday, measure)
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
internal/pipe/          ingest, normalizer, drop ledger, bounded stages, engine slot, shadow lane, rollout, invariant 1 audit, canary generator
internal/pipe/chsink/   ClickHouse sink lanes (alerts, events): batch insert, commit after insert, retry with backoff
internal/differ/        bounded merge join of the two verdict streams, divergence classes
internal/cutover/       gate criteria G0 to G6, Prometheus source, corpus replay, game day measurement, docs/cutover.md recording
internal/corpus/        NDJSON event corpus reader shared by noise, bench and the G0 replay
internal/broker/        broker interface, in-memory implementation; kafka/ is franz-go
internal/loadtest/      in-process load harness: pacer, output tap, failure injection, the seven experiments
internal/obs/           metrics, including the scrape-time staleness and canary age gauges
internal/verdict/       verdict digest, one rolling hash per partition
test/fuzz/              pySigma differential fuzzer, oracle bridge, KNOWN_DIVERGENCES.md
deploy/                 Dockerfile; docker compose for Redpanda, topic setup, ClickHouse, Prometheus, Grafana
deploy/clickhouse/      ClickHouse init SQL: the alerts table (spec columns plus engine), its migration, and the events table
deploy/prometheus/      scrape config, alert rules (absence, pipeline), promtool tests
deploy/grafana/         provisioning and the pipeline dashboard
docs/spec/              the spec (signalman-v1.html)
docs/modifiers.md       supported Sigma modifiers, chain rules, divergences
docs/taxonomy.md        logsource binding, field mapping, TaxonomyV
docs/rule-loading.md    load pipeline, rejection codes, RuleSetV
docs/corpus-acceptance.md  what loads from SigmaHQ and why the rest does not
docs/evaluation.md      the v1 and v2 evaluators and how verdict streams are compared
docs/pipeline.md        topics, Seq, drop reasons, at-least-once delivery, backpressure, the audit
docs/cutover.md         the four arguments, gate ladder G0 to G6, retirement criteria, gate checker, game day, divergence log
docs/backend-ch.md      the ClickHouse backend, its schema, rejections, dialect leaks
docs/load.md            the seven load experiments: where work queued, what fell behind, correctness
docs/results.md         measured numbers: fuzzer, corpus, benchmarks, pipeline baseline
docs/authoring.md       writing rules: supported subset, rejections, fixtures, budgets, PR gates
corpora/                third-party rule corpus clone, gitignored
config/taxonomy/        logsource bindings, hashed into every verdict
rules/                  twenty hand-written rules and signalman-canary, each with a .test.yml fixture
docs/superpowers/plans/ roadmap and per-plan task lists
docs/backlog.yml        Jira source of truth, synced by scripts/jira_sync.py
scripts/                backlog validator, Jira sync, differential fuzzer run stats, noise corpus generator
testdata/noise/         the synthetic benign corpus the noise gate measures rules against
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
  with fixed defaults, not derived from the machine. The canary runs every
  `-canary-interval` (30s; 0 turns it off) and needs the
  `signalman-canary` rule in the rule directory. Prometheus
  (`localhost:9090`) scrapes it from the compose stack, and Grafana
  (`localhost:3000`) shows the dashboard.
- Run the alert sink alongside it: `go run ./cmd/signalman-sink`. It
  reads `alerts` as group `signalman-sink`, inserts into ClickHouse
  (`-clickhouse` DSN, defaulting to the compose stack), and serves
  `/metrics` on `:9465`, which Prometheus scrapes. The table is created when the ClickHouse volume is
  first initialized. On an existing volume, run new DDL such as
  `deploy/clickhouse/002_alerts_engine.sql` by hand; `docker compose down -v`
  also applies it but wipes every compose volume: stored alerts and events,
  the Redpanda topics, Prometheus history, and dashboard edits saved in
  Grafana (the provisioned dashboard comes back).
  It needs the `alerts.dead` and `events.raw` topics, which compose
  creates; it reads the `events.raw` partitions for its canary age. Reset the
  Redpanda and ClickHouse volumes together: `seq` restarts with a new
  `events.raw` and would collide with stored alerts.
- For retro-hunts, run the events lane as a second process:
  `go run ./cmd/signalman-sink -lane events`. It reads `events.norm` as
  group `signalman-events`, writes the `events` table
  (`deploy/clickhouse/003_events.sql`; on an existing volume apply it by
  hand like 002), dead-letters to `events.dead`, and serves `/metrics` on
  `:9467`. Then `go run ./cmd/signalman hunt --from <RFC 3339> --to <RFC 3339> rules/`.
- `make check-alerts` validates the Prometheus config and alert rules and runs
  their promtool unit tests. It needs `promtool` on PATH (from the Prometheus
  release archive) and says so when it is missing; with `CI=true` a missing
  promtool fails it. It is not part of `make check`; CI's `alerts` job
  installs promtool 3.5.0 from the release tarball, checks its sha256, and
  runs it.
- Shadow mode: add `-shadow` to `signalmand`, then run
  `go run ./cmd/differ` against the same brokers. The differ serves
  `/metrics` on `:9466`; `signalman_divergences_counted_total` is the number
  the gates watch. `-rollout <file>` (one integer, 0 to 100) sets the share
  of rules v2 serves; the file is reread every `-rollout-poll` (5s) and on
  `SIGHUP`.
- Gates: `go run ./cmd/cutover check -gate G1 -prom http://localhost:9090`
  prints each criterion with its evidence and exits 0 only if the gate
  passed; `-record` dates a passed gate in `docs/cutover.md`.
  `cutover gameday -prom ... -rollout-file <file> -out <json>` runs the G5
  rollback and roll-forward. After G6, `signalmand -serve v2` makes v2 the
  serving engine; with `-shadow`, run the differ with `-primary v2`.
  `docs/cutover.md` has the procedure.
- `TestEndToEndUnderGeneratedLoad` in `internal/pipe` is the test-mode audit
  run; `SIGNALMAN_SOAK_DURATION=1h go test -timeout 2h -run EndToEnd ./internal/pipe`
  lengthens it, memory permitting.
- Load runs skip unless `SIGNALMAN_LOAD=1`:
  `SIGNALMAN_LOAD=1 go test -run 'TestLoadBaseline|TestLoadExperiment' -v -timeout 2h ./internal/loadtest/`.
  `docs/load.md` lists the knobs.
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
