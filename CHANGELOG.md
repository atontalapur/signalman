# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versions follow SemVer. `/ship` appends entries.

## [0.18.2] - 2026-11-08

### Fixed

- The fuzzer's oracle declines a case-insensitive comparison between two
  non-ASCII letters that differ only by case (`unicode-case`). SQLite folds
  ASCII only, so it reported `Ώ` against `ώ` as a Signalman bug. The G0
  fuzz matrix found it.
- `regex-casefold` also covers a regex range that holds the Turkish i
  family without naming it, as `[x-٬]` does, and an inline `(?i)` under a
  plain `re`.

## [0.18.1] - 2026-11-08

### Fixed

- Case folding no longer maps a non-ASCII character onto ASCII. Go
  lowercases `İ` (U+0130) to `i` and the Kelvin sign to `k`, so a rule with
  `contains: İ` matched every `i` on every event. `fieldref` also paired the
  long s with `s`. Each now matches only itself, in v1, v2 and the
  ClickHouse encoder alike, and Unicode folding otherwise still applies
  (`ДОМ` matches `дом`). The G0 differential fuzz matrix found it. No
  SigmaHQ rule or rule in `rules/` contains any of the three characters.
- The fuzzer recognizes the documented `windash` and chain fan-out budget
  by a typed error, `match.ErrFanOut`, instead of failing on it.
- The fuzzer declines a case-insensitive regex on the Turkish i family
  (`regex-casefold`): RE2 and Python's `re.IGNORECASE` disagree there, and
  `|re` is RE2 by design.

## [0.18.0] - 2026-11-08

### Added

- `signalman hunt --from --to rules/` runs rules as ClickHouse queries over
  stored events and prints each rule's matching `(partition, seq)` rows.
- `signalman-sink -lane events` stores `events.norm` in a new `events`
  table (`deploy/clickhouse/003_events.sql`) for the hunt to read, with the
  alert lane's delivery: commit after insert, retry on outage, and
  dead letters to the new `events.dead` topic. Prometheus scrapes it on
  `:9467`.
- Plans C, D and E passed their gates on the compose stack. The one-hour
  soak ran 3.72 million events through the real binaries with zero audit
  violations. The hunt over stored events equals the pipeline's stored
  alerts for all 21 rules. A killed `signalmand` paged in 51 s and a
  stalled one in 95 s. Numbers are in `docs/results.md`.

### Fixed

- A `fieldref` target is now renamed through the taxonomy like the field
  it sits under. Under `Image: NewProcessName`, `ParentImage|fieldref: Image`
  used to compare against a field no event has and never matched, in all
  three engines.
- A wildcard inside a `base64` or `base64offset` value is a load error
  (`modifier`). The star used to be encoded as a literal byte, so the rule
  matched something other than what it said. pySigma rejects the same
  values. No SigmaHQ rule is affected. An escaped `\*`, `\?` or `\\` under
  those modifiers is now resolved before encoding, so `a\*b` matches the
  base64 of `a*b` rather than of the backslash and star.
- `signalman hunt --json` writes a failed rule as a JSON record with an
  `error` field, and load errors print before ClickHouse is dialed.
- `go.mod` pins the go1.27.3 toolchain, so local builds no longer fail
  govulncheck on ten standard library vulnerabilities fixed after 1.27.1.
- `TestPipelineOverRedpanda` reread all of `events.raw` with a fresh group
  and timed out on a stack with history. It now starts at the end.
- `TestRetroHuntEqualsReplay` now forces the merge it claimed to check, and
  `002_alerts_engine.sql` is tested against a table that lacks the column.

## [0.17.1] - 2026-11-07

### Fixed

- `make check` passes again: govulncheck flagged GO-2026-6888 in
  `andybalholm/brotli` 1.2.6, reachable through clickhouse-go and the Kafka
  client. brotli is now 1.2.7.
- The README no longer tells you to run `docker compose down -v` after a
  schema change, which wiped stored alerts. It says to apply new DDL such as
  `002_alerts_engine.sql` by hand, and `001_alerts.sql` says the same.
- The docs now say the ClickHouse integration tests run and pass in CI's
  `integration` job, and the rules workflow passed on its first real rule
  PR. They used to say neither had run.
- Plan D stays in progress. The retro-hunt SQL equals a v1 replay on a real
  ClickHouse over synthetic rules, but no binary runs a retro-hunt yet.
- Stale counts and paths: 21 rules in `docs/load.md`, no `test/replay/` in
  the README layout, and `CLAUDE.md` points at the README's repository map
  and lists `make check-alerts`.

### Changed

- CI actions bumped by Dependabot: docker/login-action 4.7.0,
  actions/setup-python 7.1.0, goreleaser-action 7.3.0,
  actions/upload-artifact 7.0.2.

## [0.17.0] - 2026-10-21

### Added

- `internal/loadtest` runs the pipeline in process over the in-memory
  broker behind a tap that checks every batch's outputs: one verdict per
  rule of one RuleSetV, alerts equal to matched verdicts, and exactly one
  verdict record or drop per `events.raw` offset. It paces a corpus at a
  multiple of a measured baseline and injects consumer kills, poison
  records, rule reloads, an output outage and an offline partition.
- The seven spec phase 05 experiments run under `SIGNALMAN_LOAD=1`, each
  writing a JSON report. `docs/load.md` records the in-process run on the
  1,236 SigmaHQ rules and what still needs Redpanda and ClickHouse.
- `cmd/loadgen` replays an ndjson corpus, or events generated from a rule
  directory, into `events.raw` on Kafka at a multiple of a baseline.
- `pipe.Normalizer.SetFault` for failure injection in tests.

### Changed

- `Correctness.OK` fails on any redelivered verdict record whose bytes
  differ from its first write. The reload experiment uses
  `OKAcrossReloads`.
- Sustained 5x asserts its digest equals a clean replay; partition offline
  asserts no duplicates.
- Reports carry `tap_blocked_sends`, counted, in place of relying on the
  sampled tap queue depth.

### Fixed

- A redelivery was compared on rule set and matched rule indices only, and
  a changed one was reported but never failed a run.
- `Replay` resent a whole failed batch with no record of it; it now counts
  `Resent` records (possible duplicates on Kafka) and stops on a permanent
  produce error instead of retrying it forever.

## [0.16.0] - 2026-10-21

### Added

- `cmd/cutover check` evaluates one gate of the G0 to G6 ladder and prints
  every criterion with its status and evidence: a corpus replay digested
  per partition through v1 and v2, the differential fuzzer's summed
  counters and the property tests for G0, Prometheus for G1 to G6, and a
  game day result for the rollback timings. A criterion nothing here can
  check stays unchecked until attested with `-attest`. `-record` dates a
  passed gate in `docs/cutover.md` and appends its evidence.
- `cmd/cutover gameday` rolls the `-rollout` file back and forward with a
  rename and times each change from `signalman_rollout_percent` and
  `signalman_alerts_total`; `cutover measure` times a change made by hand.
- `signalmand -serve v2` makes v2 the serving engine for every rule, with
  v1 as the oracle under `-shadow`; `cmd/differ -primary v2` joins on v2's
  records. The default stays `-serve v1`.
- The ClickHouse `alerts` table and the sink carry the serving `engine`
  column, with `002_alerts_engine.sql` for an existing table.
- `signalman_audit_windows_total` counts the windows the invariant 1 audit
  closed.

### Changed

- The corpus reader moves to `internal/corpus` and the rollout file parser
  to `internal/pipe`. Prometheus also scrapes the differ.
- `chsink.Decode` refuses an alert whose engine is not v1 or v2, and the
  sink dead-letters it.

### Fixed

- Gates passed on a window only partly scraped. Every gate with a window
  now needs signalmand and the differ scraped for 95% of it (and of the
  alert volume baseline), and each engine's verdict rate above zero at
  every 5m step.
- `-at` could be in the future and `-record` could write a future date.
  Both are refused.
- G6 passed audit-violations when the audit never ran. It now needs
  `signalman_audit_windows_total` rising at every 5m step.
- A rollback drill counted for any step at any time. G2 to G4 now need one
  from the gate's step, written within `-drill-slack` (24h) of the hold.
  `-rollback-only` used to leave production at the rollback target; it now
  writes `-from` back and checks the gauge, or exits non-zero.
- `-record` dated a gate with earlier gates undated. It now refuses.
- G6 audit-violations, G4 v1-serves-none and shadow-failures missed a
  counter's first count: those series were made by it, and `increase()`
  ignores a series' first sample. signalmand now exports them at zero (per
  partition from the auditor's start, per rule and engine and per shadow
  when engines are stored), and the gates treat no series as unchecked.
- differ-running passed on any differ activity in the window, so a differ
  that stalled after an hour, or fell far behind, passed G1 to G4 and G6
  with divergences flat. It now needs differ resolutions at every 5m step,
  and the new differ-keeps-up needs the differ to have resolved the events
  signalmand evaluated, within `-verdict-tolerance`.

## [0.15.0] - 2026-10-21

### Added

- `signalmand -shadow` evaluates every event with v2 beside v1 in the same
  batch and writes `verdicts.v2` with no alerts. The slot stores the pair as
  one value, so a reload never splits them across RuleSetV. A v2 panic or
  malformed verdict list leaves v1 untouched, writes no v2 record, and
  counts in `signalman_shadow_failures_total`.
- `cmd/differ` merge-joins `verdicts.v1` and `verdicts.v2` per partition on
  (partition, seq, rule_id), classifies disagreements into the spec's five
  classes, and writes each to the `divergences` topic and the JSON log.
  Memory is bounded by one head per side and a bounded channel.
- Per-rule rollout: v2 serves a rule's alerts when fnv(rule_id) mod 100 is
  below the rollout percentage, read once per batch, so each match gets
  exactly one alert from its serving engine. `signalmand -rollout` rereads
  the percentage from a file every `-rollout-poll` (5s) and on SIGHUP.
  Alerts carry the serving engine; `signalman_alerts_total` and
  `signalman_rollout_percent` are exported.
- `docs/cutover.md`: the four arguments, the gate ladder, retirement
  criteria, and an empty divergence log.
- `broker.Checkpoint`: a committed offset with its commit metadata.

### Changed

- The differ commits each side's repeat-dropping state as offset commit
  metadata (`CommitCheckpoints` replaces `CommitOffsets` on the broker).
- `-create-topics` and the compose stack create `verdicts.v2` and
  `divergences`, with the same 1 MiB `max.message.bytes` as every topic.

### Fixed

- A 20 MB `signalmand` binary was committed at the repository root. It is
  removed, and the cmd binary names are ignored there.
- signalmand now refuses at startup a `verdicts.v2` with fewer partitions
  than `events.raw` when the shadow is on, and a `verdicts.v2` record over
  the output limit stops the pipeline like a `verdicts.v1` one.
- A differ restart inside a redelivered batch could report false missing
  verdicts, because its repeat state started empty.
- A shadowed redelivery of events first written without `-shadow` was
  passed over as a repeat, so its v2 records were reported missing.
- A v2 record for an event v1 wrote unshadowed is no longer counted as a
  missing v1 verdict.
- A shadowed v1 record whose v2 record never arrives no longer blocks its
  partition forever: once a later unshadowed v1 record shows signalmand
  moved on, it is reported missing after v2 is read to its end offset.
- The canary age and `signalman_rule_matches_total` follow the alerts
  actually served, so a v2 that wrongly stops matching the canary while it
  serves the rule now pages.

## [0.14.0] - 2026-10-21

### Added

- The rest of the spec's core metrics: `signalman_rule_eval_seconds`
  (sampled per rule with `-rule-eval-every`, exemplars off),
  `signalman_event_staleness_seconds`, and `signalman_canary_age_seconds`.
  The two age gauges are computed at scrape time and kept separate from
  consumer lag. A test parses the spec's metrics table and holds the
  registered set, types, and labels to it.
- A canary generator in `signalmand` that writes one synthetic event to
  every `events.raw` partition every `-canary-interval` (30s), and
  `rules/signalman_canary.yml`, which turns it into an alert that resets
  the partition's canary age. Canary events are left out of staleness.
- `deploy/prometheus` (scrape config, alert rules, promtool tests) and
  `deploy/grafana` (provisioned dashboard), in the compose stack.
  `SignalmanCanaryStalled` and `SignalmanCanaryAbsent` page;
  `SignalmanCanaryStalled` fires at over 50s for 30s, so a dead consumer
  pages within two minutes. `SignalmanRuleWentSilent` files a ticket.
- `signalman_event_time_future_total`, counting durable events whose event
  time is ahead of the clock.
- An `alerts` CI job that installs promtool 3.5.0 from the official release
  tarball, checks it against a pinned sha256, and runs `make check-alerts`.

### Changed

- The engine slot exports every loaded rule's `signalman_rule_matches_total`
  series at zero and deletes the series of a rule a reload removes, so a
  rule silenced by a taxonomy change still has a series for the silence
  alert to compare.
- `make check-alerts` fails when promtool is missing and `CI=true`.

### Fixed

- An event time in the future pinned a partition's staleness at zero until
  the wall clock caught up with it. Staleness now advances to the earlier
  of the event time and now.
- The promtool alert tests never ran in CI.
- The canary never reached ClickHouse: its age reset once the alert was on
  the alerts topic, so a dead signalman-sink or ClickHouse never paged, and
  Prometheus did not scrape signalman-sink at all. signalman-sink now
  exports `signalman_sink_canary_age_seconds`, reset after the insert
  holding a partition's canary alert succeeds, paged on by
  `SignalmanSinkCanaryStalled` and `SignalmanSinkCanaryAbsent`, and
  Prometheus scrapes it on `:9465`. signalman-sink now needs `events.raw`.

## [0.13.1] - 2026-10-21

### Added

- `rules/signalman_canary.yml`, the signalman-canary rule, with fixtures.
  It matches only the synthetic event the canary generator (0.14.0) writes,
  and ships in its own rules-only PR so the rule gates judge it with code
  already on the base branch.

### Changed

- The CLI and explain tests count the rules in `rules/` instead of
  hardcoding twenty, so adding a rule needs no code change.

## [0.13.0] - 2026-10-21

### Added

- `cmd/signalman-sink` and `internal/pipe/chsink`: consumes the `alerts`
  topic and batch-inserts into the ClickHouse `alerts` table over
  clickhouse-go, committing offsets only after an insert succeeds. While
  ClickHouse is down it retries one batch and stops polling, so an outage
  is consumer lag on `alerts`, not loss.
- `deploy/clickhouse/001_alerts.sql`, the spec's alerts table
  (ReplacingMergeTree on `(partition, seq, rule_id)`, 90 day TTL), created
  by the compose ClickHouse on first start.
- The `alerts.dead` topic and `signalman_sink_dead_letters_total`. A record
  the table cannot hold is written there with its position and reason, and
  its offset is committed after that write. Compose and
  `signalmand -create-topics` create the topic; the sink refuses to start
  without it.
- An integration test that reinserts a batch into a real ClickHouse and
  checks it collapses. It has not been run yet.

### Changed

- The alerts table partitions and expires on `ingest_time`, not
  `event_time` as the spec has it, matching the events table. The deviation
  is in `docs/pipeline.md`.
- The alerts table sets `fsync_after_insert` and `fsync_part_directory`, so an acknowledged insert is on
  disk before its offset is committed.
- `docs/pipeline.md` says Redpanda and ClickHouse volumes must be reset
  together, since `seq` is the `events.raw` offset and is the dedup key.

### Fixed

- A ClickHouse error an identical insert hits again (type, parse, missing
  table, too many partitions in one block) was retried forever. It now
  stops the sink with the batch's offsets and commits nothing.
- One undecodable alerts record stopped the sink for every partition and
  crash-looped it on restart. It is now dead-lettered.
- An alert for an event older than 90 days was TTL-deleted after its offset
  was committed. A time outside the DateTime64(3) range is refused.
- The ClickHouse sink integration test fails instead of skipping under
  `CI=true` without a DSN.
- The merge property test is named and documented as a check of a model,
  not of ClickHouse.
- An `event_time` from 2262-04-12 to 2299 passed the range check, was
  stored as a time in the 1600s or 1700s by the driver's `UnixNano`
  encoding, and had its offset committed. `event_time` is now bounded at
  2262-04-11, and `ingest_time` to 1970 through 2105-11-09 so the TTL
  cannot overflow DateTime. Both are dead-lettered outside that.

## [0.12.0] - 2026-10-21

### Added

- `signalman gates`, the rule pull request gates: parse, fixtures, noise
  budget, latency budget, and prefilter for each changed rule, written as
  one markdown report. A failed gate exits 1; a rule in the v2 `Always` set
  is a warning. `--changed` reads a git diff file list, where a changed
  fixture stands for its rule, and `--set` catches an id another rule in the
  set already uses.
- `.github/workflows/rules.yml` runs the gates on PRs that touch `rules/`.
  The PR's code runs with a read-only token; a separate job with no
  checkout posts the report as one PR comment and edits it on later pushes.
  Fork PRs get the job summary only.
- `docs/authoring.md`: the supported Sigma subset, rejection codes,
  fixtures, explain, budgets, the prefilter, and the gates.
- Load codes `invalid-id` and `level`.

### Changed

- The loader rejects a rule whose id is not a canonical UUID
  (`invalid-id`) or whose `level` is missing or not one of the five Sigma
  levels (`level`). The alerts table stores both as typed columns. SigmaHQ
  corpus acceptance is unchanged. A non-UUID id is no longer a pySigma
  divergence; a missing level is a new one.
- `signalman gates` prints the full report on stdout; `--comment FILE`
  writes a copy cut to fit one PR comment.
- The rules workflow fails without running the gates when a rules PR also
  changes `cmd/`, `internal/`, `config/taxonomy/`, `go.mod`, `go.sum`, the
  noise corpus, or the workflow, since the gates would run the PR's own code.

### Fixed

- Past about 450 rules the gates report overran GitHub's comment limit,
  because only the details were cut and the table was not, so the comment
  POST failed. The comment copy now drops table rows too, keeping failures
  and warnings first, says how many it left out, and the job summary gets
  the full report it points to.
- Two rules whose ids differed only in hex case both loaded, matched the
  same events, and wrote alerts to one `(partition, seq, rule_id)` row, so
  one alert disappeared on merge. The loader now lowers the id, so the rule
  set and `gates --set` reject the second as `duplicate-id`.

## [0.11.0] - 2026-10-21

### Added

- `internal/backend/ch`, the ClickHouse SQL backend. `CompileRule` turns a
  loaded rule into a WHERE clause over an events table, and `RetroHunt` runs
  it over a time window through `database/sql`. Every node type and
  modifier the frontend accepts compiles, as does every rule the corpus
  loads.
- `ch.Encode` stores each field as v1 would compare it (folded, regex-safe,
  fold key, ints, addresses), so the SQL only compares and never relies on
  ClickHouse's own case folding, regex, or parsing. Each dialect leak is in
  `docs/backend-ch.md`.
- A retro-hunt-equals-replay integration test against ClickHouse.

### Changed

- The CI integration job and `make integration` set
  `SIGNALMAN_CLICKHOUSE_DSN` to the compose server. Under `CI=true` the
  retro-hunt test fails instead of skipping when the DSN is unset.

### Fixed

- The events table partitioned and expired rows on the source's
  `event_time`, so old or skewed events were deleted on arrival and a wide
  batch could exceed the 100 partitions per insert limit. It now uses
  `ingest_time`.
- The query size check covered only the WHERE clause. `HuntQuery` now
  checks the full statement.

## [0.10.0] - 2026-10-21

### Added

- `cmd/signalmand`, the pipeline daemon. It consumes `events.raw`, assigns
  Seq from the record offset, normalizes through the taxonomy, evaluates
  with v1, and writes `events.norm`, `verdicts.v1`, `alerts`, and `drops`.
  It serves `/metrics` and reloads rules on `SIGHUP`.
- `internal/broker`: the broker interface, an in-memory implementation for
  unit tests, and a franz-go implementation for Redpanda.
  `deploy/docker-compose.yml` runs pinned Redpanda and ClickHouse and
  creates the topics.
- The normalizer and drop ledger: every decode failure becomes a drop with
  a closed reason code and the raw bytes, a normalizer panic included.
- Bounded stages and a sink that commits a batch's offsets only after its
  outputs are durable. Delivery is at-least-once; a stuck sink is lag,
  never loss.
- Rule set reloads through a slot read once per batch, so no batch
  straddles two RuleSetV values.
- The invariant 1 audit, which checks every committed `events.raw` offset
  against `verdicts.v1` and `drops`, and `docs/pipeline.md`.

### Changed

- Every pipeline topic has `max.message.bytes` of 1 MiB, the same as the
  producer's batch limit.
- Drop entries carry `raw_bytes`, and `truncated` for a record that was cut.

### Fixed

- Outputs could exceed the broker's size limit and were retried forever,
  wedging every partition. Records over 128 KiB are dropped as
  `record-too-large`, and an event whose outputs would not fit is dropped as
  `output-too-large`.
- A produce error that cannot succeed on retry (message too large, unknown
  topic or partition) now stops the pipeline with the batch uncommitted.
  Startup refuses a missing output topic or a `verdicts.v1` with fewer
  partitions than `events.raw`.
- The audit counted offsets removed by retention as missing verdicts when
  a partition had no committed offset. It now starts at the log start.
- A batch in flight during a rebalance could commit for a partition this
  member had lost and move the group offset backwards. Those commits are
  dropped.
- A `source` header that was not valid UTF-8 panicked ingest through its
  Prometheus label, and redelivery panicked it again. The header was also an
  unbounded label. Labels now map to `auditd`, `cloudtrail`, `sysmon`,
  `unknown`, or `other`, and a source outside that set is an
  `unknown-source` drop.
- A matched event whose alert record would be over the output limit was
  dropped as `output-too-large` with its verdicts, so escape-heavy fields
  could suppress a detection. The alert now leaves `fields` empty and sets
  the new optional `fields_omitted`; `output-too-large` covers only
  `events.norm`.

## [0.9.0] - 2026-10-21

### Added

- `internal/engine/v2`, the compiled evaluator. It interns every leaf
  predicate, logsource tests included, into one table, and each rule
  becomes a tree over that table's bitset.
- A literal prefilter: each rule's required literals feed an Aho-Corasick
  automaton (`internal/engine/v2/aho`), and a rule none of whose literals
  occur is settled false without a walk. Nothing under a `not` is used.
- Presence gating: a rule whose required fields are absent is settled false
  without a walk and still emits its verdict.
- `EvaluateInto` makes 0 allocations per event on the fixtures and the
  SigmaHQ corpus. On the corpus stream it runs at 17,633 ns/event against
  v1's 938,733 (`docs/results.md`).
- Equivalence with v1, verdict by verdict and digest by digest, over the
  fixtures and the corpus, plus rule independence and prefilter soundness
  tests and `FuzzPrefilterSound`.

### Changed

- `ast.Pred` carries the modifier chain and values its matcher was built
  from, and `match.Build` is now `Plan` followed by `Spec.Matcher`. RuleSetV
  is unchanged.

### Fixed

- The v2 equivalence tests now cover the shipped `rules/` directory in CI,
  and fail if any shipped rule stops loading. Before, those rules were only
  compared when the SigmaHQ corpus was present.

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

## [0.7.2] - 2026-10-21

### Fixed

- `make check` passes again on Go 1.27.3, which CI's `setup-go` now
  resolves. staticcheck v0.8.1 could not read Go 1.27.3's export data and
  failed every run, on `main` and on Dependabot PRs; it is now v0.8.2.

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
