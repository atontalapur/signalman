# Signalman Implementation Roadmap

**Spec:** `docs/spec/signalman-v1.html` (source: https://claude.ai/code/artifact/5f8ebb2e-f99b-479e-b26c-d00e0d1aa3d4)

**Goal:** Build a Sigma detection engine and event pipeline in Go whose evaluation core can be replaced under live traffic and proven equivalent before the old core is retired.

This roadmap splits the spec into seven sub-plans. Each one produces working, testable software on its own. Only Plan A is written in full task detail so far (`2026-09-10-sigma-frontend.md`); the rest get written when their predecessor lands, so they can be informed by real code instead of guesses.

---

## Global constraints

These apply to every plan. Copied from the spec.

- Go 1.27. Install on the host before Plan A Task 1 (`brew install go`).
- Kafka wire protocol via Redpanda, run locally with Docker Compose. ClickHouse likewise.
- Rules are Sigma, SigmaHQ corpus. Aggregation and correlation rules (`|` in the condition) are rejected at load time with rule ID, line number, and the phrase "aggregation is not supported". Never silently skipped.
- A verdict is a pure function of `(Event, RuleSetV, TaxonomyV)`. No wall clock, no randomness, no dependence on Go map iteration order or rule load order.
- Every admitted event produces exactly one verdict per enabled rule, or exactly one drop ledger entry with a reason code. No third outcome.
- Logsource mismatch emits an explicit `false` verdict, not an absent verdict.
- Sigma string comparison is case insensitive by default. `|re` is case sensitive unless `|re|i`.
- Every stage boundary is a bounded channel. No unbounded buffers anywhere.
- Lag over loss. The pipeline never sheds load.
- No emojis in code, comments, docs, or commit messages.
- Conventional Commits. Feature branch per plan, PR to `main`. Never commit to `main` directly.
- `go vet ./...`, `gofmt -l .` clean, and `go test ./...` green before every commit.

## Non-goals, restated so they stay cut

Sigma correlations and aggregations. Enrichment of any kind. Case management. Multi-tenancy. Each of these will look reasonable around week 6. Adding any of them costs the cutover, which is the only part of the project that is hard to get elsewhere.

---

## Plan sequence

| Plan | Spec phases | Output | Depends on |
|---|---|---|---|
| A. Sigma frontend | 02, part of 01 | `internal/event`, `internal/sigma`, rule loader, taxonomy, pySigma differential fuzzer | nothing |
| B. Reference evaluator and CLI | 03, 01 | `internal/engine/v1`, verdict digest, `signalman test` and `explain` | A |
| C. Pipeline | 04 | Redpanda, ingest, normalizer, bounded stages, drop ledger, invariant 1 audit job | B |
| D. Sink and SQL backend | 04, 02 | ClickHouse alert schema, sink, AST to SQL compiler, retro-hunt | C |
| E. Observability | 06 | Metrics, dashboards, canary generator, silence detector | C |
| F. Load behavior | 05 | Load harness, seven experiments, `docs/load.md` | C, D, E |
| G. Compiled engine and cutover | 07, 08, 09 | `internal/engine/v2`, shadow lane, differ, rollout flags, `docs/cutover.md` | all above |
| H. Author surface | 10 | `signalman lint / noise / bench`, fixtures, rule PR CI gates, `docs/authoring.md` | B, D |

Plan H can be interleaved once B and D land. Everything else is strictly ordered.

### Why this order

The data contract in spec phase 01 is not its own plan. Its types (`Event`, `Value`, `Verdict`) are needed by the very first frontend test, so they are Task 1 of Plan A. The digest lands in Plan B, where there are verdicts to fold.

Plan G is the point of the project. Plans C through F exist so that G has real traffic, real metrics, and a documented baseline to compare against. If the schedule slips, cut scope inside C through F rather than starting G late.

---

## Gates between plans

A plan is done when its gate passes, not when its tasks are checked off.

- **A** Every rule in the SigmaHQ corpus either parses or is rejected with a specific machine-readable reason, and the counts are recorded in `docs/corpus-acceptance.md`. The pySigma differential fuzzer runs 1e6 executions clean.
- **B** Twenty hand-written rules pass their fixtures. Determinism property test green: same corpus, rule set shuffled ten times, identical digest.
- **C** Events flow end to end. The invariant 1 audit job reconciles ingested count against verdicts plus drops, and is green for an hour under load.
- **D** A retro-hunt SQL query returns the same rows as an in-process replay of the same rules over the same window.
- **E** Killing a consumer produces a page within two minutes via `signalman_canary_age_seconds`.
- **F** `docs/load.md` answers all three questions (where did work queue, what fell behind first, what happened to correctness) for all seven experiments.
- **G** The gate ladder G0 to G6 in spec phase 09, ending with v1 demoted to test oracle and three documents written.

---

## Repository layout

Created incrementally, one directory per plan.

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
corpora/                EVTX-ATTACK-SAMPLES, Security Datasets
deploy/                 docker compose for Redpanda and ClickHouse
docs/load.md docs/cutover.md docs/authoring.md
```

## The three documents

Written as the work happens, not reconstructed at the end.

1. `docs/load.md` from Plan F.
2. `docs/cutover.md` from Plan G, including the divergence log kept from the first day of shadow mode.
3. `docs/authoring.md` from Plan H.
