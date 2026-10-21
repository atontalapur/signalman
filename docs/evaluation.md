# Evaluation and the verdict digest

How an event becomes verdicts, and how two engines' verdict streams are
compared without diffing forty million rows.

## The v1 evaluator

`internal/engine/v1` walks every enabled rule for every event, in rule id
order. No index, no prefilter, no cache, no reordering. For each rule:

1. Test the logsource. If the event does not belong, the verdict is `false`
   and the condition is not consulted.
2. Otherwise walk the bound condition tree with `ast.Eval`.
3. Emit one verdict carrying the event's seq and partition, the rule id, the
   result, the engine name, and both versions.

`Evaluate` returns exactly `len(rules)` verdicts. `EvaluateInto` appends into
a caller-owned buffer, because the pipeline runs millions of events and one
allocation per event per rule is not acceptable.

### Why it is slow on purpose

v1 is the permanent oracle. When v2 and v1 disagree during the cutover, the
argument that v1 is right has to be short enough to hold in one reading, and
every optimization lengthens it. Speed is v2's job; v1 is never optimized by
rule. That is a standing invariant, not a temporary state.

### Read-only by contract

Evaluation writes to nothing: not the rule set, not the event, not the
evaluator. The shadow lane in Plan G hands one event to two engines at once,
so this is load-bearing rather than tidy, and a concurrent test pins it under
`-race`.

### A mismatch is a verdict

An event outside a rule's logsource produces an explicit `false`, never an
absent verdict. "Did not match" and "was never evaluated" have to stay
distinguishable: a detection that silently never ran is the failure this
pipeline exists to rule out, and it is invisible if absence is an allowed
outcome.

### Explain is a second walker, held to v1

`signalman explain` needs selection names and every leaf's value, and the
bound tree v1 walks has neither, so `internal/explain` walks the rule's
named condition (`Rule.Condition` with `Rule.Selections`) instead. It
differs from `ast.Eval` only in never short circuiting, which cannot change
a result because predicates are pure. Two tests keep it honest: substituting
the selections into the named condition gives exactly the bound tree
(`internal/sigma/named_test.go`), and the explained verdict equals v1's for
every shipped rule against every shipped fixture event
(`TestExplainAgreesWithV1`). v1 itself is unchanged.

## The digest

`internal/verdict` folds a verdict stream into 16 hex characters with
FNV-1a 64. The comparison between v1 and v2 is then a string equality.

The fold has two deliberately different halves:

- **Within one event, addition.** Each verdict hashes to a number from its
  rule id and its result, and those numbers are summed. Addition is
  commutative, so the digest does not depend on the order rules were
  evaluated in. A rule set shuffle must not look like a divergence.
- **Across events, a rolling hash.** When the seq advances, the event's
  accumulated value is folded into the rolling hash together with the seq
  itself. Order matters here, and so do the seq values: a stream missing
  event 5 must not hash like one that has it.

Addition rather than XOR, because two verdicts that hashed alike would cancel
under XOR and vanish.

### What is folded, and what is not

Folded: `Seq`, `RuleID`, `Matched`.

Not folded: `Engine`, `RuleSetV`, `TaxonomyV`, `Partition`. Those identify
the stream, not the verdict. Folding the engine name in would make v1 and v2
differ by construction and the whole comparison meaningless. They are
compared separately, as preconditions: two digests are only comparable if the
rule set and taxonomy versions on both sides are equal.

### One digest per partition

Partitions are independent ordered streams, so `verdict.Set` keeps one
`Digest` each. A partition's digest never depends on another partition's
traffic, so a consumer rebalance cannot look like a divergence.

### Monotonic seq is required

`Fold` rejects a seq that goes backwards. A digest over out-of-order events
is a number that means nothing, and the caller has to be told rather than
handed a confident wrong answer.

### Counts travel with the digest

`Verdicts()` and `Events()` are reported beside the hash. Two engines that
agree on the digest but disagree on the counts were not fed the same stream,
and that is worth catching separately from a hash mismatch.

## Measured baseline

Apple M1 Pro, `go test -bench . -benchtime 3s ./internal/engine/v1/`, corpus
commit `2e8fd89`, one Sysmon process creation event:

| Benchmark | Rules | ns/event | verdicts/s | B/event | allocs/event |
|---|---|---|---|---|---|
| `BenchmarkEvaluateFixtures` | 3 | 1,108 | 2,708,682 | 472 | 7 |
| `BenchmarkEvaluateCorpus` | 1236 | 3,553,219 | 347,854 | 2,297,217 | 18,593 |

Single-threaded, that is roughly 282 events per second against the full
accepted corpus. v1 has no index and no prefilter by design, so the cost is a
linear scan and the per-rule figure is what matters: about 2.9 microseconds
and 15 allocations per rule per event.

Fifteen allocations per rule is the number v2 has to attack, and it is
evidence rather than a guess: `Value.Text` allocates a string for int and
bool values, and the wildcard matcher lowercases and rune-decodes its input
on every call. Both sit on the per-field, per-rule path. The entry in
`TODOS.md` carries the options; the decision belongs to Plan G, with these
numbers as the baseline.

This is not a pipeline throughput figure. There is no ingest, no
normalization, and no sink yet, and events per second under real traffic is
Plan F's measurement.

## The gate property

`TestDigestSurvivesARuleSetShuffle` in `internal/engine/v1` is the Plan B
gate: the same events and the same rules, with the rules in ten different
orders, produce identical per-partition digests. Its companion,
`TestDigestMovesWhenOneRuleChanges`, asserts the other half, since a digest
that never moved would pass the first test trivially.

## Where this is enforced

- `internal/engine/v1/evaluator.go` — the walk, the logsource gate, verdicts
- `internal/verdict/digest.go` — the fold, per-partition sets
- `internal/engine/v1/digest_property_test.go` — the gate property
- `internal/fixture/` — rule fixtures, run through v1
- `internal/explain/` — the explain walker and its v1 equivalence test
