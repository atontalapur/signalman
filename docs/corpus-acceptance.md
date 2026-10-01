# SigmaHQ corpus acceptance

What fraction of the real SigmaHQ corpus this engine loads, and why it
rejects the rest. The point is that the supported subset of Sigma is
**documented rather than discovered**: every rejection has a code, and every
code has a paragraph here saying whether it is intended.

Regenerate with:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma corpora/sigmahq
go run ./cmd/corpusaccept -rules corpora/sigmahq/rules
```

`corpora/` is gitignored; the corpus is a third-party clone, not vendored
source.

## Run of 2026-09-21

- Corpus commit `2e8fd89f82d9104c1b30321a307254ddeea17de2`
- Taxonomy `33c005fb8a7c69be` (`config/taxonomy/`, three logsources)
- Rule set `7d1bba9e7029d5b5` for the `rules` tree

| Tree | Files | Accepted | `aggregation` | `condition` | `modifier` | `missing-id` | `no-taxonomy` |
|---|---|---|---|---|---|---|---|
| `rules` | 3144 | 1236 (39.3%) | 0 | 0 | 1 | 0 | 1907 |
| `rules-emerging-threats` | 473 | 176 (37.2%) | 0 | 0 | 2 | 0 | 295 |
| `rules-threat-hunting` | 140 | 66 (47.1%) | 0 | 0 | 0 | 0 | 74 |
| `rules-compliance` | 3 | 0 | 0 | 0 | 0 | 0 | 3 |
| `deprecated` | 172 | 82 (47.7%) | 1 | 0 | 3 | 0 | 86 |
| `unsupported` | 87 | 4 (4.6%) | 53 | 6 | 0 | 1 | 23 |

Accepted plus rejected equals the file count in every tree. That accounting
is asserted by `TestCorpusEveryRuleIsAcceptedOrRejectedWithAReason`, and it
is the property that matters: there is no third outcome where a rule is
quietly not evaluated.

## Reading the headline number

39.3% is not the interesting figure. Of the 1908 rejections in the `rules`
tree, 1907 are `no-taxonomy`: this deployment's `config/taxonomy/` maps three
logsources (Sysmon and Security process creation, Sysmon network
connection), and the corpus covers dozens, from Okta to Bitbucket to AWS
CloudTrail. Mapping a logsource is a deployment task, not an engine change.

The engine figure is the other column. Across the 3760 live rules in `rules`,
`rules-emerging-threats`, `rules-threat-hunting`, and `rules-compliance`,
**three rules** use something this engine cannot express. Every rule using an
aggregation pipe is in SigmaHQ's own `unsupported/` tree, which is where the
project itself parks them.

Load order is deliberate: everything that decides whether the engine can
express a rule runs before the taxonomy is resolved. A rule with an
aggregation pipe on an unmapped logsource reports `aggregation`, not
`no-taxonomy`. Either way it is rejected, but the code has to measure the
engine rather than the config, or this table would say nothing.

## Per-code commentary

### `no-taxonomy` — 2388 rules, intended

The rule declares a logsource `config/taxonomy/` does not bind. Nothing is
wrong with the rule or the engine; this deployment does not ingest that
stream, so there is no field mapping and no membership test to apply.

Closing it is config work: one file per logsource. It is deliberately not
closed wholesale here, because a taxonomy entry asserting a mapping nobody
verified would bind rules to the wrong fields and match silently wrong
things. That is worse than a loud rejection. See `docs/taxonomy.md`.

### `aggregation` — 54 rules, intended and permanent

The condition uses `|`, so the rule needs state across events: `count() > 5
by User`. Every verdict in this engine is a pure function of one event, one
rule set, and one taxonomy, which is what makes the v1-to-v2 equivalence
provable by comparing two digests. Supporting aggregation would mean carrying
windowed state through the cutover and proving that state equivalent too.

This stays a non-goal. The rejection names the rule id and the condition's
line number, so it is actionable as a "this rule will never run here"
statement rather than a mystery. 53 of the 54 are in `unsupported/`.

### `modifier` — 6 rules, two distinct causes

Three rules use `|expand`, pySigma's placeholder modifier
(`Attributes|contains|expand`, `Date|expand`). Placeholders resolve against
an external value list supplied at conversion time, which this engine has no
concept of: a verdict depends on the event, the rule set, and the taxonomy,
and a fourth input would have to be versioned into every verdict to keep that
true. Not planned.

Three rules use `fieldref` beside a comparison
(`userIdentity.arn|fieldref|contains`). pySigma allows it. This engine
rejects it rather than silently picking one of the two operations, which is
the divergence recorded in `docs/modifiers.md`. Supporting it properly means
a `FieldRef` variant per comparison, and it is worth doing if the count grows
past a handful; at three rules, the loud rejection is the better trade.

### `condition` — 6 rules, correct rejections

All six are in `unsupported/`. Four use characters the condition grammar does
not accept (`>` and `%` placeholder syntax, which is aggregation and
placeholder territory). Two reference a selection the detection block does
not define, one directly (`selection2`) and one through a quantifier glob
matching nothing (`selection*`). A rule that references a selection nobody
wrote cannot be evaluated, and guessing at the author's intent is how a
detection ends up matching something other than what it claims.

### `missing-id` — 1 rule, correct rejection

One rule in `unsupported/` has no `id`. Verdicts are keyed on the rule id, so
a rule without one cannot be reported on or compared across engines.

### `detection` and `duplicate-id` — 0 rules

No rule in the corpus has a detection block shape the compiler rejects, and
no two rules share an id.

## Differential fuzzer runs

Loading is not matching, so `test/fuzz` checks the frontend's semantics
against pySigma rather than against another reading of the specification.
How the oracle works, and every difference that is suppressed rather than
fixed, is in `test/fuzz/KNOWN_DIVERGENCES.md`.

Run with `make fuzz-differential FUZZTIME=30m`. It needs the oracle's
virtualenv; without it every case skips and the run proves nothing.

**Executions are not comparisons.** Go reports executions, and an input
neither engine evaluated says nothing about either. The target counts what
each case actually did and `scripts/fuzz_stats.py` sums the per-worker
counters, so the number below is comparisons.

Later runs, including the Plan A gate run after the suppression fixes,
are in `docs/results.md`.

### Run of 2026-09-21

| | 20 min, 2 workers | 30 min, 4 workers |
|---|---|---|
| Executions | 1,989,112 | 5,670,565 |
| Verdicts compared and equal | 755,860 | 2,193,509 |
| Rejected by both engines | 100,150 | 296,839 |
| Landed in a documented gap | 241,997 | 628,122 |
| Never reached both engines | 885,197 | 2,559,675 |
| Oracle timeouts | 0 | 0 |
| Divergences | 0 | 0 |

- pySigma 1.5.1, pySigma-backend-sqlite 1.2.4, Python 3.14.3
- Taxonomy `33c005fb8a7c69be`, the same three logsources as above
- The 30 minute run was killed by the host at 29m29s for memory, with
  nothing found; the 20 minute run ran to completion. Each worker holds an
  interpreter with pySigma loaded, so worker count is a memory budget.

Plan A's gate wants 1e6 executions clean. Both runs clear that by cases
reaching both engines, and the 30 minute run clears it by verdict
comparisons alone. Spec gate G0 wants 1e8, which accumulates in nightly CI
rather than in one sitting.

### What the fuzzer found

Every divergence it surfaced was on the oracle's side of the bridge. Two
were defects rather than dialect:

- `pySigma-backend-sqlite` converts a negated multi-variant selection to
  `NOT a LIKE x OR a LIKE y` with no parentheses. `NOT` binds tighter than
  `OR`, so the query asks `(NOT a) OR b`.
- pySigma indexes the `base64offset` trim table by the plaintext's character
  count. base64 works on bytes, so the two agree on ASCII and nowhere else.

The rest were SQLite's semantics (`=` is case sensitive, which the oracle
now corrects with `COLLATE NOCASE`), its limits (no NUL in a query, no
expression tree past depth 1000), and the gap between RE2 and Python's regex
engine. One open question came out of it and is carried in `TODOS.md`:
Signalman encodes a wildcard inside an encoded value as a literal byte where
pySigma rejects the rule.

## What this does and does not prove

It proves that the frontend accounts for every file, that its rejections are
attributable, and that the engine's expressive gaps against the real corpus
are three rules wide.

It proves that on the shapes the fuzzer generates, the accepted rules
evaluate the way an independent implementation evaluates them. It does not
prove that for the shapes it does not generate: `cidr`, the numeric
comparisons, `fieldref`, and keyword searches are outside the oracle's
reach, and their coverage is unit tests in `internal/sigma/match`.
