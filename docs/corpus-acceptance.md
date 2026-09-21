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

## What this does and does not prove

It proves that the frontend accounts for every file, that its rejections are
attributable, and that the engine's expressive gaps against the real corpus
are three rules wide.

It does not prove the accepted rules **evaluate correctly**. Loading is not
matching. That is the pySigma differential fuzzer's job, and until it has run
clean, "1236 rules load" means only that they load.
