# Rule loading and structured rejection

A rule either loads or is rejected with a code, a reason, the rule id, and a
line number. There is no third outcome. A rule that is silently skipped is a
missing detection with no signal attached to it, and nobody finds out until
the incident review.

## The pipeline

`sigma.LoadRule(path, tax)` reads the file and calls
`sigma.LoadRuleBytes(path, src, tax)`, which is the real entry point. The
fuzzer and the corpus tools generate rules that never touch the disk.

1. **Decode YAML.** A malformed file is `yaml`.
2. **Require an id.** No id is `missing-id`. Verdicts are keyed on the rule
   id, so a rule without one cannot be reported on.
3. **Read the condition.** Sigma allows a single string or a list of strings;
   a list is an OR over the arms. Any other shape is `condition`, with the
   type named. Missing or empty is `condition`.
4. **Resolve the logsource.** No taxonomy entry is `no-taxonomy`. See
   `docs/taxonomy.md` for why resolution is exact.
5. **Compile the detection block.** A bad shape is `detection`; an
   unsupported or contradictory modifier chain is `modifier`. The two are
   told apart with `errors.Is(err, match.ErrUnsupportedModifier)`, never by
   error text: the text is for humans and will change, the code is counted.
6. **Parse each condition arm.** An aggregation pipe is `aggregation`, with
   the phrase "aggregation is not supported" and the condition's line number.
   Anything else the parser rejects is `condition`.
7. **Expand quantifiers and bind names.** `1 of selection_*` becomes an OR
   over the matching selections. A reference to a selection that does not
   exist is `condition`.
8. **Substitute the selections** into the condition tree, then **rename
   fields** through the taxonomy mapping. A field with no mapping keeps its
   name, which is what a source that already speaks Sigma field names needs.

The result carries the bound tree, the logsource matcher, and the sorted list
of fields the rule reads.

## Error codes

| Code | Meaning | Intended? |
|---|---|---|
| `yaml` | The file did not decode | Author error |
| `missing-id` | No `id` field | Author error |
| `duplicate-id` | Another file already claimed the id | Author error; names both paths |
| `no-taxonomy` | The logsource is not mapped | Expected; a deployment maps what it ingests |
| `condition` | Condition missing, malformed, or naming an undefined selection | Author error |
| `detection` | The detection block has a shape the compiler does not accept | Author error |
| `modifier` | Unsupported modifier or an invalid chain | Mostly intended; see `docs/modifiers.md` |
| `aggregation` | The condition uses `|` | Intended and permanent; a non-goal |

The set is closed. A new code needs a paragraph in
`docs/corpus-acceptance.md` saying whether the rejection is intended, so
adding one is a documentation change as well as a code change.

## Why aggregation is rejected rather than ignored

A correlation or aggregation rule needs state across events. Everything else
in this engine is a pure function of one event, one rule set, and one
taxonomy, which is what makes the v1-to-v2 equivalence provable by comparing
two digests. Supporting aggregation would mean carrying windowed state
through the cutover and proving that state equivalent too. It stays a
non-goal, so the rule is rejected at load with its id and the line, and the
count shows up in the acceptance report.

## RuleSetV

`LoadRuleSet(dir, tax)` walks the directory, loads each file, sorts the
loaded rules by id, and hashes:

- each rule's id, and
- `ast.Canonical` of its bound tree, and
- the taxonomy version.

`Canonical` rather than `String`: every string is written quoted, so a
detection value containing a separator cannot collide with the structure
around it and produce the same hash as a different rule set.

Sorting by id before hashing is what makes the version independent of
filesystem order. Hashing the taxonomy version in is what makes a taxonomy
edit visible as a rule set change, because the bound tree and the logsource
test both depend on it.

A duplicate id is rejected rather than merged: verdicts are keyed on the rule
id, so two rules sharing one would produce verdicts nobody could attribute.
The first file to claim an id keeps it, which makes the outcome independent
of walk order, and the second gets a `duplicate-id` rejection naming both
paths.

## Where this is enforced

- `internal/sigma/rule.go` — decode, validate, bind, rename
- `internal/sigma/ruleset.go` — directory walk, duplicate ids, RuleSetV
- `internal/sigma/testdata/rules*/` — one fixture per outcome
