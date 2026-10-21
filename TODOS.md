# TODOS

Engineering debt too small for a Jira story. Stories live in `docs/backlog.yml`.

## Infrastructure

### Keep cmd/corpusaccept out of releases
**What:** GoReleaser builds every `main` under `./...`, so the corpus acceptance tool ships in every `v*` tarball and the Docker image.
**Why:** It is a dev tool that needs a vendored corpus; shipping it is noise, not harm.
**Context:** `.goreleaser.yaml` build id `cmds` uses `main: ./...` on purpose so new `cmd/` dirs appear automatically. Options: an `ignore` list in the build, or move the tool under `tools/`. Revisit when the first release is cut.
**Effort:** S
**Priority:** P4
**Depends on:** Plan A Task 13

### Revisit the event.Value layout
**What:** `event.Value` is 64 bytes with every payload slot present. Options from the SIG-13 review: fold `I` and `B` into one slot, move `L` behind a pointer.
**Why:** The allocation half of the original entry is settled. v2 (SIG-40) never calls `Value.Text` on its hot path: each field is folded once per event with `match.AppendFold` and `strconv.AppendInt` into a reused arena, and the common wildcard shapes compare bytes (`match.Folded`). v2 is at 0 allocs/event on the corpus (`docs/results.md`). What is left is size, which costs copies and cache, not allocations.
**Context:** v2 copies one `Value` per program field per event into its scratch. Measure that before changing a type every package uses.
**Effort:** M
**Priority:** P4
**Depends on:** Plan F load numbers

### Rename fieldref targets through the taxonomy
**What:** `rename` in `internal/sigma/rule.go` maps `Pred.Field` through the taxonomy but leaves the `fieldref` target, which lives in the rule value, under its Sigma name.
**Why:** Found while writing the ClickHouse backend (SIG-32). Under `Image: NewProcessName`, `ParentImage|fieldref: Image` compares against a field the event never has, so the rule silently never matches. v1 and the SQL backend agree on this, so no differ catches it.
**Context:** Fix in the loader by rewriting the value through the same mapping, then let `ch` and v1 both pick it up. Changes RuleSetV for any rule using fieldref under a renaming entry. See `docs/backend-ch.md`, "Found in the frontend".
**Effort:** S
**Priority:** P2
**Depends on:** nothing

### Case folding applied to base64 text widens matching
**What:** `Equals` lowercases both sides, and encoding transforms run before that fold, so a `base64offset|contains` matcher compares lowercased base64. Two different plaintext bytes can encode to base64 characters that differ only in case (`A` and `a`), so a value can match a blob it did not encode.
**Why:** Sigma string matching is case insensitive by default and pySigma's backends fold case the same way, so following the spec here is right and the fuzzer will confirm it. The cost is a wider match on encoded values, which is a false positive, never a missed detection.
**Context:** From SIG-16. Options if it shows up in practice: a case-sensitive `Matcher` variant selected when the chain carries an encoding transform, or a note in `docs/authoring.md` (Plan H) telling authors that encoded values are effectively case sensitive anyway. Decide with fuzzer evidence in Task 14, not before. `docs/modifiers.md` records the current behavior and `internal/sigma/match/build_test.go` pins it in `TestBuildEncodedValuesAreCaseSensitiveInPractice`.
**Effort:** S
**Priority:** P3
**Depends on:** Plan A Task 14

### Decide whether a wildcard inside an encoded value is a load error
**What:** `CommandLine|base64|contains: '*foo*'` encodes the asterisks as literal bytes here and matches the base64 of `*foo*`. pySigma rejects the rule outright ("Base64 encoding of strings with wildcards is not allowed").
**Why:** Found by the SIG-21 differential fuzzer. An author who writes that almost certainly means a wildcard, and gets a rule that silently matches something else. Signalman already prefers a loud load error for a chain that cannot mean what it says: a chain whose variants are all empty is rejected for exactly this reason.
**Context:** Two options. Reject at load with a new `modifier` rejection reason, which matches pySigma and costs a line in `docs/modifiers.md`, `docs/corpus-acceptance.md`, and a recount of the corpus (no corpus rule does this today). Or keep the literal reading and document it in `docs/modifiers.md` as a divergence. Either way the suppression in `test/fuzz/oracle.go` and its section in `test/fuzz/KNOWN_DIVERGENCES.md` come out. Not decided inside SIG-21: it changes frontend semantics, which is its own story.
**Effort:** S
**Priority:** P2
**Depends on:** None

## Completed

### Decide event value limits at decode time
**What:** The decoder (Plan C) needs three stated decisions: a maximum field value length, what to do with invalid UTF-8 (reject, replace, or pass through), and whether nested lists are flattened or rejected.
**Why:** From the SIG-15 adversarial review. `Wildcard.MatchString` is O(input x longest literal run), so a 1 MiB value against a rule with a 2000-character `contains` costs seconds and nothing upstream caps it. `strings.ToLower` maps invalid bytes to U+FFFD on both sides, so `Equals("a\xff")` matches `"a\xfe"` by accident. A list nested in a list never matches and never reaches the drop ledger, which the verdict invariant forbids.
**Context:** All three are ingest-side rules, not matcher rules; the matcher must stay a pure function of the value it is given. Write the decisions into the spec's data contract section when Plan C lands.
**Effort:** S
**Priority:** P2
**Depends on:** Plan C
**Completed:** SIG-27. All three are drops with their own reason code: a string over `MaxValueLen` (64 KiB default) is `value-too-long`, invalid UTF-8 anywhere in the record is `invalid-utf8` (checked before decoding, so nothing is replaced), and a list holding a list or an object is `nested-value`. Codes and rationale are in `internal/pipe/drop.go`.

### Add integration test entrypoint when compose lands
**What:** `make integration` and the `integration` CI job expect `deploy/docker-compose.yml` and a `-tags integration` build tag.
**Why:** The job is wired now so Plan C only has to add the compose file and tagged tests.
**Context:** See `.github/workflows/ci.yml` `integration` job and `Makefile` `integration` target.
**Effort:** S
**Priority:** P2
**Depends on:** Plan C (S-02)
**Completed:** SIG-26. `deploy/docker-compose.yml` runs Redpanda, a topic setup service, and ClickHouse; `internal/broker/kafka` carries the first `integration`-tagged tests.

### Stop an oracle subprocess that outlives its fuzz worker
**What:** If a fuzz worker is SIGKILLed while its pySigma subprocess is stuck in a backtracking regex, the subprocess keeps running until the regex finishes. When Python is idle, stdin EOF ends it, so only the stuck case leaks.
**Why:** From the SIG-21 adversarial review. It costs CPU on a long local run, not correctness: the worker is gone and nothing reads the answer.
**Context:** The obvious fixes do not work. A Python watchdog thread cannot run while `re` holds the GIL. Linux `Pdeathsig` fires when the OS thread that started the child exits, and the Go runtime can retire that thread, which would kill a healthy oracle mid-run and fail the case as `ErrOracleBroken`. A working option is a small supervisor: start the oracle under a wrapper that polls its parent pid from a separate process and kills the group.
**Effort:** S
**Priority:** P4
**Depends on:** nothing
**Completed:** v0.7.0 (2026-10-01). The oracle starts a watcher process that polls its parent and kills the oracle once the parent is gone; `OrphanWatch` in `test/fuzz/test_pysigma_eval.py` reproduces the stuck-regex case.

### Connect GitHub to Jira so merged PRs transition stories
**What:** Install the GitHub for Jira app on the SIG site, connect `atontalapur/signalman`, add one automation rule (pull request merged, transition to Done), and document it in `README.md` under "Working on it".
**Why:** Nothing in the repo moves ticket status. `scripts/jira_sync.py` is push-only: it creates and updates issues from `docs/backlog.yml` and never touches status. Branch names and PR titles already carry `SIG-<n>`, so the app needs no repo changes.
**Context:** Atlassian-side setup in a browser, about five minutes. Treat `backlog.yml` as the source for what the stories are and Jira as the source for where they stand; do not try to make the YAML track status.
**Effort:** S
**Priority:** P2
**Depends on:** None
**Completed:** 2026-09-16. GitHub for Jira app installed and `atontalapur/signalman` connected; automation rule "pull request merged, transition to Done" enabled on project SIG. Documented in `README.md` under "Working on it".

### Apply branch protection on main
**What:** Require the `go`, `python`, and `pr-policy` checks and a PR before merging to `main`.
**Why:** S-01 acceptance says direct pushes to `main` are rejected; nothing enforces that yet.
**Context:** Run after the first CI run on `main` so the check names exist. Command is in the PR body for #2 (`gh api -X PUT repos/atontalapur/signalman/branches/main/protection --input -`).
**Effort:** S
**Priority:** P1
**Depends on:** First merge to main with the new ci.yml
**Completed:** 2026-09-11. Protection is live: required checks `go`, `python`, `pr-policy` (strict), admins enforced, force pushes and deletions blocked. Verified with `gh api repos/atontalapur/signalman/branches/main/protection`.
