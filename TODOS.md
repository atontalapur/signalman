# TODOS

Engineering debt too small for a Jira story. Stories live in `docs/backlog.yml`.

## Infrastructure

### Connect GitHub to Jira so merged PRs transition stories
**What:** Install the GitHub for Jira app on the SIG site, connect `atontalapur/signalman`, add one automation rule (pull request merged, transition to Done), and document it in `README.md` under "Working on it".
**Why:** Nothing in the repo moves ticket status. `scripts/jira_sync.py` is push-only: it creates and updates issues from `docs/backlog.yml` and never touches status. Branch names and PR titles already carry `SIG-<n>`, so the app needs no repo changes.
**Context:** Atlassian-side setup in a browser, about five minutes. Treat `backlog.yml` as the source for what the stories are and Jira as the source for where they stand; do not try to make the YAML track status.
**Effort:** S
**Priority:** P2
**Depends on:** None

### Keep cmd/corpusaccept out of releases
**What:** GoReleaser builds every `main` under `./...`, so the corpus acceptance tool ships in every `v*` tarball and the Docker image.
**Why:** It is a dev tool that needs a vendored corpus; shipping it is noise, not harm.
**Context:** `.goreleaser.yaml` build id `cmds` uses `main: ./...` on purpose so new `cmd/` dirs appear automatically. Options: an `ignore` list in the build, or move the tool under `tools/`. Revisit when the first release is cut.
**Effort:** S
**Priority:** P4
**Depends on:** Plan A Task 13

### Revisit Value layout and Text() allocation for the v2 hot path
**What:** `event.Value` is 64 bytes with every payload slot present, and `Value.Text()` allocates a string per call for `KindInt` and `KindBool`. Both sit on the per-field, per-rule comparison path.
**Why:** Flagged by the SIG-13 pre-landing review. v1 is never optimized by rule, and the v2 hot path is Plan G, so the layout stays as the plan specifies until there is a benchmark to justify changing it.
**Context:** Options noted in review: fold `I` and `B` into one slot, move `L` behind a pointer, add `AppendText(dst []byte)` using `strconv.AppendInt`, and a `BenchmarkValueText` asserting 0 allocs/op. From the SIG-15 review, on the same path: `Wildcard.MatchString` lowercases and rune-decodes the input per call, `Any`/`All` repeat that per value in a list, and `Contains`/`StartsWith`/`EndsWith` without author wildcards could use `strings.Contains`/`HasPrefix`/`HasSuffix` on a once-lowered input. Decide in Plan G with numbers.
**Effort:** M
**Priority:** P3
**Depends on:** Plan G

### Decide event value limits at decode time
**What:** The decoder (Plan C) needs three stated decisions: a maximum field value length, what to do with invalid UTF-8 (reject, replace, or pass through), and whether nested lists are flattened or rejected.
**Why:** From the SIG-15 adversarial review. `Wildcard.MatchString` is O(input x longest literal run), so a 1 MiB value against a rule with a 2000-character `contains` costs seconds and nothing upstream caps it. `strings.ToLower` maps invalid bytes to U+FFFD on both sides, so `Equals("a\xff")` matches `"a\xfe"` by accident. A list nested in a list never matches and never reaches the drop ledger, which the verdict invariant forbids.
**Context:** All three are ingest-side rules, not matcher rules; the matcher must stay a pure function of the value it is given. Write the decisions into the spec's data contract section when Plan C lands.
**Effort:** S
**Priority:** P2
**Depends on:** Plan C

### Add integration test entrypoint when compose lands
**What:** `make integration` and the `integration` CI job expect `deploy/docker-compose.yml` and a `-tags integration` build tag.
**Why:** The job is wired now so Plan C only has to add the compose file and tagged tests.
**Context:** See `.github/workflows/ci.yml` `integration` job and `Makefile` `integration` target.
**Effort:** S
**Priority:** P2
**Depends on:** Plan C (S-02)

## Completed

### Apply branch protection on main
**What:** Require the `go`, `python`, and `pr-policy` checks and a PR before merging to `main`.
**Why:** S-01 acceptance says direct pushes to `main` are rejected; nothing enforces that yet.
**Context:** Run after the first CI run on `main` so the check names exist. Command is in the PR body for #2 (`gh api -X PUT repos/atontalapur/signalman/branches/main/protection --input -`).
**Effort:** S
**Priority:** P1
**Depends on:** First merge to main with the new ci.yml
**Completed:** 2026-09-11. Protection is live: required checks `go`, `python`, `pr-policy` (strict), admins enforced, force pushes and deletions blocked. Verified with `gh api repos/atontalapur/signalman/branches/main/protection`.
