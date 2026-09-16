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
