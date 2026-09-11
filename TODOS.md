# TODOS

Engineering debt too small for a Jira story. Stories live in `docs/backlog.yml`.

## Infrastructure

### Apply branch protection on main
**What:** Require the `go`, `python`, and `pr-policy` checks and a PR before merging to `main`.
**Why:** S-01 acceptance says direct pushes to `main` are rejected; nothing enforces that yet.
**Context:** Run after the first CI run on `main` so the check names exist. Command is in the PR body for #2 (`gh api -X PUT repos/atontalapur/signalman/branches/main/protection --input -`).
**Effort:** S
**Priority:** P1
**Depends on:** First merge to main with the new ci.yml

### Add integration test entrypoint when compose lands
**What:** `make integration` and the `integration` CI job expect `deploy/docker-compose.yml` and a `-tags integration` build tag.
**Why:** The job is wired now so Plan C only has to add the compose file and tagged tests.
**Context:** See `.github/workflows/ci.yml` `integration` job and `Makefile` `integration` target.
**Effort:** S
**Priority:** P2
**Depends on:** Plan C (S-02)

## Completed
