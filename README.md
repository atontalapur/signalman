# Signalman

A Sigma detection engine and event pipeline in Go, built so that its evaluation core can be replaced under live traffic and proven equivalent before the old one is retired.

- Spec: `docs/spec/signalman-v1.html`
- Roadmap: `docs/superpowers/plans/2026-09-10-signalman-roadmap.md`
- Backlog (source of truth for Jira): `docs/backlog.yml`
- Sync backlog to Jira: `JIRA_SITE=... JIRA_EMAIL=... JIRA_TOKEN=... scripts/jira_sync.py`

Before every commit: `make check`. CI runs the same target on every PR (`.github/workflows/ci.yml`), fuzzers run nightly, and a `v*` tag cuts a release with binaries and a GHCR image (`.goreleaser.yaml`).

Work is tracked in Jira project SIG. Every branch is `feat/SIG-<n>-<slug>` and every PR names its story.
