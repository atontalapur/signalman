## Jira

SIG-

## What

## How verified

- [ ] `make check` clean locally (gofmt, vet, tidy, build, race tests, staticcheck, govulncheck)
- [ ] Acceptance criteria on the Jira story checked
- [ ] No unbounded buffers: every channel, queue, or slice that grows with traffic has a stated bound, and a full one blocks rather than drops
