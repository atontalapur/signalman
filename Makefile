# Single entrypoint for the checks CI runs. Keep CI and local in sync by
# adding new checks here, not in the workflow files.

GO_PKGS := ./...
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0

.PHONY: check fmt vet test build lint tidy-check fuzz fuzz-differential check-backlog check-python integration

## check: everything a PR must pass. Same as the ci workflow's go job.
check: fmt tidy-check vet build test lint

fmt:
	@out=$$(gofmt -l . 2>&1) || { echo "$$out"; exit 1; }; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet $(GO_PKGS)

tidy-check:
	go mod tidy -diff

build:
	go build $(GO_PKGS)

## The differential fuzzer skips every case without its oracle, and a fully
## skipped package prints "ok" like any other. Say so, or a green check reads
## as proof of something it never ran.
test:
	@[ -x test/fuzz/.venv/bin/python ] || echo "note: test/fuzz oracle venv absent, the pySigma differential tests will SKIP (see README)"
	go test -race -count=1 $(GO_PKGS)

lint:
	go run $(STATICCHECK) $(GO_PKGS)
	go run $(GOVULNCHECK) $(GO_PKGS)

## integration: needs Redpanda and ClickHouse up (deploy/docker-compose.yml).
integration:
	go test -race -count=1 -tags integration $(GO_PKGS)

## fuzz: run every Fuzz* target for FUZZTIME each, keep going after a crasher,
## fail at the end. Nightly runs this with 10m.
FUZZTIME ?= 30s
fuzz:
	@rc=0; for pkg in $$(go list $(GO_PKGS)); do \
	  list=$$(go test -list '^Fuzz' $$pkg) || exit 1; \
	  for f in $$(printf '%s\n' "$$list" | grep '^Fuzz'); do \
	    echo "== $$pkg $$f"; \
	    go test -run '^$$' -fuzz "^$$f\$$" -fuzztime $(FUZZTIME) $$pkg || rc=1; \
	  done; \
	done; exit $$rc

check-backlog:
	python3 scripts/backlog_check.py

check-python:
	python3 -m ruff check scripts test/fuzz
	python3 -m py_compile scripts/*.py test/fuzz/*.py

## fuzz-differential: the pySigma differential fuzzer, with the per-worker
## counters summed at the end. Executions are not comparisons: see
## scripts/fuzz_stats.py. Needs test/fuzz/.venv, built from
## test/fuzz/requirements.txt.
## Each worker holds a Python interpreter with pySigma loaded, so worker
## count is a memory budget, not a core count: one per core exhausts a
## laptop long before the time budget runs out.
FUZZSTATS := $(CURDIR)/.fuzzstats
FUZZWORKERS ?= 4
## A run that compares nothing passes every other check. Nightly holds a
## floor; interactive runs default to 0 so a 30s smoke run is not a failure.
FUZZMINCOMPARED ?= 0
fuzz-differential:
	@rm -rf $(FUZZSTATS) && mkdir -p $(FUZZSTATS)
	SIGNALMAN_FUZZ_STATS=$(FUZZSTATS) go test ./test/fuzz/ \
	  -run '^$$' -fuzz '^FuzzAgainstPySigma$$' -parallel $(FUZZWORKERS) \
	  -fuzztime $(FUZZTIME)
	@python3 scripts/fuzz_stats.py $(FUZZSTATS) --min-compared $(FUZZMINCOMPARED)
