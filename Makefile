# Single entrypoint for the checks CI runs. Keep CI and local in sync by
# adding new checks here, not in the workflow files.

GO_PKGS := ./...
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0

.PHONY: check fmt vet test build lint tidy-check fuzz check-backlog check-python integration

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

test:
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
	python3 -m ruff check scripts
	python3 -m py_compile scripts/*.py
