.PHONY: build test test-race test-fail lint docker clean help

# Use the project-local Go install if present (drop in .go/), fall back
# to whatever's on PATH. Lets `make build` work without sourcing
# activate.sh first.
GO := $(shell test -x ./.go/go/bin/go && echo ./.go/go/bin/go || echo go)
GOLANGCI := $(shell command -v golangci-lint 2>/dev/null)

BIN := bin/ospooflog
PKG := ./cmd/ospooflog

build: ## build the CLI binary
	$(GO) build -ldflags="-s -w" -o $(BIN) $(PKG)

test: ## run tests without race detector
	$(GO) test -count=1 ./...

test-race: ## run tests with race detector (requires gcc)
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

test-fail: ## run the intentionally-red canaries (TestFail*); passes only when every one fails
	$(GO) vet -tags failtests ./... # catch compile errors so the inversion below can't mask them
	@out=$$($(GO) test -tags failtests -run TestFail -count=1 -v ./... 2>&1); echo "$$out"; \
	if echo "$$out" | grep -q '^=== RUN   TestFail' && ! echo "$$out" | grep -q '^--- PASS: TestFail'; then \
		echo "OK: every canary failed as designed"; \
	else \
		echo "FAIL: a canary passed or none ran — a guarantee silently stopped holding"; exit 1; \
	fi

lint: ## run golangci-lint if available, otherwise go vet
ifeq ($(GOLANGCI),)
	@echo "golangci-lint not found, running go vet"
	$(GO) vet ./...
else
	$(GOLANGCI) run ./...
endif

docker: ## build the Docker image
	docker build -t ospooflog:latest .

clean: ## remove built artifacts
	rm -rf bin/

help: ## show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
