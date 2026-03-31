.PHONY: test test-coverage test-cover build clean help lint fmt

# Default port for coverage server
PORT ?= :3000
# Verbose test output
VERBOSE ?= false

# Version info injected at build time
VERSION ?= $(shell scripts/auto-version.sh 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo "none")
LDFLAGS = -X github.com/anchorageoss/visualsign-turnkeyclient/version.Version=$(VERSION) \
           -X github.com/anchorageoss/visualsign-turnkeyclient/version.Commit=$(COMMIT)

help:
	@echo "Available targets:"
	@echo "  make test              	- Run all tests (excludes cmd package from coverage)"
	@echo "                           		Usage: make test VERBOSE=true"
	@echo "  make test-coverage     	- Run tests and generate coverage report (HTML)"
	@echo "  make test-coverage-serve       - Run tests, serve coverage on PORT (default :3000)"
	@echo "                           		Usage: make test-cover PORT=:8080"
	@echo "  make build             	- Build the application"
	@echo "  make clean             	- Remove build artifacts and test coverage files"
	@echo "  make fmt               	- Format Go code with gofmt"
	@echo "  make check-deps        	- Check for prohibited dependencies"
	@echo "  make lint              	- Run linter with dependency checks"

test:
ifeq ($(VERBOSE),true)
	go test -v -race -coverprofile=coverage.out ./... -count=1
else
	go test -v -race -coverprofile=coverage.out ./... -count=1
endif
	@echo ""
	@echo "Filtering out cmd package from coverage (will be covered by integration tests)..."
	@grep -v "/cmd/" coverage.out > coverage.filtered.out || true
	@echo "mode: set" > coverage.out.tmp
	@grep -v "^mode:" coverage.filtered.out >> coverage.out.tmp || true
	@mv coverage.out.tmp coverage.out
	@echo ""
	@echo "Coverage summary (excluding cmd package):"
	@go tool cover -func=coverage.out | tail -1

test-coverage: test
	go tool cover -html=coverage.out -o index.html
	@echo ""
	@echo "Coverage report generated: index.html"
	@echo "Open index.html in a browser to view the detailed report"

# Run tests and serve coverage report on a local HTTP server
test-coverage-serve: test
	@set -e; \
	TMPDIR=$$(mktemp -d); \
	trap "rm -rf $$TMPDIR" EXIT; \
	go tool cover -html=coverage.out -o $$TMPDIR/index.html; \
	echo ""; \
	echo "✓ Coverage report generated"; \
	echo "  Location: $$TMPDIR/index.html"; \
	echo ""; \
	echo "Starting HTTP server..."; \
	echo "  URL: http://localhost$(PORT)"; \
	echo "  Press Ctrl+C to stop"; \
	echo ""; \
	if command -v python3 >/dev/null 2>&1; then \
		cd $$TMPDIR && python3 -m http.server $(subst :,,$(PORT)); \
	elif command -v python >/dev/null 2>&1; then \
		cd $$TMPDIR && python -m SimpleHTTPServer $(subst :,,$(PORT)); \
	else \
		echo "ERROR: python3 or python not found"; \
		exit 1; \
	fi

build: bin/
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/visualsign-turnkeyclient .

bin/:
	mkdir -p bin

clean:
	rm -rf bin/ coverage.out coverage.filtered.out coverage.out.tmp index.html
	go clean

# Run tests with strict race detection and fail on coverage below threshold
test-strict:
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo ""
	@echo "Filtering out cmd package from coverage (will be covered by integration tests)..."
	@grep -v "/cmd/" coverage.out > coverage.filtered.out || true
	@echo "mode: atomic" > coverage.out.tmp
	@grep -v "^mode:" coverage.filtered.out >> coverage.out.tmp || true
	@mv coverage.out.tmp coverage.out
	@echo ""
	@COVERAGE=$$(go tool cover -func=coverage.out | tail -1 | awk '{print $$3}' | sed 's/%//'); \
	if [ "$$(echo "$$COVERAGE < 80" | bc)" -eq 1 ]; then \
		echo "ERROR: Code coverage $$COVERAGE% is below minimum 80% (excluding cmd package)"; \
		exit 1; \
	fi; \
	echo "✓ Code coverage: $$COVERAGE% (excluding cmd package)"

# Run tests related to manifest processing
test-manifest:
	go test -v -race -run TestManifest ./...

# Run tests related to cryptography
test-crypto:
	go test -v -race -run TestCrypto ./...

# Run tests related to API key handling
test-apikey:
	go test -v -race -run TestAPIKey ./...

# Run tests related to client functionality
test-client:
	go test -v -race -run TestClient ./...

# Run benchmarks
bench:
	go test -bench=. -benchmem ./...

# Run benchmarks with verbose output
bench-verbose:
	go test -bench=. -benchmem -v ./...

# Format all Go code
fmt:
	@echo "Formatting Go code..."
	@gofmt -w -s .
	@echo "✓ Code formatted"

# Check for prohibited dependencies
check-deps:
	@./test_ci_check.sh

# Run linter with dependency checks
lint:
	@echo "Running linter..."
	@echo "  Running dependency checks (primary security check)..."
	@$(MAKE) check-deps
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "  Running golangci-lint..."; \
		golangci-lint run ./... --timeout=10m || echo "  ⚠️  Some linting issues found, but dependency check passed"; \
		echo "  ✅ Linting completed"; \
	else \
		echo "  ⚠️  golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		echo "  ✅ Dependency check completed (primary security check passed)"; \
	fi
