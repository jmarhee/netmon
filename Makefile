# Makefile for inet-tool-cli (netmon)
#
# Usage:
#   make help          - show this help
#   make build         - build the netmon binary (output: bin/netmon)
#   make test          - run unit tests
#   make cover         - run tests and produce coverage report
#   make lint          - run linter (uses golangci-lint if installed, falls back to go vet)
#   make fmt           - run go fmt on the module
#   make vet           - run go vet
#   make tidy          - run go mod tidy
#   make run           - build and run the binary (pass ARGS to the program)
#   make clean         - remove build artifacts
#
# Notes:
# - This Makefile tries to be conservative about tool availability. If you want
#   golangci-lint integration, install it locally (recommended) or the lint
#   target will use `go vet` as a fallback.

GO ?= go
BINARY ?= netmon
OUTDIR ?= bin
PKG ?= ./...
BUILD_DIR_MAIN ?= .
# CGO is required for packet capture (gopacket/pcap) on platforms that use
# the system libpcap. Enable CGO by default so `make build`/`make run` will
# succeed when the pcap-backed monitor is compiled.
CGO_ENABLED ?= 1

# Common build flags (add LDFLAGS for version stamping)
LD_FLAGS ?=
BUILD_FLAGS ?=

.DEFAULT_GOAL := help

.PHONY: help build test cover lint fmt vet tidy run install-deps clean

help:
	@echo "Makefile for inet-tool-cli (netmon)"
	@echo ""
	@echo "Available targets:"
	@echo "  help         Show this help"
	@echo "  build        Build the netmon binary -> $(OUTDIR)/$(BINARY)"
	@echo "  test         Run unit tests"
	@echo "  cover        Run tests with coverage (coverage.out) and show func summary"
	@echo "  lint         Run linter (golangci-lint if installed, otherwise go vet)"
	@echo "  fmt          Run go fmt ./..."
	@echo "  vet          Run go vet ./..."
	@echo "  tidy         Run go mod tidy"
	@echo "  run          Build and run the binary (pass ARGS to program)"
	@echo "  install-deps Install optional tooling (golangci-lint)"
	@echo "  clean        Remove build artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make run ARGS=\"-once -subnet 192.168.1.0/24\""
	@echo "  make lint"

# Ensure output directory exists then build
build: $(OUTDIR)/$(BINARY)

$(OUTDIR)/$(BINARY): $(shell find . -name '*.go')
	@mkdir -p $(OUTDIR)
	@echo "Building $(BINARY) -> $(OUTDIR)/$(BINARY)"
	@CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(BUILD_FLAGS) -ldflags '$(LD_FLAGS)' -o $(OUTDIR)/$(BINARY) $(BUILD_DIR_MAIN)

test:
	@echo "Running unit tests..."
	@$(GO) test -v ./...

cover:
	@echo "Running tests with coverage..."
	@$(GO) test ./... -coverprofile=coverage.out
	@echo ""
	@echo "Coverage summary:"
	@$(GO) tool cover -func=coverage.out

fmt:
	@echo "Formatting Go files..."
	@$(GO) fmt ./...

vet:
	@echo "Running go vet..."
	@$(GO) vet ./...

lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "Using golangci-lint"; \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found, falling back to 'go vet'"; \
		$(MAKE) vet; \
	fi

tidy:
	@echo "Running go mod tidy..."
	@$(GO) mod tidy

run: build
	@echo "Running $(OUTDIR)/$(BINARY) with ARGS='$(ARGS)'>"
	@$(OUTDIR)/$(BINARY) $(ARGS)

# Install optional development tooling (local machine)
install-deps:
	@echo "Installing optional dev tools (golangci-lint)..."
	@$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Done. Make sure $(shell $(GO) env GOPATH)/bin is in your PATH."

clean:
	@echo "Removing build artifacts..."
	@rm -rf $(OUTDIR) coverage.out

# Convenience target for CI to run lint+test quickly
ci: fmt vet lint test
