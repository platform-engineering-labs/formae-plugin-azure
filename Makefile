# Formae Plugin Makefile
#
# Targets:
#   build   - Build the plugin binary
#   test    - Run tests
#   lint    - Run linter
#   clean   - Remove build artifacts
#   install - Build and install plugin locally (binary + schema + manifest)

# Plugin metadata - extracted from formae-plugin.pkl
PLUGIN_NAME := $(shell pkl eval -x 'name' formae-plugin.pkl 2>/dev/null || echo "example")
PLUGIN_VERSION := $(shell pkl eval -x 'version' formae-plugin.pkl 2>/dev/null || echo "0.0.0")
PLUGIN_NAMESPACE := $(shell pkl eval -x 'namespace' formae-plugin.pkl 2>/dev/null || echo "EXAMPLE")

# Build settings
GO := go
GOFLAGS := -trimpath
BINARY := $(PLUGIN_NAME)

# Installation paths
# Plugin discovery expects lowercase directory names matching the plugin name
PLUGIN_BASE_DIR := $(HOME)/.pel/formae/plugins
INSTALL_DIR := $(PLUGIN_BASE_DIR)/$(PLUGIN_NAME)/v$(PLUGIN_VERSION)

.PHONY: all build test test-unit test-integration lint verify-schema clean install help setup-credentials clean-environment conformance-test conformance-test-crud conformance-test-discovery gen-pkl

all: build

## build: Build the plugin binary
build:
	$(GO) build $(GOFLAGS) -o bin/$(BINARY) .

## test: Run all tests
test:
	$(GO) test -v ./...

## test-unit: Run unit tests only (tests with //go:build unit tag)
test-unit:
	$(GO) test -v -tags=unit ./...

## test-integration: Run integration tests (requires cloud credentials)
## Add tests with //go:build integration tag
test-integration:
	$(GO) test -v -tags=integration ./...

## lint: Run golangci-lint
lint:
	golangci-lint run

## verify-schema: Validate PKL schema files
## Checks that schema files are well-formed and follow formae conventions.
verify-schema:
	$(GO) run github.com/platform-engineering-labs/formae/pkg/plugin/testutil/cmd/verify-schema --namespace $(PLUGIN_NAMESPACE) ./schema/pkl

## gen-pkl: Resolve all PKL project dependencies
gen-pkl:
	pkl project resolve schema/pkl
	pkl project resolve examples
	pkl project resolve testdata

## clean: Remove build artifacts
clean:
	rm -rf bin/ dist/

## install: Build and install plugin locally (binary + schema + manifest)
## Installs to ~/.pel/formae/plugins/<name>/v<version>/
## Removes any existing versions of the plugin first to ensure clean state.
install: build
	@echo "Installing $(PLUGIN_NAME) v$(PLUGIN_VERSION) (namespace: $(PLUGIN_NAMESPACE))..."
	@rm -rf $(PLUGIN_BASE_DIR)/$(PLUGIN_NAME)
	@mkdir -p $(INSTALL_DIR)/schema/pkl
	@cp bin/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	@cp -r schema/pkl/* $(INSTALL_DIR)/schema/pkl/
	@cp formae-plugin.pkl $(INSTALL_DIR)/
	@echo "Installed to $(INSTALL_DIR)"
	@echo "  - Binary: $(INSTALL_DIR)/$(BINARY)"
	@echo "  - Schema: $(INSTALL_DIR)/schema/pkl/"
	@echo "  - Manifest: $(INSTALL_DIR)/formae-plugin.pkl"

## install-dev: Build and install plugin for local development (version 0.0.0)
## Use this when testing with formae debug builds which use version 0.0.0.
DEV_INSTALL_DIR := $(PLUGIN_BASE_DIR)/$(PLUGIN_NAME)/v0.0.0
install-dev: build
	@echo "Installing $(PLUGIN_NAME) v0.0.0 (dev) (namespace: $(PLUGIN_NAMESPACE))..."
	@rm -rf $(PLUGIN_BASE_DIR)/$(PLUGIN_NAME)
	@mkdir -p $(DEV_INSTALL_DIR)/schema/pkl
	@cp bin/$(BINARY) $(DEV_INSTALL_DIR)/$(BINARY)
	@cp -r schema/pkl/* $(DEV_INSTALL_DIR)/schema/pkl/
	@cp formae-plugin.pkl $(DEV_INSTALL_DIR)/
	@echo "Installed to $(DEV_INSTALL_DIR)"
	@echo "  - Binary: $(DEV_INSTALL_DIR)/$(BINARY)"
	@echo "  - Schema: $(DEV_INSTALL_DIR)/schema/pkl/"
	@echo "  - Manifest: $(DEV_INSTALL_DIR)/formae-plugin.pkl"

## help: Show this help message
help:
	@echo "Available targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'

## setup-credentials: Verify Azure credentials are configured
## Edit scripts/ci/setup-credentials.sh to configure for your provider.
setup-credentials:
	@./scripts/ci/setup-credentials.sh

## clean-environment: Clean up test resources in cloud environment
## Called before and after conformance tests. Edit scripts/ci/clean-environment.sh
## to configure for your provider.
clean-environment:
	@./scripts/ci/clean-environment.sh

## conformance-test: Run all conformance tests (CRUD + discovery)
## Usage: make conformance-test [VERSION=0.80.0] [TEST=resourcegroup]
## Downloads the specified formae version (or latest) and runs conformance tests.
## Calls setup-credentials and clean-environment automatically.
##
## Parameters:
##   VERSION - Formae version to test against (default: latest)
##   TEST    - Filter tests by name pattern (e.g., TEST=resourcegroup)
conformance-test: conformance-test-crud conformance-test-discovery

## conformance-test-crud: Run only CRUD lifecycle tests
## Usage: make conformance-test-crud [VERSION=0.80.0] [TEST=resourcegroup]
conformance-test-crud: install setup-credentials
	@echo "Pre-test cleanup..."
	@./scripts/ci/clean-environment.sh || true
	@echo ""
	@echo "Running CRUD conformance tests..."
	@FORMAE_TEST_FILTER="$(TEST)" FORMAE_TEST_TYPE=crud ./scripts/run-conformance-tests.sh $(VERSION); \
	TEST_EXIT=$$?; \
	echo ""; \
	echo "Post-test cleanup..."; \
	./scripts/ci/clean-environment.sh || true; \
	exit $$TEST_EXIT

## conformance-test-discovery: Run only discovery tests
## Usage: make conformance-test-discovery [VERSION=0.80.0] [TEST=resourcegroup]
conformance-test-discovery: install setup-credentials
	@echo "Pre-test cleanup..."
	@./scripts/ci/clean-environment.sh || true
	@echo ""
	@echo "Running discovery conformance tests..."
	@FORMAE_TEST_FILTER="$(TEST)" FORMAE_TEST_TYPE=discovery ./scripts/run-conformance-tests.sh $(VERSION); \
	TEST_EXIT=$$?; \
	echo ""; \
	echo "Post-test cleanup..."; \
	./scripts/ci/clean-environment.sh || true; \
	exit $$TEST_EXIT
