# Running Azure Plugin Conformance Tests

## Prerequisites

1. **Azure CLI** logged in (`az login`)
2. **formae** built and installed (`./formae` in formae-internal)
3. **Plugin installed** to `~/.pel/formae/plugins/azure/v0.1.0/`

## Quick Start

```bash
cd formae-plugin-azure

# Build and install plugin
make install

# Verify Azure creds work
make setup-credentials

# Run tests (don't forget the version!)
make conformance-test
```

## If Tests Fail With "resource is taken"

There's a rogue formae agent lurking. Kill it:

```bash
pkill -f formae
```

Then retry.

## Test Subsets

```bash
# Just CRUD tests
make conformance-test-crud

# Just discovery tests
make conformance-test-discovery

# Single resource (e.g., just resourcegroup)
make conformance-test-crud TEST=resourcegroup
```

## What Gets Tested

Test fixtures live in `testdata/`:
- `resources/resourcegroup/` - Resource Group CRUD
- `network/virtualnetwork/` - VNet CRUD
- `network/subnet/` - Subnet CRUD

Each has `*.pkl`, `*-update.pkl`, and `*-replace.pkl` files for create/update/replace scenarios.

## Cleanup

If tests leave orphaned resources in Azure:

```bash
make clean-environment
```

This deletes any resource groups prefixed with `formae-plugin-sdk-test-`.

## TL;DR

```bash
make install && make conformance-test
```

☕ Grab coffee. Tests hit real Azure APIs.
