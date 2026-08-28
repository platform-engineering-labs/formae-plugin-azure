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

## What CI Runs

| Event | Conformance scope |
|---|---|
| Pull request | Only the fixtures the PR added or modified (`testdata/*.pkl`) |
| Pull request labelled `full-conformance` | The whole curated matrix |
| Push to `main` | The whole curated matrix |
| Nightly | The whole curated matrix, against formae `main` |

A fixture's `-update` / `-replace` companion maps back to the fixture itself, so
editing only `web-app-update.pkl` still runs `web-app`. Deleted fixtures are
ignored. A PR touching no fixture runs no conformance at all, which is what makes
a plumbing or refactor PR fast.

**Shared code is the gap to know about.** A change under `pkg/client/`,
`pkg/prov/` or `pkg/resources/common.go` affects every resource but touches no
fixture, so it resolves to an empty scope. Either add the `full-conformance`
label to that PR, or rely on push-to-`main`, which always runs the full matrix.

The resolution logic lives in `scripts/ci/conformance-scope.sh` and has a
self-check that needs no cloud creds:

```bash
./scripts/ci/conformance-scope_test.sh
```

To run a specific set against a branch regardless of what changed, dispatch the
Debug Conformance workflow:

```bash
gh workflow run debug-conformance.yml --ref <branch> -f resources=web-app
gh workflow run debug-conformance.yml --ref <branch> -f resources='web-app,function-app' -f phases=crud
```

Every conformance run - CI, nightly and debug - shares the
`azure-conformance-tests` concurrency group, because they all target one Azure
subscription. Runs queue rather than race. GitHub keeps only **one** run in that
queue, so a third concurrent run evicts the waiting one and it reports as
`cancelled` rather than failed; re-run it once the slot frees.

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
