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

This deletes any resource group prefixed with `formae-plugin-sdk-test-`, then
**waits and verifies they are gone**, exiting non-zero if any survive. Two passes,
because a group can appear while the first pass is still deleting.

A scheduled **Reap Test Resources** workflow runs the same sweep every 6 hours as a
safety net, and can be dispatched manually. It exists because an in-run cleanup
cannot cover the cases that actually leak:

- a cancelled run whose jobs are still mid-create when the sweep lists groups
- a hard-cancelled run or dead runner, where `conformance-cleanup` never starts
- a local `TEST=<fixture>` run, where the Makefile deliberately skips its own
  cleanup — note the OOB-recreate phase builds a *second* resource group with a
  fresh run ID, so check for a stray `-rg-<id>` afterwards

The reaper shares the `azure-conformance-tests` concurrency group, so it queues
behind a live conformance run instead of deleting its resources. **A conformance run
on your own machine is invisible to that lock** — the reaper may delete its groups
mid-run. Prefer the Debug Conformance workflow for anything long.

## TL;DR

```bash
make install && make conformance-test
```

☕ Grab coffee. Tests hit real Azure APIs.
