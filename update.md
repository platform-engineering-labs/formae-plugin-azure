# Migrating a Formae Plugin from Monorepo to Standalone Repository

## Overview

This document describes migrating a cloud provider plugin (Azure) from the `formae-internal` monorepo to a standalone repository following the external plugin template pattern. Use this as a guide for migrating other plugins (e.g., GCP, OVH, OCI).

## ⚠️ Important: Use `formae plugin init`

We migrated Azure manually from the monorepo. **Don't do this.** Use `formae plugin init` instead - it scaffolds from `formae-plugin-template` which has everything set up correctly, including:
- `.github/workflows/ci.yml` with `VERSION=0.77.16-internal` already pinned
- `.github/dependabot.yml`
- `LICENSE`
- `README.md` template

```bash
formae plugin init my-plugin
```

If running conformance tests manually:
```bash
make conformance-test VERSION=0.77.16-internal
```

## Source and Destination

- **Source**: `formae-internal/plugins/<provider>/` (the monorepo)
- **Destination**: `formae-plugin-<provider>/` (new standalone repo)
- **Reference**: `formae-plugin-aws/` (already migrated, use as template)

## File Structure Comparison

The standalone plugin should have this structure:

```
formae-plugin-<provider>/
├── .github/
│   ├── dependabot.yml          # Missing in Azure, exists in AWS
│   └── workflows/ci.yml        # Missing in Azure, exists in AWS
├── .gitignore
├── LICENSE                      # Missing in Azure, exists in AWS
├── Makefile
├── README.md                    # Missing in Azure, exists in AWS
├── conformance_test.go
├── formae-plugin.pkl            # Plugin manifest (name, version, namespace)
├── go.mod
├── go.sum
├── main.go
├── plugin.go                    # Or <provider>.go (AWS uses aws.go)
├── pkg/
│   ├── client/client.go         # Provider SDK client wrapper
│   ├── config/config.go         # Target config extraction
│   ├── prov/provisioner.go      # Provisioner interface
│   ├── registry/registry.go     # ResourceType → Provisioner mapping
│   └── resources/               # Individual resource provisioners
├── schema/pkl/
│   ├── PklProject
│   ├── PklProject.deps.json
│   ├── VERSION                  # Contains "0.1.0"
│   └── <resource-schemas>.pkl
├── scripts/
│   ├── ci/
│   │   ├── clean-environment.sh
│   │   └── setup-credentials.sh
│   └── run-conformance-tests.sh
├── examples/
│   ├── PklProject
│   ├── PklProject.deps.json
│   └── <example-dirs>/
└── testdata/
    ├── PklProject
    ├── PklProject.deps.json
    └── <test-fixtures>/
```

## Key Files to Create/Update

### 1. Makefile

Compare with AWS Makefile and ensure these targets exist:

| Target | Description |
|--------|-------------|
| `build` | Build plugin binary to `bin/<name>` |
| `install` | Install to `~/.pel/formae/plugins/<name>/v<version>/` |
| `install-dev` | Install as v0.0.0 for debug builds |
| `test` | Run all tests |
| `test-unit` | Run unit tests only |
| `test-integration` | Run integration tests |
| `lint` | Run golangci-lint |
| `gen-pkl` | Resolve all PklProject dependencies |
| `setup-credentials` | Verify cloud credentials |
| `clean-environment` | Clean up test resources |
| `conformance-test` | Run full conformance suite |
| `conformance-test-crud` | Run CRUD tests only |
| `conformance-test-discovery` | Run discovery tests only |

**Important**: Update example filter names in comments from AWS examples (e.g., `s3-bucket`) to provider-specific examples (e.g., `resourcegroup`).

### 2. go.mod

```go
module github.com/platform-engineering-labs/formae-plugin-<provider>

go 1.25

require (
    // Provider SDK dependencies
    github.com/platform-engineering-labs/formae/pkg/model v0.1.1
    github.com/platform-engineering-labs/formae/pkg/plugin v0.1.3  // Match AWS version
    github.com/platform-engineering-labs/formae/pkg/plugin-conformance-tests v0.1.6
)
```

**Important**:
- Remove any `replace` directives pointing to `../formae-internal`
- Remove `toolchain` directive
- Update formae SDK versions to match AWS

### 3. schema/pkl/PklProject

```pkl
amends "pkl:Project"

dependencies {
  ["formae"] {
    uri = "package://hub.platform.engineering/plugins/pkl/schema/pkl/formae/formae@0.77.16-internal"
  }
}

package {
  name = "<provider>"
  baseUri = "package://hub.platform.engineering/plugins/<provider>/schema/pkl/\(name)/\(name)"
  version = read("VERSION").text.trim()
  packageZipUrl = "https://hub.platform.engineering/plugins/<provider>/schema/pkl/\(name)/\(name)@\(version).zip"
}
```

### 4. schema/pkl/VERSION

```
0.1.0
```

### 5. examples/PklProject

```pkl
amends "pkl:Project"

dependencies {
  ["formae"] {
    uri = "package://hub.platform.engineering/plugins/pkl/schema/pkl/formae/formae@0.77.16-internal"
  }
  ["<provider>"] = import("../schema/pkl/PklProject")
}
```

### 6. testdata/PklProject

Same pattern as examples/PklProject - reference formae via package URI, reference local schema via import.

**Gotcha**: Old monorepo paths like `import("../../pkl/schema/PklProject")` need to be updated to package URIs.

### 7. scripts/ci/setup-credentials.sh

Create provider-specific credential verification:

For Azure:
- Check `~/.azure/azureProfile.json` exists
- Parse with `jq` to get subscription/tenant ID
- Check for service principal env vars as alternative
- Verify with `az account show`

For AWS (reference):
- Check AWS env vars or profile
- Check region is set
- Verify with `aws sts get-caller-identity`

For other providers, follow similar pattern with their CLI tools.

### 8. scripts/run-conformance-tests.sh

**Note**: Default version is "latest" but for internal builds, pass the version explicitly:

```bash
make conformance-test VERSION=0.77.16-internal
```

## formae-internal Makefile Updates

After migrating a plugin, update `formae-internal/Makefile`:

### 1. Add to EXTERNAL_PLUGIN_REPOS

```make
EXTERNAL_PLUGIN_REPOS ?= \
    https://github.com/platform-engineering-labs/formae-plugin-aws.git \
    https://github.com/platform-engineering-labs/formae-plugin-<provider>.git \
    ...
```

### 2. Remove from internal build targets

Remove the provider from:
- `build:` target
- `build-debug:` target
- `tidy-all:` target
- `gen-pkl:` target (if applicable)
- `pkg-pkl:` target (if applicable)
- `publish-pkl:` target (if applicable)
- `pkg-bin:` target (remove cp commands for the provider)
- `.PHONY:` line (remove install-<provider>-plugin targets)

### 3. Remove install targets

Delete:
- `install-<provider>-plugin:`
- `install-<provider>-plugin-dev:`

## Git Repository Setup

1. **Initialize** (if not already a git repo):
   ```bash
   git init
   ```

2. **Create GitHub repo** (via UI or CLI):
   ```bash
   gh repo create platform-engineering-labs/formae-plugin-<provider> --private
   ```

   Or create via GitHub UI at https://github.com/organizations/platform-engineering-labs/repositories/new

3. **Add remote and push**:
   ```bash
   git remote add origin git@github.com:platform-engineering-labs/formae-plugin-<provider>.git
   git add .
   git commit -m "feat: initial <provider> plugin for formae"
   git push -u origin main
   ```

## Common Gotchas

1. **PklProject paths**: Old monorepo imports like `import("../../pkl/schema/PklProject")` must become package URIs.

2. **Version mismatches**: Debug builds default to v0.0.0. Use `make install-dev` to install plugins at v0.0.0 when working with debug agent.

3. **Stale .so plugins**: If formae-internal has stale `.so` files in `plugins/*/`, they'll cause "built with different version" errors. Run `make clean` or delete them.

4. **formae dependency version**: Must match between schema/pkl/PklProject, examples/PklProject, and testdata/PklProject. Currently `0.77.16-internal`.

5. **Plugin SDK version**: Check AWS go.mod for latest version (was v0.1.3 at time of migration).

6. **gen-pkl target**: Must resolve all three PklProjects: schema/pkl, examples, testdata.

7. **Conformance test version**: Pass `VERSION=0.77.16-internal` explicitly - default "latest" won't work for internal builds.

## Testing the Migration

1. **Build**:
   ```bash
   make build
   ```

2. **Install for dev**:
   ```bash
   make install-dev
   ```

3. **Resolve PKL dependencies**:
   ```bash
   make gen-pkl
   ```

4. **Test with formae** (from formae-internal):
   ```bash
   ./formae apply --mode reconcile ../formae-plugin-<provider>/examples/<example>/main.pkl
   ```

## Files Still Missing (compared to AWS)

These were identified but not created during Azure migration:
- `.github/dependabot.yml`
- `.github/workflows/ci.yml`
- `LICENSE`
- `README.md`

Consider adding these for completeness.

## Repo Description

> <Provider> resource plugin for Formae infrastructure-as-code platform

---

## Session Notes

### What We Did (Azure Migration)

1. Created `scripts/ci/setup-credentials.sh` - verifies Azure credentials via `~/.azure/azureProfile.json` and `az account show`

2. Updated `Makefile`:
   - Added `setup-credentials` target
   - Added `gen-pkl` target (resolves schema/pkl, examples, testdata)
   - Added `install-dev` target (installs as v0.0.0 for debug builds)
   - Wired `setup-credentials` as dependency for conformance tests
   - Updated example names in comments (s3-bucket → resourcegroup)

3. Updated `go.mod`:
   - Removed `replace` directive pointing to `../formae-internal`
   - Removed `toolchain go1.25.1` directive
   - Updated `pkg/plugin` from v0.1.2 to v0.1.3

4. Updated `schema/pkl/PklProject`:
   - Changed dependency from local import to package URI
   - Added VERSION file pattern

5. Updated `examples/PklProject`:
   - Changed formae dependency from `@0.80.0` (non-existent) to `@0.77.16-internal`

6. Updated `testdata/PklProject`:
   - Fixed stale monorepo import path to use package URI

7. Updated `formae-internal/Makefile`:
   - Added azure to `EXTERNAL_PLUGIN_REPOS`
   - Removed azure from `build`, `build-debug`, `tidy-all`, `gen-pkl`, `pkg-pkl`, `publish-pkl`, `pkg-bin`
   - Removed `install-azure-plugin` and `install-azure-plugin-dev` targets

8. Created GitHub repo and pushed initial commit

### TODO

- [ ] Add `.github/dependabot.yml`
- [ ] Add `.github/workflows/ci.yml`
- [ ] Add `LICENSE`
- [ ] Add `README.md`
