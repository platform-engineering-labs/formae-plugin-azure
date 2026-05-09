# Contributing

This document covers local development for plugin authors. For user-facing
plugin docs (configuration, supported resources, examples), see
[README.md](README.md).

## Local Installation

```bash
make install
```

## Building & Testing

```bash
make build          # Build plugin
make test           # Run tests
make install        # Install locally
make install-dev    # Install as v0.0.0 (for debug builds)
make gen-pkl        # Resolve PKL dependencies
```

## Conformance Tests

Run against real Azure resources:

```bash
make setup-credentials   # Verify Azure login
make conformance-test    # Run full suite
```
