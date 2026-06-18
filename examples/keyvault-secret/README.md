# Key Vault Secret

Demonstrates issue #67: declaring an `Azure::KeyVault::Secret` in the same stack
as the vault that holds it, instead of dropping out to `az keyvault secret set`.

## What it builds

- A resource group
- A Key Vault (`Azure::KeyVault::Vault`) in RBAC-authorization mode
- A secret in that vault (`Azure::KeyVault::Secret`) holding a database admin
  password

Dependency chain: `ResourceGroup -> Vault -> Secret`. Downstream resources and
applications then read the password from the vault at runtime; declaring the
secret here makes that credential a managed, declarative part of the stack.

## Prerequisites

```sh
export AZURE_SUBSCRIPTION_ID=...
export AZURE_TENANT_ID=...
export PG_ADMIN_PASSWORD='a-strong-password'
```

Key Vault names are globally unique and 3 to 24 characters; edit `projectName` in
`vars.pkl` (or the vault `name`) if `azure-kv-secret-kv` is taken.

### Data-plane permission

Writing a secret is a data-plane operation. Creating the vault does NOT grant the
formae principal rights to write its secrets, so the apply 403s on the secret
unless the principal has data-plane access. This example puts the vault in RBAC
mode (`enableRbacAuthorization = true`), so grant the formae principal the
`Key Vault Secrets Officer` role (vault, resource-group, or subscription scope):

```sh
az role assignment create \
  --assignee-object-id <your-principal-object-id> \
  --role "Key Vault Secrets Officer" \
  --scope /subscriptions/<subscription-id>
```

RBAC assignments are eventually consistent, so allow a short propagation delay
before the first apply. See `../../future-work.md` section 1 for the full
permission model (RBAC vs access policies).

## A note on the secret value

The `value` is write-only: formae sets it on create but never reads it back into
state or diff (mirroring `administratorLoginPassword` on FlexibleServer). A
downstream resource that needs the same password (for example a Postgres Flexible
Server's `administratorLoginPassword`) is configured from the same source, not
read back out of the vault.

## Apply

```sh
formae apply --mode reconcile main.pkl
```
