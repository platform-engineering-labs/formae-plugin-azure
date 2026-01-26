# Subscription Bootstrap

Set up foundational RBAC for a new Azure subscription. The "day zero" stuff before you deploy anything real.

## What You Get

- Resource Group for managed identities
- Deploy Identity (Contributor) - for CI/CD pipelines
- Monitor Identity (Reader) - for observability tools
- Subscription-scoped role assignments

## Prerequisites

1. Azure CLI authenticated: `az login`
2. Sufficient permissions to create role assignments (Owner or User Access Administrator)

## Configuration

Edit `vars.pkl`:

```pkl
projectName = "acme-corp"
subscriptionId = "your-subscription-id-here"
```

## Deploy

```bash
formae apply main.pkl
formae status command --watch --output-layout detailed
```

## After Deployment

Use the managed identities with:

GitHub Actions (OIDC):
```yaml
- uses: azure/login@v1
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

Terraform:
```hcl
provider "azurerm" {
  use_msi = true
}
```

## Tear Down

```bash
formae destroy --query 'stack:subscription-bootstrap' --yes
```

## Architecture

```
Subscription
├── Identity Resource Group
│   ├── Deploy Identity (User Assigned)
│   └── Monitor Identity (User Assigned)
└── Role Assignments
    ├── deploy-identity → Contributor
    └── monitor-identity → Reader
```

## What This Doesn't Cover (Yet)

- Entra ID App Registrations
- Federated Identity Credentials (OIDC)
- Azure Lighthouse (cross-tenant)
- Management Groups
