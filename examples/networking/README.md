# Networking

Basic Azure networking foundation.

## What You Get

- Resource Group
- Virtual Network (10.0.0.0/16)
- Subnet (10.0.1.0/24)

## Prerequisites

1. Azure CLI authenticated: `az login`
2. Valid Azure subscription

## Configuration

Edit `vars.pkl`:

```pkl
subscriptionId = "your-subscription-id"
location = "eastus"
vnetCidr = "10.0.0.0/16"
subnetCidr = "10.0.1.0/24"
```

## Deploy

```bash
formae apply --mode reconcile main.pkl
```

## Tear Down

```bash
formae destroy --query 'stack:azure-networking-eastus'
```

## Architecture

```
Resource Group (azure-networking-rg)
└── Virtual Network (azure-networking-vnet)
    └── Subnet (azure-networking-subnet)
```
