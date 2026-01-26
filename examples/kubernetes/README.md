# Kubernetes

AKS cluster with Azure Container Registry.

## What You Get

- Resource Group
- Virtual Network + Subnet
- Container Registry (Basic SKU)
- AKS Cluster with system-assigned identity

## Prerequisites

1. Azure CLI authenticated: `az login`
2. Valid Azure subscription

## Configuration

Edit `vars.pkl`:
```pkl
subscriptionId = "your-subscription-id"
location = "eastus"
vnetCidr = "10.0.0.0/16"
aksSubnetCidr = "10.0.0.0/22"
dnsPrefix = "aks"
```

## Deploy

```bash
formae apply main.pkl
formae status command --watch --output-layout detailed
```

## Accessing Your Cluster

Get credentials:
```bash
az aks get-credentials --resource-group azure-kubernetes-rg --name azure-kubernetes-aks
```

Verify connection:
```bash
kubectl get nodes
```

Attach ACR to AKS (enables pull access):
```bash
az aks update -n azure-kubernetes-aks -g azure-kubernetes-rg --attach-acr azurekubernetesacr
```

## Tear Down

```bash
formae destroy --query 'stack:azure-kubernetes-eastus' --yes
```

## Architecture

```
Resource Group (azure-kubernetes-rg)
├── Virtual Network (azure-kubernetes-vnet)
│   └── Subnet (azure-kubernetes-aks-subnet)
├── Container Registry (azurekubernetesacr)
└── AKS Cluster (azure-kubernetes-aks)
    └── System Node Pool (1x Standard_D2s_v3)
```

## Cluster Configuration

- SKU: Base (Free tier)
- Identity: System-assigned managed identity
- Network: Azure CNI
- Node Pool: 1 system node (Standard_D2s_v3)
- RBAC: Enabled

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `kubectl get nodes` fails | Ensure credentials are configured: `az aks get-credentials ...` |
| Deployment hangs | Check Azure portal for provisioning status |
| Slow creation | AKS cluster creation typically takes 5-10 minutes |
