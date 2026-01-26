# Virtual Machine

SSH-accessible Ubuntu VM with all the networking plumbing handled for you.

## What You Get

- Resource Group
- Virtual Network + Subnet
- Network Security Group (SSH allowed)
- Public IP Address
- Network Interface
- Ubuntu 22.04 LTS VM

## Prerequisites

1. Azure CLI authenticated: `az login`
2. SSH public key

## Configuration

Set your SSH key:
```bash
export SSH_PUBLIC_KEY=$(cat ~/.ssh/id_rsa.pub)
```

Edit `vars.pkl` to customize:
```pkl
subscriptionId = "your-subscription-id"
adminUsername = "azureuser"
vmSize = "Standard_D2s_v3"
```

## Deploy

```bash
formae apply main.pkl
formae status command --watch --output-layout detailed
```

## Connect

```bash
ssh azureuser@<PUBLIC_IP>
```

## Tear Down

```bash
formae destroy --query 'stack:azure-vm-eastus' --yes
```

## Architecture

```
Resource Group
├── Virtual Network (10.0.0.0/16)
│   └── Subnet (10.0.1.0/24)
├── Network Security Group
│   └── Rule: Allow SSH (port 22)
├── Public IP Address
├── Network Interface
└── Virtual Machine (Ubuntu 22.04)
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| SSH timeout | Check NSG allows your IP, verify public IP is attached |
| Permission denied | Verify SSH key matches what's in `vars.pkl` |
| VM won't start | Check quota limits in your subscription |

## Known Issues

Destroy may require multiple runs to remove all resources. Run `formae destroy` again until all resources are removed.
