# Azure Plugin for Formae

Formae plugin for managing Azure resources.

## Supported Resources

| Resource Type | Description |
|---------------|-------------|
| `Azure::Resources::ResourceGroup` | Resource groups |
| `Azure::Network::VirtualNetwork` | Virtual networks |
| `Azure::Network::Subnet` | Subnets |
| `Azure::Network::NetworkInterface` | Network interfaces |
| `Azure::Network::NetworkSecurityGroup` | Network security groups |
| `Azure::Network::PublicIPAddress` | Public IP addresses |
| `Azure::Compute::VirtualMachine` | Virtual machines |
| `Azure::Storage::StorageAccount` | Storage accounts |
| `Azure::KeyVault::Vault` | Key vaults |
| `Azure::ContainerService::ManagedCluster` | AKS clusters |
| `Azure::ContainerRegistry::Registry` | Container registries |
| `Azure::DBforPostgreSQL::FlexibleServer` | PostgreSQL flexible servers |
| `Azure::DBforPostgreSQL::FirewallRule` | PostgreSQL firewall rules |
| `Azure::ManagedIdentity::UserAssignedIdentity` | Managed identities |
| `Azure::Authorization::RoleAssignment` | Role assignments |

## Installation

```bash
make install
```

## Configuration

Configure an Azure target in your Forma file:

```pkl
new formae.Target {
    label = "my-azure-target"
    namespace = "AZURE"
    config = new Mapping {
        ["SubscriptionId"] = "your-subscription-id"
    }
}
```

Authentication uses `DefaultAzureCredential` which tries (in order):
- Environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`)
- Managed Identity
- Azure CLI (`az login`)

## Examples

See [examples/](examples/) for usage patterns:

- `networking/` - VNet and subnet setup
- `kubernetes/` - AKS cluster with ACR
- `database/` - PostgreSQL flexible server
- `virtual-machine/` - VM with networking
- `subscription-bootstrap/` - Resource group, key vault, storage account

## Development

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
make setup-credentials                           # Verify Azure login
make conformance-test VERSION=0.77.16-internal   # Run full suite
```

## License

FSL-1.1-ALv2
