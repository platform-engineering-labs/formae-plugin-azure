# Azure Plugin for Formae

[![CI](https://github.com/platform-engineering-labs/formae-plugin-azure/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/platform-engineering-labs/formae-plugin-azure/actions/workflows/ci.yml)
[![Nightly](https://github.com/platform-engineering-labs/formae-plugin-azure/actions/workflows/nightly.yml/badge.svg?branch=main)](https://github.com/platform-engineering-labs/formae-plugin-azure/actions/workflows/nightly.yml)

Formae plugin for managing Azure resources.

## Supported Resources

| Resource Type | Description |
|---------------|-------------|
| `AZURE::Resources::ResourceGroup` | Resource groups |
| `AZURE::Network::VirtualNetwork` | Virtual networks |
| `AZURE::Network::Subnet` | Subnets |
| `AZURE::Network::NetworkInterface` | Network interfaces |
| `AZURE::Network::NetworkSecurityGroup` | Network security groups |
| `AZURE::Network::PublicIPAddress` | Public IP addresses |
| `AZURE::Compute::VirtualMachine` | Virtual machines |
| `AZURE::Storage::StorageAccount` | Storage accounts |
| `AZURE::KeyVault::Vault` | Key vaults |
| `AZURE::ContainerService::ManagedCluster` | AKS clusters |
| `AZURE::ContainerService::MaintenanceConfiguration` | AKS maintenance windows |
| `AZURE::ContainerService::TrustedAccessRoleBinding` | AKS trusted access for Azure services |
| `AZURE::KubernetesConfiguration::Extension` | Kubernetes extensions (Flux, Dapr, etc.) |
| `AZURE::KubernetesConfiguration::FluxConfiguration` | GitOps Flux v2 configurations |
| `AZURE::ContainerRegistry::Registry` | Container registries |
| `AZURE::DBforPostgreSQL::FlexibleServer` | PostgreSQL flexible servers |
| `AZURE::DBforPostgreSQL::FirewallRule` | PostgreSQL firewall rules |
| `AZURE::DBforPostgreSQL::Database` | PostgreSQL databases |
| `AZURE::DBforPostgreSQL::Configuration` | PostgreSQL server parameters |
| `AZURE::ManagedIdentity::UserAssignedIdentity` | Managed identities |
| `AZURE::ManagedIdentity::FederatedIdentityCredential` | Federated identity credentials (workload identity / OIDC) |
| `AZURE::Authorization::RoleAssignment` | Role assignments |
| `AZURE::Network::LoadBalancer` | Load balancers |
| `AZURE::Network::PrivateDnsZone` | Private DNS zones |
| `AZURE::Network::PrivateDnsZoneVirtualNetworkLink` | Private DNS zone-to-VNet links |
| `AZURE::Network::PrivateEndpoint` | Private endpoints |
| `AZURE::Network::PrivateDnsZoneGroup` | Private DNS zone group bindings |
| `AZURE::Storage::BlobContainer` | Blob containers |
| `AZURE::Compute::Disk` | Managed disks |
| `AZURE::Compute::VirtualMachineScaleSet` | Virtual machine scale sets |
| `AZURE::Network::ApplicationGateway` | Application Gateway v2 (L7 load balancer / HTTPS ingress) |
| `AZURE::Network::ApplicationGatewayWebApplicationFirewallPolicy` | WAF policy for Application Gateway |
| `AZURE::KeyVault::Certificate` | Key Vault certificates (BYO import or self-signed policy) |
| `AZURE::Network::DnsZone` | Public DNS zones |
| `AZURE::Network::DnsRecordSet` | Public DNS record sets (A / CNAME / TXT) |
| `AZURE::Cdn::Profile` | Front Door Standard/Premium profiles |
| `AZURE::Cdn::AFDEndpoint` | Front Door endpoints |
| `AZURE::Cdn::AFDOriginGroup` | Front Door origin groups |
| `AZURE::Cdn::AFDOrigin` | Front Door origins |
| `AZURE::Cdn::Route` | Front Door routes |
| `AZURE::Cdn::AFDCustomDomain` | Front Door custom domains |
| `AZURE::Cdn::Secret` | Front Door secrets (BYO Key Vault TLS certificate) |
| `AZURE::App::ManagedEnvironment` | Container Apps managed environments |
| `AZURE::App::ContainerApp` | Container Apps |

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

## License

FSL-1.1-ALv2
