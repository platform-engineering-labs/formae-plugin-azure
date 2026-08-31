# Azure Plugin for Formae

[![CI](https://github.com/platform-engineering-labs/formae-plugin-azure/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/platform-engineering-labs/formae-plugin-azure/actions/workflows/ci.yml)
[![Nightly](https://github.com/platform-engineering-labs/formae-plugin-azure/actions/workflows/nightly.yml/badge.svg?branch=main)](https://github.com/platform-engineering-labs/formae-plugin-azure/actions/workflows/nightly.yml)

Formae plugin for managing Azure resources.

## Supported Resources

| Resource Type | Description |
|---------------|-------------|
| `AZURE::App::ContainerApp` | Container Apps |
| `AZURE::App::ManagedEnvironment` | Container Apps managed environments |
| `AZURE::AppConfiguration::ConfigurationStore` | An Azure App Configuration store |
| `AZURE::Authorization::PolicyAssignment` | Policy assignments (applies a definition or initiative over a scope) |
| `AZURE::Authorization::PolicyDefinition` | Custom Azure Policy definitions (rule plus effect) |
| `AZURE::Authorization::PolicySetDefinition` | Policy initiatives (several definitions assigned as one unit) |
| `AZURE::Authorization::RoleAssignment` | Role assignments |
| `AZURE::Authorization::RoleDefinition` | Custom RBAC roles (granted operations and assignable scopes) |
| `AZURE::Batch::Account` | An Azure Batch account |
| `AZURE::Cache::Redis` | An Azure Cache for Redis instance |
| `AZURE::Cdn::AFDCustomDomain` | Front Door custom domains |
| `AZURE::Cdn::AFDEndpoint` | Front Door endpoints |
| `AZURE::Cdn::AFDOrigin` | Front Door origins |
| `AZURE::Cdn::AFDOriginGroup` | Front Door origin groups |
| `AZURE::Cdn::Profile` | Front Door Standard/Premium profiles |
| `AZURE::Cdn::Route` | Front Door routes |
| `AZURE::Cdn::Secret` | Front Door secrets (BYO Key Vault TLS certificate) |
| `AZURE::CognitiveServices::Account` | Azure AI Services accounts (OpenAI, Speech, Vision, multi-service) |
| `AZURE::Compute::AvailabilitySet` | Availability sets (fault/update domain placement for VMs) |
| `AZURE::Compute::Disk` | Managed disks |
| `AZURE::Compute::DiskAccess` | Disk access resources (private-link target for disk/snapshot export) |
| `AZURE::Compute::Gallery` | Compute Galleries (container for versioned image and app definitions) |
| `AZURE::Compute::GalleryApplication` | Gallery application definitions (VM Applications) |
| `AZURE::Compute::GalleryImage` | Gallery image definitions (publisher/offer/sku metadata shell) |
| `AZURE::Compute::Image` | Managed images (pre-Compute-Gallery generalized OS disk capture) |
| `AZURE::Compute::ProximityPlacementGroup` | Proximity placement groups (co-locate VMs for low latency) |
| `AZURE::Compute::Snapshot` | Managed disk snapshots (point-in-time, read-only) |
| `AZURE::Compute::SshPublicKey` | Stored SSH public keys for Linux VM provisioning |
| `AZURE::Compute::VirtualMachine` | Virtual machines |
| `AZURE::Compute::VirtualMachineExtension` | VM extensions (post-provision agents and scripts) |
| `AZURE::Compute::VirtualMachineScaleSet` | Virtual machine scale sets |
| `AZURE::ContainerInstance::ContainerGroup` | An Azure Container Instances container group |
| `AZURE::ContainerRegistry::Registry` | Container registries |
| `AZURE::ContainerRegistry::ScopeMap` | Scope maps (named repository permission sets for tokens) |
| `AZURE::ContainerRegistry::Token` | Registry tokens (identity bound to a scope map; no password in state) |
| `AZURE::ContainerRegistry::Webhook` | Registry webhooks (POST on image push, delete or quarantine) |
| `AZURE::ContainerService::MaintenanceConfiguration` | AKS maintenance windows |
| `AZURE::ContainerService::ManagedCluster` | AKS clusters |
| `AZURE::ContainerService::TrustedAccessRoleBinding` | AKS trusted access for Azure services |
| `AZURE::DBforMySQL::FlexibleServer` | An Azure Database for MySQL flexible server |
| `AZURE::DBforPostgreSQL::Configuration` | PostgreSQL server parameters |
| `AZURE::DBforPostgreSQL::Database` | PostgreSQL databases |
| `AZURE::DBforPostgreSQL::FirewallRule` | PostgreSQL firewall rules |
| `AZURE::DBforPostgreSQL::FlexibleServer` | PostgreSQL flexible servers |
| `AZURE::Dashboard::Grafana` | Azure Managed Grafana workspaces |
| `AZURE::Dashboard::GrafanaManagedPrivateEndpoint` | Managed private endpoints from a Grafana workspace to a data source |
| `AZURE::DataProtection::BackupVault` | Backup vaults (Azure Backup data-protection stack) |
| `AZURE::Devices::IotHub` | An Azure IoT Hub |
| `AZURE::DocumentDB::CassandraKeyspace` | Cosmos DB Cassandra keyspaces |
| `AZURE::DocumentDB::CassandraTable` | Cosmos DB Cassandra tables (column schema, partition and cluster keys) |
| `AZURE::DocumentDB::DatabaseAccount` | An Azure Cosmos DB database account |
| `AZURE::DocumentDB::GremlinDatabase` | Cosmos DB Gremlin databases |
| `AZURE::DocumentDB::GremlinGraph` | Cosmos DB Gremlin graphs (partition key, indexing policy) |
| `AZURE::DocumentDB::MongoCollection` | Cosmos DB MongoDB collections (shard key, indexes) |
| `AZURE::DocumentDB::MongoDatabase` | Cosmos DB MongoDB databases |
| `AZURE::DocumentDB::SqlContainer` | Cosmos DB SQL containers (partition key, indexing and TTL policies) |
| `AZURE::DocumentDB::SqlDatabase` | Cosmos DB SQL (core API) databases |
| `AZURE::DocumentDB::SqlRoleAssignment` | Cosmos DB SQL data-plane role assignments |
| `AZURE::DocumentDB::SqlRoleDefinition` | Cosmos DB SQL data-plane role definitions |
| `AZURE::DocumentDB::Table` | Cosmos DB Table API tables |
| `AZURE::EventGrid::Domain` | Event Grid domains (one ingress endpoint fanning out to many topics) |
| `AZURE::EventGrid::DomainTopic` | Topics inside an Event Grid domain (typically one per tenant) |
| `AZURE::EventGrid::EventSubscription` | Event subscriptions (delivery from any scope to a handler) |
| `AZURE::EventGrid::SystemTopic` | System topics (events emitted by an Azure resource itself) |
| `AZURE::EventGrid::Topic` | Event Grid custom topics (application-published events) |
| `AZURE::EventHub::ConsumerGroup` | A consumer group is an independent read cursor over an event hub |
| `AZURE::EventHub::EventHub` | Event hubs (the Kafka-topic equivalent inside a namespace) |
| `AZURE::EventHub::Namespace` | Event Hubs namespaces |
| `AZURE::EventHub::SchemaGroup` | Schema registry groups (Avro schemas with a compatibility rule) |
| `AZURE::Insights::ActionGroup` | An Azure Monitor action group — the "who to tell" half of alerting |
| `AZURE::Insights::ActivityLogAlert` | Activity log alerts (fire on control-plane events) |
| `AZURE::Insights::Component` | An Application Insights component (workspace-based) |
| `AZURE::Insights::DataCollectionEndpoint` | Data collection endpoints (ingestion front door for Azure Monitor Agent) |
| `AZURE::Insights::DataCollectionRule` | Data collection rules (what the agent collects and where it lands) |
| `AZURE::Insights::DiagnosticSetting` | Diagnostic settings (route a resource's logs and metrics to a sink) |
| `AZURE::Insights::MetricAlert` | Metric alerts (fire when metrics cross a threshold) |
| `AZURE::Insights::PrivateLinkScope` | Azure Monitor Private Link Scopes |
| `AZURE::Insights::PrivateLinkScopedResource` | Puts a workspace or component inside a private link scope |
| `AZURE::Insights::ScheduledQueryRule` | Scheduled query rules (KQL log alerts) |
| `AZURE::KeyVault::Certificate` | Key Vault certificates (BYO import or self-signed policy) |
| `AZURE::KeyVault::Secret` | Key Vault secrets (data-plane; value never read into state) |
| `AZURE::KeyVault::Vault` | Key vaults |
| `AZURE::KubernetesConfiguration::Extension` | Kubernetes extensions (Flux, Dapr, etc.) |
| `AZURE::KubernetesConfiguration::FluxConfiguration` | GitOps Flux v2 configurations |
| `AZURE::ManagedIdentity::FederatedIdentityCredential` | Federated identity credentials (workload identity / OIDC) |
| `AZURE::ManagedIdentity::UserAssignedIdentity` | Managed identities |
| `AZURE::NetApp::Account` | Azure NetApp Files accounts (top of the ANF hierarchy) |
| `AZURE::Network::ApplicationGateway` | Application Gateway v2 (L7 load balancer / HTTPS ingress) |
| `AZURE::Network::ApplicationGatewayWebApplicationFirewallPolicy` | WAF policy for Application Gateway |
| `AZURE::Network::ApplicationSecurityGroup` | Application security groups (named handle for NSG rules) |
| `AZURE::Network::BastionHost` | Azure Bastion hosts (needs a subnet named `AzureBastionSubnet`) |
| `AZURE::Network::DnsForwardingRule` | Forwarding rules (resolve a domain through named DNS servers) |
| `AZURE::Network::DnsForwardingRuleset` | DNS forwarding rulesets |
| `AZURE::Network::DnsForwardingRulesetVirtualNetworkLink` | Links a forwarding ruleset to a virtual network |
| `AZURE::Network::DnsRecordSet` | Public DNS record sets (A / CNAME / TXT) |
| `AZURE::Network::DnsResolver` | Azure DNS Private Resolver instances |
| `AZURE::Network::DnsResolverDomainList` | Domain lists referenced by DNS security rules |
| `AZURE::Network::DnsResolverInboundEndpoint` | Inbound endpoints (IP that on-premises resolvers forward to) |
| `AZURE::Network::DnsResolverOutboundEndpoint` | Outbound endpoints (subnet queries leave the vnet through) |
| `AZURE::Network::DnsResolverPolicy` | DNS resolver policies (container for DNS security rules) |
| `AZURE::Network::DnsResolverPolicyVirtualNetworkLink` | Links a resolver policy to a virtual network |
| `AZURE::Network::DnsSecurityRule` | DNS security rules (allow/block queries by domain list) |
| `AZURE::Network::DnsZone` | Public DNS zones |
| `AZURE::Network::FirewallPolicy` | Azure Firewall policies |
| `AZURE::Network::FirewallPolicyRuleCollectionGroup` | Rule collection groups (where firewall rules live) |
| `AZURE::Network::FlowLog` | Network Watcher flow logging |
| `AZURE::Network::IpGroup` | IP groups (reusable address lists for firewall rules) |
| `AZURE::Network::LoadBalancer` | Load balancers |
| `AZURE::Network::LocalNetworkGateway` | Local network gateways (on-premises end of a site-to-site VPN) |
| `AZURE::Network::NatGateway` | Outbound SNAT for a subnet |
| `AZURE::Network::NetworkInterface` | Network interfaces |
| `AZURE::Network::NetworkSecurityGroup` | Network security groups |
| `AZURE::Network::NetworkWatcher` | Network Watcher service instances (per region) |
| `AZURE::Network::PrivateDnsRecordSet` | A record set inside a private DNS zone |
| `AZURE::Network::PrivateDnsZone` | Private DNS zones |
| `AZURE::Network::PrivateDnsZoneGroup` | Private DNS zone group bindings |
| `AZURE::Network::PrivateDnsZoneVirtualNetworkLink` | Private DNS zone-to-VNet links |
| `AZURE::Network::PrivateEndpoint` | Private endpoints |
| `AZURE::Network::PublicIPAddress` | Public IP addresses |
| `AZURE::Network::PublicIPPrefix` | Public IP prefixes (contiguous ranges to allocate addresses from) |
| `AZURE::Network::RouteTable` | Route tables with inline user-defined routes |
| `AZURE::Network::Subnet` | Subnets |
| `AZURE::Network::TrafficManagerProfile` | Traffic Manager profiles (DNS-based global load balancing) |
| `AZURE::Network::VirtualHub` | Virtual WAN hubs |
| `AZURE::Network::VirtualNetwork` | Virtual networks |
| `AZURE::Network::VirtualNetworkGateway` | VPN and ExpressRoute virtual network gateways (needs a subnet named `GatewaySubnet`) |
| `AZURE::Network::VirtualNetworkGatewayConnection` | Site-to-site, VNet-to-VNet and ExpressRoute connections |
| `AZURE::Network::VirtualNetworkPeering` | Virtual network peerings |
| `AZURE::Network::VirtualWan` | Virtual WANs |
| `AZURE::Network::VpnGateway` | Virtual WAN scoped VPN gateways |
| `AZURE::Network::VpnSite` | Virtual WAN VPN sites (on-premises branch definitions) |
| `AZURE::NotificationHubs::Namespace` | Notification Hubs namespaces |
| `AZURE::NotificationHubs::NotificationHub` | Notification hubs (PNS credentials never read into state) |
| `AZURE::NotificationHubs::NotificationHubAuthorizationRule` | Notification hub SAS rules |
| `AZURE::OperationalInsights::DataExport` | Continuous export rules (workspace tables to storage or event hub) |
| `AZURE::OperationalInsights::LinkedStorageAccount` | Links workspace data classes to customer-owned storage accounts |
| `AZURE::OperationalInsights::SavedSearch` | Saved searches and workspace functions (stored KQL) |
| `AZURE::OperationalInsights::Workspace` | Log Analytics workspaces |
| `AZURE::Relay::HybridConnection` | Relay hybrid connections |
| `AZURE::Relay::HybridConnectionAuthorizationRule` | Hybrid connection SAS rules (keys never read into state) |
| `AZURE::Relay::Namespace` | Relay namespaces |
| `AZURE::Relay::NamespaceAuthorizationRule` | Namespace SAS rules (keys never read into state) |
| `AZURE::Resources::ResourceGroup` | Resource groups |
| `AZURE::Search::Service` | An Azure AI Search service |
| `AZURE::ServiceBus::AuthorizationRule` | Service Bus namespace SAS rules |
| `AZURE::ServiceBus::Namespace` | Service Bus namespaces |
| `AZURE::ServiceBus::Queue` | A Service Bus queue |
| `AZURE::ServiceBus::Rule` | Subscription filter rules (SQL or correlation filters) |
| `AZURE::ServiceBus::Subscription` | Topic subscriptions (independent filtered copy of the topic stream) |
| `AZURE::ServiceBus::Topic` | A Service Bus topic — the publish side of publish/subscribe |
| `AZURE::SignalRService::SignalR` | An Azure SignalR Service instance |
| `AZURE::SignalRService::WebPubSub` | An Azure Web PubSub service instance |
| `AZURE::Sql::Database` | Azure SQL databases |
| `AZURE::Sql::ElasticPool` | SQL elastic pools |
| `AZURE::Sql::FirewallRule` | SQL server firewall rules (IP allow ranges) |
| `AZURE::Sql::OutboundFirewallRule` | Outbound firewall rules (permitted destination FQDNs) |
| `AZURE::Sql::Server` | Azure SQL logical servers |
| `AZURE::Sql::ServerAzureADAdministrator` | Microsoft Entra administrator on a SQL server |
| `AZURE::Sql::ServerDnsAlias` | SQL server DNS aliases (stable hostname, repointable) |
| `AZURE::Sql::VirtualNetworkRule` | SQL vnet rules (subnet allowed to reach the server) |
| `AZURE::Storage::BlobContainer` | Blob containers |
| `AZURE::Storage::FileShare` | A file share in a storage account's File service |
| `AZURE::Storage::ManagementPolicy` | Blob lifecycle-management policies (tiering / expiry rules) |
| `AZURE::Storage::Queue` | A queue in a storage account's Queue service |
| `AZURE::Storage::StorageAccount` | Storage accounts |
| `AZURE::Storage::Table` | A table in a storage account's Table service |
| `AZURE::Web::Certificate` | App Service certificates |
| `AZURE::Web::CustomHostnameBinding` | Custom hostname bindings on a web app |
| `AZURE::Web::FunctionApp` | Function apps |
| `AZURE::Web::ServicePlan` | App Service plans (the compute a web or function app runs on) |
| `AZURE::Web::StaticSite` | Azure Static Web Apps |
| `AZURE::Web::WebApp` | Web apps (Linux and Windows, via `siteConfig`) |
| `AZURE::Web::WebAppSlot` | Deployment slots on a web app |

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
