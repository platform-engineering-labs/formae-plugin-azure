# Azure Plugin for Formae

[![CI](https://github.com/platform-engineering-labs/formae-plugin-azure/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/platform-engineering-labs/formae-plugin-azure/actions/workflows/ci.yml)
[![Nightly](https://github.com/platform-engineering-labs/formae-plugin-azure/actions/workflows/nightly.yml/badge.svg?branch=main)](https://github.com/platform-engineering-labs/formae-plugin-azure/actions/workflows/nightly.yml)

Formae plugin for managing Azure resources.

## Supported Resources

| Resource Type | Description |
|---------------|-------------|
| `AZURE::AlertsManagement::AlertProcessingRuleActionGroup` | An alert processing rule that ADDS action groups to every alert matching its scopes |
| `AZURE::AlertsManagement::AlertProcessingRuleSuppression` | An alert processing rule that SUPPRESSES notifications |
| `AZURE::AlertsManagement::PrometheusRuleGroup` | A managed Prometheus rule group |
| `AZURE::ApiManagement::Api` | An API in an API Management instance |
| `AZURE::ApiManagement::ApiDiagnostic` | The per-API diagnostic |
| `AZURE::ApiManagement::ApiOperation` | A single operation on an API — one method and one URL template under the API's path |
| `AZURE::ApiManagement::ApiOperationPolicy` | The policy attached to one operation |
| `AZURE::ApiManagement::ApiPolicy` | The policy attached to one API |
| `AZURE::ApiManagement::ApiRelease` | A release of an API revision |
| `AZURE::ApiManagement::ApiSchema` | A schema attached to one API |
| `AZURE::ApiManagement::ApiTagDescription` | The description shown for one tag in the context of one API |
| `AZURE::ApiManagement::ApiVersionSet` | A version set — the grouping several versions of the same API belong to |
| `AZURE::ApiManagement::AuthorizationServer` | An OAuth 2.0 authorization server registration |
| `AZURE::ApiManagement::Backend` | A backend — a named destination an API or a policy can forward to |
| `AZURE::ApiManagement::Certificate` | A client certificate held by the service, for mutual TLS to a backend |
| `AZURE::ApiManagement::Diagnostic` | The service-wide diagnostic |
| `AZURE::ApiManagement::Gateway` | A self-hosted gateway registration |
| `AZURE::ApiManagement::GlobalSchema` | A service-wide schema |
| `AZURE::ApiManagement::Group` | A developer group — the unit product visibility is granted to |
| `AZURE::ApiManagement::GroupUser` | The membership of one user in one group |
| `AZURE::ApiManagement::Logger` | A logger — the event sink a diagnostic writes to |
| `AZURE::ApiManagement::NamedValue` | A named value — the service's own key/value store |
| `AZURE::ApiManagement::OpenIdConnectProvider` | An OpenID Connect provider registration |
| `AZURE::ApiManagement::Policy` | The service-wide policy of an API Management instance |
| `AZURE::ApiManagement::Product` | An API Management product — the unit a consumer subscribes to |
| `AZURE::ApiManagement::ProductApi` | The membership of one API in one product |
| `AZURE::ApiManagement::ProductGroup` | The visibility of one product to one group |
| `AZURE::ApiManagement::ProductPolicy` | The policy attached to one product |
| `AZURE::ApiManagement::Service` | An Azure API Management service |
| `AZURE::ApiManagement::Subscription` | A subscription — the pair of keys a caller sends to reach an API |
| `AZURE::ApiManagement::User` | A developer account in the API Management user store |
| `AZURE::App::ContainerApp` | Container Apps |
| `AZURE::App::ManagedEnvironment` | Container Apps managed environments |
| `AZURE::AppConfiguration::ConfigurationStore` | An Azure App Configuration store |
| `AZURE::Authorization::ManagementLock` | Blocks deletion — or all writes — of everything at and under a scope |
| `AZURE::Authorization::PolicyAssignment` | Policy assignments (applies a definition or initiative over a scope) |
| `AZURE::Authorization::PolicyDefinition` | Custom Azure Policy definitions (rule plus effect) |
| `AZURE::Authorization::PolicyExemption` | Carves a scope out of a policy assignment |
| `AZURE::Authorization::PolicySetDefinition` | Policy initiatives (several definitions assigned as one unit) |
| `AZURE::Authorization::RoleAssignment` | Role assignments |
| `AZURE::Authorization::RoleDefinition` | Custom RBAC roles (granted operations and assignable scopes) |
| `AZURE::Automation::Account` | An Azure Automation account |
| `AZURE::Automation::Credential` | A credential asset in an Azure Automation account |
| `AZURE::Automation::JobSchedule` | The link between a runbook and a schedule |
| `AZURE::Automation::Module` | A PowerShell module imported into an Azure Automation account |
| `AZURE::Automation::Runbook` | A runbook in an Azure Automation account |
| `AZURE::Automation::Schedule` | A schedule in an Azure Automation account |
| `AZURE::Automation::Variable` | A variable asset in an Azure Automation account |
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
| `AZURE::DataFactory::DataFlow` | A `MappingDataFlow` |
| `AZURE::DataFactory::DatasetAzureBlob` | An `AzureBlob` dataset — a blob path described for a copy activity to read or write |
| `AZURE::DataFactory::DatasetAzureSqlTable` | An `AzureSqlTable` dataset |
| `AZURE::DataFactory::DatasetDelimitedText` | A `DelimitedText` dataset — CSV and its relatives, stored in blob storage |
| `AZURE::DataFactory::DatasetJson` | A `Json` dataset — JSON files in blob storage |
| `AZURE::DataFactory::DatasetParquet` | A `Parquet` dataset — Parquet files in blob storage |
| `AZURE::DataFactory::Factory` | An Azure Data Factory (v2) |
| `AZURE::DataFactory::IntegrationRuntimeAzure` | An Azure (service-managed) integration runtime |
| `AZURE::DataFactory::IntegrationRuntimeSelfHosted` | A self-hosted integration runtime |
| `AZURE::DataFactory::LinkedServiceAzureBlobStorage` | An `AzureBlobStorage` linked service — how a factory reaches blob containers |
| `AZURE::DataFactory::LinkedServiceAzureSqlDatabase` | An `AzureSqlDatabase` linked service — how a factory reaches an Azure SQL database |
| `AZURE::DataFactory::LinkedServiceAzureTableStorage` | An `AzureTableStorage` linked service — how a factory reaches table storage |
| `AZURE::DataFactory::LinkedServiceKeyVault` | An `AzureKeyVault` linked service |
| `AZURE::DataFactory::LinkedServiceWeb` | A `Web` linked service |
| `AZURE::DataFactory::Pipeline` | A Data Factory pipeline |
| `AZURE::DataFactory::TriggerBlobEvent` | A `BlobEventsTrigger` |
| `AZURE::DataFactory::TriggerSchedule` | A `ScheduleTrigger` — starts pipelines on a wall-clock recurrence |
| `AZURE::DataProtection::BackupInstanceBlobStorage` | Puts one storage account's blobs under a Backup vault policy |
| `AZURE::DataProtection::BackupInstanceDisk` | Puts one managed disk under a Backup vault policy |
| `AZURE::DataProtection::BackupPolicyBlobStorage` | A Backup vault policy for blob storage |
| `AZURE::DataProtection::BackupPolicyDisk` | A Backup vault policy for managed disks |
| `AZURE::DataProtection::BackupPolicyKubernetesCluster` | A Backup vault policy for AKS managed clusters |
| `AZURE::DataProtection::BackupPolicyPostgreSqlFlexibleServer` | A Backup vault policy for PostgreSQL flexible servers |
| `AZURE::DataProtection::BackupVault` | Backup vaults (Azure Backup data-protection stack) |
| `AZURE::DataProtection::ResourceGuard` | A Resource Guard |
| `AZURE::DesktopVirtualization::Application` | A single published application inside a `RemoteApp` application group |
| `AZURE::DesktopVirtualization::ApplicationGroup` | An Azure Virtual Desktop application group |
| `AZURE::DesktopVirtualization::HostPool` | An Azure Virtual Desktop host pool |
| `AZURE::DesktopVirtualization::ScalingPlan` | An Azure Virtual Desktop scaling plan |
| `AZURE::DesktopVirtualization::Workspace` | An Azure Virtual Desktop workspace |
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
| `AZURE::Insights::AutoscaleSetting` | An Azure Monitor autoscale setting |
| `AZURE::Insights::Component` | An Application Insights component (workspace-based) |
| `AZURE::Insights::DataCollectionEndpoint` | Data collection endpoints (ingestion front door for Azure Monitor Agent) |
| `AZURE::Insights::DataCollectionRule` | Data collection rules (what the agent collects and where it lands) |
| `AZURE::Insights::DataCollectionRuleAssociation` | Attaches a data collection rule |
| `AZURE::Insights::DiagnosticSetting` | Diagnostic settings (route a resource's logs and metrics to a sink) |
| `AZURE::Insights::MetricAlert` | Metric alerts (fire when metrics cross a threshold) |
| `AZURE::Insights::PrivateLinkScope` | Azure Monitor Private Link Scopes |
| `AZURE::Insights::PrivateLinkScopedResource` | Puts a workspace or component inside a private link scope |
| `AZURE::Insights::ScheduledQueryRule` | Scheduled query rules (KQL log alerts) |
| `AZURE::KeyVault::AccessPolicy` | One entry of a Key Vault's access policy list |
| `AZURE::KeyVault::Certificate` | Key Vault certificates (BYO import or self-signed policy) |
| `AZURE::KeyVault::Key` | Keys in a Key Vault |
| `AZURE::KeyVault::ManagedHsm` | A single-tenant, FIPS 140-2 Level 3 HSM pool |
| `AZURE::KeyVault::Secret` | Key Vault secrets (data-plane; value never read into state) |
| `AZURE::KeyVault::Vault` | Key vaults |
| `AZURE::KubernetesConfiguration::Extension` | Kubernetes extensions (Flux, Dapr, etc.) |
| `AZURE::KubernetesConfiguration::FluxConfiguration` | GitOps Flux v2 configurations |
| `AZURE::Logic::IntegrationAccount` | An integration account |
| `AZURE::Logic::IntegrationAccountAgreement` | A trading-partner agreement held in an integration account |
| `AZURE::Logic::IntegrationAccountAssembly` | A .NET assembly held in an integration account |
| `AZURE::Logic::IntegrationAccountCertificate` | A certificate held in an integration account |
| `AZURE::Logic::IntegrationAccountMap` | A transform held in an integration account |
| `AZURE::Logic::IntegrationAccountPartner` | A trading partner held in an integration account |
| `AZURE::Logic::IntegrationAccountSchema` | An XSD held in an integration account |
| `AZURE::Logic::Workflow` | A Logic Apps (Consumption) workflow — one trigger plus the actions it runs |
| `AZURE::ManagedIdentity::FederatedIdentityCredential` | Federated identity credentials (workload identity / OIDC) |
| `AZURE::ManagedIdentity::UserAssignedIdentity` | Managed identities |
| `AZURE::Management::ManagementGroup` | A container for subscriptions and other management groups |
| `AZURE::Management::ManagementGroupSubscriptionAssociation` | Places one subscription under one management group |
| `AZURE::Monitor::MonitorWorkspace` | An Azure Monitor workspace |
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
| `AZURE::Network::NetworkManager` | An Azure Virtual Network Manager instance |
| `AZURE::Network::NetworkManagerAdminRule` | A security admin rule |
| `AZURE::Network::NetworkManagerAdminRuleCollection` | A rule collection inside a security admin configuration |
| `AZURE::Network::NetworkManagerConnectivityConfiguration` | A connectivity configuration |
| `AZURE::Network::NetworkManagerNetworkGroup` | A network group inside a virtual network manager |
| `AZURE::Network::NetworkManagerSecurityAdminConfiguration` | A security admin configuration |
| `AZURE::Network::NetworkManagerStaticMember` | One virtual network pinned into a network group by ARM ID |
| `AZURE::Network::NetworkManagerSubscriptionConnection` | A subscription's side of a cross-tenant network manager connection |
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
| `AZURE::OperationalInsights::Cluster` | A Log Analytics DEDICATED CLUSTER |
| `AZURE::OperationalInsights::DataExport` | Continuous export rules (workspace tables to storage or event hub) |
| `AZURE::OperationalInsights::DataSourceWindowsEvent` | Tells the Log Analytics agents reporting to a workspace to collect one Windows event |
| `AZURE::OperationalInsights::DataSourceWindowsPerformanceCounter` | Tells the Log Analytics agents reporting to a workspace to sample one Windows |
| `AZURE::OperationalInsights::LinkedService` | Binds a Log Analytics workspace to another resource by ARM ID |
| `AZURE::OperationalInsights::LinkedStorageAccount` | Links workspace data classes to customer-owned storage accounts |
| `AZURE::OperationalInsights::SavedSearch` | Saved searches and workspace functions (stored KQL) |
| `AZURE::OperationalInsights::StorageInsightConfig` | Ingests an existing diagnostics storage account into a workspace |
| `AZURE::OperationalInsights::Table` | Per-table data retention on a Log Analytics workspace |
| `AZURE::OperationalInsights::Workspace` | Log Analytics workspaces |
| `AZURE::PolicyInsights::PolicyRemediation` | A remediation task |
| `AZURE::RecoveryServices::BackupPolicyFileShare` | An Azure Files backup policy in a Recovery Services vault |
| `AZURE::RecoveryServices::BackupPolicyVM` | An Azure VM backup policy in a Recovery Services vault |
| `AZURE::RecoveryServices::BackupProtectedFileShare` | An Azure Files share protected by a Recovery Services vault |
| `AZURE::RecoveryServices::Vault` | A Recovery Services vault |
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
| `AZURE::Storage::BlobContainerImmutabilityPolicy` | Time-based retention (WORM) policy on a blob container |
| `AZURE::Storage::BlobContainerLegalHold` | Legal hold on a blob container |
| `AZURE::Storage::BlobInventoryPolicy` | Blob inventory policy of a storage account |
| `AZURE::Storage::FileShare` | A file share in a storage account's File service |
| `AZURE::Storage::LocalUser` | A local user of a storage account |
| `AZURE::Storage::ManagementPolicy` | Blob lifecycle-management policies (tiering / expiry rules) |
| `AZURE::Storage::ObjectReplicationPolicy` | Object replication between two storage accounts |
| `AZURE::Storage::Queue` | A queue in a storage account's Queue service |
| `AZURE::Storage::QueueServiceProperties` | Service-level settings of a storage account's Queue service |
| `AZURE::Storage::StorageAccount` | Storage accounts |
| `AZURE::Storage::Table` | A table in a storage account's Table service |
| `AZURE::StreamAnalytics::FunctionJavaScriptUdf` | A JavaScript user-defined function on a Stream Analytics job |
| `AZURE::StreamAnalytics::InputBlob` | A blob storage stream input on a Stream Analytics job |
| `AZURE::StreamAnalytics::InputEventHub` | An Event Hubs stream input on a Stream Analytics job |
| `AZURE::StreamAnalytics::InputIotHub` | An IoT Hub stream input on a Stream Analytics job |
| `AZURE::StreamAnalytics::OutputBlob` | A blob storage output on a Stream Analytics job |
| `AZURE::StreamAnalytics::OutputEventHub` | An Event Hubs output on a Stream Analytics job |
| `AZURE::StreamAnalytics::OutputServiceBusQueue` | A Service Bus queue output on a Stream Analytics job |
| `AZURE::StreamAnalytics::OutputTable` | An Azure Table storage output on a Stream Analytics job |
| `AZURE::StreamAnalytics::StreamingJob` | An Azure Stream Analytics job |
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
