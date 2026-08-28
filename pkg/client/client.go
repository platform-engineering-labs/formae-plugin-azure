// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appconfiguration/armappconfiguration"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/applicationinsights/armapplicationinsights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/batch/armbatch/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dashboard/armdashboard"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dnsresolver/armdnsresolver"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/iothub/armiothub"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kubernetesconfiguration/armkubernetesconfiguration"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/netapp/armnetapp/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/notificationhubs/armnotificationhubs"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/relay/armrelay"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/search/armsearch"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/signalr/armsignalr"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/trafficmanager/armtrafficmanager"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/webpubsub/armwebpubsub"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
)

const (
	// Module name and version for ARM client (used for telemetry)
	moduleName    = "github.com/platform-engineering-labs/formae/plugins/azure"
	moduleVersion = "v0.1.0"
)

// Client wraps Azure SDK clients for the Azure plugin.
//
// Architecture Decision: We use resource-specific clients (e.g., ResourceGroupsClient)
// for type-safe CRUD operations, following Azure SDK conventions. The armClient field
// provides low-level pipeline access specifically for resuming async pollers from
// serialized resume tokens across process restarts - this is not a competing approach,
// but a necessary implementation detail for async operation handling.
//
// When adding new resource types, add new typed client fields here (e.g., StorageClient,
// NetworkClient) rather than using the generic armClient for operations.
type Client struct {
	Config                                   *config.Config
	ResourceGroupsClient                     *armresources.ResourceGroupsClient
	VirtualNetworksClient                    *armnetwork.VirtualNetworksClient
	VirtualNetworkPeeringsClient             *armnetwork.VirtualNetworkPeeringsClient
	FirewallPoliciesClient                   *armnetwork.FirewallPoliciesClient
	FirewallPolicyRuleCollectionGroupsClient *armnetwork.FirewallPolicyRuleCollectionGroupsClient
	LocalNetworkGatewaysClient               *armnetwork.LocalNetworkGatewaysClient
	SubnetsClient                            *armnetwork.SubnetsClient
	SecurityGroupsClient                     *armnetwork.SecurityGroupsClient
	ApplicationSecurityGroupsClient          *armnetwork.ApplicationSecurityGroupsClient
	IPGroupsClient                           *armnetwork.IPGroupsClient
	PublicIPAddressesClient                  *armnetwork.PublicIPAddressesClient
	PublicIPPrefixesClient                   *armnetwork.PublicIPPrefixesClient
	NatGatewaysClient                        *armnetwork.NatGatewaysClient
	WatchersClient                           *armnetwork.WatchersClient
	FlowLogsClient                           *armnetwork.FlowLogsClient
	LoadBalancersClient                      *armnetwork.LoadBalancersClient
	ApplicationGatewaysClient                *armnetwork.ApplicationGatewaysClient
	WebApplicationFirewallPoliciesClient     *armnetwork.WebApplicationFirewallPoliciesClient
	InterfacesClient                         *armnetwork.InterfacesClient
	PrivateEndpointsClient                   *armnetwork.PrivateEndpointsClient
	PrivateDnsZoneGroupsClient               *armnetwork.PrivateDNSZoneGroupsClient
	PrivateDnsZonesClient                    *armprivatedns.PrivateZonesClient
	PrivateDnsVNetLinksClient                *armprivatedns.VirtualNetworkLinksClient
	PrivateDnsRecordSetsClient               *armprivatedns.RecordSetsClient
	DnsZonesClient                           *armdns.ZonesClient
	RecordSetsClient                         *armdns.RecordSetsClient
	VirtualMachinesClient                    *armcompute.VirtualMachinesClient
	AvailabilitySetsClient                   *armcompute.AvailabilitySetsClient
	DisksClient                              *armcompute.DisksClient
	SnapshotsClient                          *armcompute.SnapshotsClient
	ImagesClient                             *armcompute.ImagesClient
	GalleriesClient                          *armcompute.GalleriesClient
	GalleryImagesClient                      *armcompute.GalleryImagesClient
	GalleryApplicationsClient                *armcompute.GalleryApplicationsClient
	DiskAccessesClient                       *armcompute.DiskAccessesClient
	ProximityPlacementGroupsClient           *armcompute.ProximityPlacementGroupsClient
	SSHPublicKeysClient                      *armcompute.SSHPublicKeysClient
	VMScaleSetsClient                        *armcompute.VirtualMachineScaleSetsClient
	StorageAccountsClient                    *armstorage.AccountsClient
	StorageEncryptionScopesClient            *armstorage.EncryptionScopesClient
	BlobContainersClient                     *armstorage.BlobContainersClient
	StorageQueuesClient                      *armstorage.QueueClient
	StorageTablesClient                      *armstorage.TableClient
	FileSharesClient                         *armstorage.FileSharesClient
	StorageManagementPoliciesClient          *armstorage.ManagementPoliciesClient
	VaultsClient                             *armkeyvault.VaultsClient
	ManagedClustersClient                    *armcontainerservice.ManagedClustersClient
	MaintenanceConfigurationsClient          *armcontainerservice.MaintenanceConfigurationsClient
	TrustedAccessRoleBindingsClient          *armcontainerservice.TrustedAccessRoleBindingsClient
	ExtensionsClient                         *armkubernetesconfiguration.ExtensionsClient
	FluxConfigurationsClient                 *armkubernetesconfiguration.FluxConfigurationsClient
	RegistriesClient                         *armcontainerregistry.RegistriesClient
	ContainerRegistryWebhooksClient          *armcontainerregistry.WebhooksClient
	ContainerRegistryScopeMapsClient         *armcontainerregistry.ScopeMapsClient
	ContainerRegistryTokensClient            *armcontainerregistry.TokensClient
	UserAssignedIdentitiesClient             *armmsi.UserAssignedIdentitiesClient
	FederatedIdentityCredentialsClient       *armmsi.FederatedIdentityCredentialsClient
	RoleAssignmentsClient                    *armauthorization.RoleAssignmentsClient
	RoleDefinitionsClient                    *armauthorization.RoleDefinitionsClient
	PolicyDefinitionsClient                  *armpolicy.DefinitionsClient
	PolicyAssignmentsClient                  *armpolicy.AssignmentsClient
	PolicySetDefinitionsClient               *armpolicy.SetDefinitionsClient
	FlexibleServersClient                    *armpostgresqlflexibleservers.ServersClient
	FirewallRulesClient                      *armpostgresqlflexibleservers.FirewallRulesClient
	DatabasesClient                          *armpostgresqlflexibleservers.DatabasesClient
	ConfigurationsClient                     *armpostgresqlflexibleservers.ConfigurationsClient
	SQLServersClient                         *armsql.ServersClient
	SQLDatabasesClient                       *armsql.DatabasesClient
	SQLElasticPoolsClient                    *armsql.ElasticPoolsClient
	SQLFirewallRulesClient                   *armsql.FirewallRulesClient
	SQLServerAzureADAdministratorsClient     *armsql.ServerAzureADAdministratorsClient
	SQLServerDNSAliasesClient                *armsql.ServerDNSAliasesClient
	SQLOutboundFirewallRulesClient           *armsql.OutboundFirewallRulesClient
	SQLVirtualNetworkRulesClient             *armsql.VirtualNetworkRulesClient
	RouteTablesClient                        *armnetwork.RouteTablesClient
	VirtualMachineExtensionsClient           *armcompute.VirtualMachineExtensionsClient
	EventHubNamespacesClient                 *armeventhub.NamespacesClient
	EventHubSchemaRegistryClient             *armeventhub.SchemaRegistryClient
	EventHubsClient                          *armeventhub.EventHubsClient
	EventHubConsumerGroupsClient             *armeventhub.ConsumerGroupsClient
	ServiceBusNamespacesClient               *armservicebus.NamespacesClient
	AppConfigurationStoresClient             *armappconfiguration.ConfigurationStoresClient
	LogAnalyticsWorkspacesClient             *armoperationalinsights.WorkspacesClient
	LogAnalyticsSavedSearchesClient          *armoperationalinsights.SavedSearchesClient
	LogAnalyticsDataExportsClient            *armoperationalinsights.DataExportsClient
	LogAnalyticsLinkedStorageAccountsClient  *armoperationalinsights.LinkedStorageAccountsClient
	MonitorActionGroupsClient                *armmonitor.ActionGroupsClient
	MonitorActivityLogAlertsClient           *armmonitor.ActivityLogAlertsClient
	MonitorMetricAlertsClient                *armmonitor.MetricAlertsClient
	MonitorScheduledQueryRulesClient         *armmonitor.ScheduledQueryRulesClient
	MonitorDiagnosticSettingsClient          *armmonitor.DiagnosticSettingsClient
	MonitorDataCollectionEndpointsClient     *armmonitor.DataCollectionEndpointsClient
	MonitorDataCollectionRulesClient         *armmonitor.DataCollectionRulesClient
	MonitorPrivateLinkScopesClient           *armmonitor.PrivateLinkScopesClient
	MonitorPrivateLinkScopedResourcesClient  *armmonitor.PrivateLinkScopedResourcesClient
	AppInsightsComponentsClient              *armapplicationinsights.ComponentsClient
	ContainerGroupsClient                    *armcontainerinstance.ContainerGroupsClient
	MySQLFlexibleServersClient               *armmysqlflexibleservers.ServersClient
	CosmosDatabaseAccountsClient             *armcosmos.DatabaseAccountsClient
	SearchServicesClient                     *armsearch.ServicesClient
	BatchAccountClient                       *armbatch.AccountClient
	DNSResolversClient                       *armdnsresolver.DNSResolversClient
	DNSResolverInboundEndpointsClient        *armdnsresolver.InboundEndpointsClient
	DNSResolverOutboundEndpointsClient       *armdnsresolver.OutboundEndpointsClient
	DNSForwardingRulesetsClient              *armdnsresolver.DNSForwardingRulesetsClient
	DNSForwardingRulesClient                 *armdnsresolver.ForwardingRulesClient
	DNSForwardingRulesetVNetLinksClient      *armdnsresolver.VirtualNetworkLinksClient
	DNSResolverPoliciesClient                *armdnsresolver.PoliciesClient
	DNSResolverDomainListsClient             *armdnsresolver.DomainListsClient
	DNSSecurityRulesClient                   *armdnsresolver.DNSSecurityRulesClient
	DNSResolverPolicyVNetLinksClient         *armdnsresolver.PolicyVirtualNetworkLinksClient
	RelayNamespacesClient                    *armrelay.NamespacesClient
	RelayHybridConnectionsClient             *armrelay.HybridConnectionsClient
	NotificationHubNamespacesClient          *armnotificationhubs.NamespacesClient
	NotificationHubsClient                   *armnotificationhubs.Client
	NetAppAccountsClient                     *armnetapp.AccountsClient
	RedisClient                              *armredis.Client
	IotHubResourceClient                     *armiothub.ResourceClient
	TrafficManagerProfilesClient             *armtrafficmanager.ProfilesClient
	BackupVaultsClient                       *armdataprotection.BackupVaultsClient
	SignalRClient                            *armsignalr.Client
	WebPubSubClient                          *armwebpubsub.Client
	ServiceBusQueuesClient                   *armservicebus.QueuesClient
	ServiceBusTopicsClient                   *armservicebus.TopicsClient
	ServiceBusSubscriptionsClient            *armservicebus.SubscriptionsClient
	ServiceBusRulesClient                    *armservicebus.RulesClient
	EventGridSystemTopicsClient              *armeventgrid.SystemTopicsClient
	EventGridTopicsClient                    *armeventgrid.TopicsClient
	EventGridEventSubscriptionsClient        *armeventgrid.EventSubscriptionsClient
	EventGridDomainsClient                   *armeventgrid.DomainsClient
	EventGridDomainTopicsClient              *armeventgrid.DomainTopicsClient
	CognitiveAccountsClient                  *armcognitiveservices.AccountsClient
	GrafanaClient                            *armdashboard.GrafanaClient
	GrafanaManagedPrivateEndpointsClient     *armdashboard.ManagedPrivateEndpointsClient
	ManagedEnvironmentsClient                *armappcontainers.ManagedEnvironmentsClient
	ContainerAppsClient                      *armappcontainers.ContainerAppsClient
	// Azure Front Door Standard (Microsoft.Cdn AFD) clients.
	CdnProfilesClient         *armcdn.ProfilesClient
	CdnAFDEndpointsClient     *armcdn.AFDEndpointsClient
	CdnAFDOriginGroupsClient  *armcdn.AFDOriginGroupsClient
	CdnAFDOriginsClient       *armcdn.AFDOriginsClient
	CdnRoutesClient           *armcdn.RoutesClient
	CdnAFDCustomDomainsClient *armcdn.AFDCustomDomainsClient
	CdnSecretsClient          *armcdn.SecretsClient

	// Microsoft.Web (App Service) clients. One WebAppsClient covers sites, slots,
	// function apps and hostname bindings — ARM models them all under /sites.
	AppServicePlansClient        *armappservice.PlansClient
	AppServiceWebAppsClient      *armappservice.WebAppsClient
	AppServiceCertificatesClient *armappservice.CertificatesClient
	AppServiceStaticSitesClient  *armappservice.StaticSitesClient

	// Cosmos DB data-model clients (Microsoft.DocumentDB). The account itself is
	// CosmosDatabaseAccountsClient above; these carry its per-API child resources.
	CosmosSQLResourcesClient       *armcosmos.SQLResourcesClient
	CosmosMongoDBResourcesClient   *armcosmos.MongoDBResourcesClient
	CosmosCassandraResourcesClient *armcosmos.CassandraResourcesClient
	CosmosGremlinResourcesClient   *armcosmos.GremlinResourcesClient
	CosmosTableResourcesClient     *armcosmos.TableResourcesClient

	// Gateway and Virtual WAN clients (Microsoft.Network).
	VirtualNetworkGatewaysClient           *armnetwork.VirtualNetworkGatewaysClient
	VirtualNetworkGatewayConnectionsClient *armnetwork.VirtualNetworkGatewayConnectionsClient
	VirtualWansClient                      *armnetwork.VirtualWansClient
	VirtualHubsClient                      *armnetwork.VirtualHubsClient
	VPNGatewaysClient                      *armnetwork.VPNGatewaysClient
	VPNSitesClient                         *armnetwork.VPNSitesClient
	BastionHostsClient                     *armnetwork.BastionHostsClient
	credential                             azcore.TokenCredential
	clientOptions                          *arm.ClientOptions
	// armClient provides access to the pipeline for resuming pollers
	armClient *arm.Client
}

// NewClient creates a new Azure client wrapper
// clientCache holds one *Client per subscription for the plugin process lifetime.
//
// The plugin runs as a persistent process and issues many operations against the
// same target. Rebuilding the Client (and its credential) on every operation
// discards the Azure SDK's in-credential token cache, forcing a fresh token
// acquisition each time. Under short-lived federated auth (e.g. GitHub OIDC in
// CI, where the assertion outlives only ~10 min but the access token it buys
// lasts ~1 h) that means re-exchanging an assertion that has since expired —
// every op fails once the assertion ages out. Reusing one credential means the
// assertion is exchanged once (while fresh) and the SDK rides the ~1 h token
// across all subsequent operations. For refreshable auth (Managed Identity,
// service principal, az login) the SDK simply renews as designed.
// clientEntry carries a per-subscription lock so the (slow) first build of a
// subscription's Client serializes only same-subscription callers on entry.mu,
// never the global clientCacheMu. Holding the global lock through buildClient
// (credential construction + the first token acquisition, which shells out to
// `az` and can take seconds) stalls EVERY NewClient caller across the plugin
// process during a cold apply burst — enough to starve the plugin node and time
// out concurrent operator spawns. The global lock now guards only the tiny
// map get-or-create.
type clientEntry struct {
	mu     sync.Mutex
	client *Client
}

var (
	clientCacheMu sync.Mutex
	clientCache   = map[string]*clientEntry{}
)

// newCredential builds the Azure credential for a config. Overridable in tests.
var newCredential = func(cfg *config.Config) (azcore.TokenCredential, error) {
	return cfg.ToAzureCredential(context.Background())
}

// NewClient returns a cached *Client for the config's subscription, building one
// on first use. The returned Client (and its shared credential) is reused across
// operations so the SDK's token cache survives — see clientCache.
func NewClient(cfg *config.Config) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("azure config is required")
	}
	if strings.TrimSpace(cfg.SubscriptionId) == "" {
		return nil, fmt.Errorf("azure config requires non-empty SubscriptionId")
	}

	// Global lock guards only the map get-or-create — released immediately.
	clientCacheMu.Lock()
	entry, ok := clientCache[cfg.SubscriptionId]
	if !ok {
		entry = &clientEntry{}
		clientCache[cfg.SubscriptionId] = entry
	}
	clientCacheMu.Unlock()

	// Build (or reuse) under the per-subscription lock, NOT the global one, so a
	// cold build never blocks callers for other subscriptions or the node's other
	// work. A failed build is not cached, so the next operation retries it.
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.client != nil {
		return entry.client, nil
	}
	c, err := buildClient(cfg)
	if err != nil {
		return nil, err
	}
	entry.client = c
	return c, nil
}

// buildClient constructs a fresh Client with all typed sub-clients sharing one
// credential. Callers go through NewClient, which caches the result per subscription.
func buildClient(cfg *config.Config) (*Client, error) {
	cred, err := newCredential(cfg)
	if err != nil {
		return nil, err
	}

	clientOptions := &arm.ClientOptions{}

	rgClient, err := armresources.NewResourceGroupsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	vnetClient, err := armnetwork.NewVirtualNetworksClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	virtualNetworkPeeringsClient, err := armnetwork.NewVirtualNetworkPeeringsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	firewallPoliciesClient, err := armnetwork.NewFirewallPoliciesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	firewallPolicyRuleCollectionGroupsClient, err := armnetwork.NewFirewallPolicyRuleCollectionGroupsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	localNetworkGatewaysClient, err := armnetwork.NewLocalNetworkGatewaysClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	subnetClient, err := armnetwork.NewSubnetsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	securityGroupsClient, err := armnetwork.NewSecurityGroupsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	applicationSecurityGroupsClient, err := armnetwork.NewApplicationSecurityGroupsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	ipGroupsClient, err := armnetwork.NewIPGroupsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	publicIPAddressesClient, err := armnetwork.NewPublicIPAddressesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	publicIPPrefixesClient, err := armnetwork.NewPublicIPPrefixesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	natGatewaysClient, err := armnetwork.NewNatGatewaysClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	watchersClient, err := armnetwork.NewWatchersClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	flowLogsClient, err := armnetwork.NewFlowLogsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	loadBalancersClient, err := armnetwork.NewLoadBalancersClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	applicationGatewaysClient, err := armnetwork.NewApplicationGatewaysClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	webApplicationFirewallPoliciesClient, err := armnetwork.NewWebApplicationFirewallPoliciesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	privateEndpointsClient, err := armnetwork.NewPrivateEndpointsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	privateDnsZoneGroupsClient, err := armnetwork.NewPrivateDNSZoneGroupsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	privateDnsZonesClient, err := armprivatedns.NewPrivateZonesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	privateDnsVNetLinksClient, err := armprivatedns.NewVirtualNetworkLinksClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	privateDnsRecordSetsClient, err := armprivatedns.NewRecordSetsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	dnsZonesClient, err := armdns.NewZonesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	recordSetsClient, err := armdns.NewRecordSetsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	interfacesClient, err := armnetwork.NewInterfacesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	virtualMachinesClient, err := armcompute.NewVirtualMachinesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	availabilitySetsClient, err := armcompute.NewAvailabilitySetsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	disksClient, err := armcompute.NewDisksClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	snapshotsClient, err := armcompute.NewSnapshotsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	imagesClient, err := armcompute.NewImagesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	galleriesClient, err := armcompute.NewGalleriesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	galleryImagesClient, err := armcompute.NewGalleryImagesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	galleryApplicationsClient, err := armcompute.NewGalleryApplicationsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	diskAccessesClient, err := armcompute.NewDiskAccessesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	proximityPlacementGroupsClient, err := armcompute.NewProximityPlacementGroupsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	sshPublicKeysClient, err := armcompute.NewSSHPublicKeysClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	vmScaleSetsClient, err := armcompute.NewVirtualMachineScaleSetsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	storageAccountsClient, err := armstorage.NewAccountsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	storageEncryptionScopesClient, err := armstorage.NewEncryptionScopesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	blobContainersClient, err := armstorage.NewBlobContainersClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	storageQueuesClient, err := armstorage.NewQueueClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	storageTablesClient, err := armstorage.NewTableClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	fileSharesClient, err := armstorage.NewFileSharesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	storageManagementPoliciesClient, err := armstorage.NewManagementPoliciesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	vaultsClient, err := armkeyvault.NewVaultsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	managedClustersClient, err := armcontainerservice.NewManagedClustersClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	maintenanceConfigurationsClient, err := armcontainerservice.NewMaintenanceConfigurationsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	trustedAccessRoleBindingsClient, err := armcontainerservice.NewTrustedAccessRoleBindingsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	extensionsClient, err := armkubernetesconfiguration.NewExtensionsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	fluxConfigurationsClient, err := armkubernetesconfiguration.NewFluxConfigurationsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	registriesClient, err := armcontainerregistry.NewRegistriesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	containerRegistryWebhooksClient, err := armcontainerregistry.NewWebhooksClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	containerRegistryScopeMapsClient, err := armcontainerregistry.NewScopeMapsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	containerRegistryTokensClient, err := armcontainerregistry.NewTokensClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	userAssignedIdentitiesClient, err := armmsi.NewUserAssignedIdentitiesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	federatedIdentityCredentialsClient, err := armmsi.NewFederatedIdentityCredentialsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	roleAssignmentsClient, err := armauthorization.NewRoleAssignmentsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	// Role definitions are scope-addressed, so this client takes no subscription.
	roleDefinitionsClient, err := armauthorization.NewRoleDefinitionsClient(cred, clientOptions)
	if err != nil {
		return nil, err
	}

	policyDefinitionsClient, err := armpolicy.NewDefinitionsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	policyAssignmentsClient, err := armpolicy.NewAssignmentsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	policySetDefinitionsClient, err := armpolicy.NewSetDefinitionsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	flexibleServersClient, err := armpostgresqlflexibleservers.NewServersClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	firewallRulesClient, err := armpostgresqlflexibleservers.NewFirewallRulesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	databasesClient, err := armpostgresqlflexibleservers.NewDatabasesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	configurationsClient, err := armpostgresqlflexibleservers.NewConfigurationsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	sqlServersClient, err := armsql.NewServersClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	sqlDatabasesClient, err := armsql.NewDatabasesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	sqlElasticPoolsClient, err := armsql.NewElasticPoolsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	sqlFirewallRulesClient, err := armsql.NewFirewallRulesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	sqlServerAzureADAdministratorsClient, err := armsql.NewServerAzureADAdministratorsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	sqlServerDNSAliasesClient, err := armsql.NewServerDNSAliasesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	sqlOutboundFirewallRulesClient, err := armsql.NewOutboundFirewallRulesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	sqlVirtualNetworkRulesClient, err := armsql.NewVirtualNetworkRulesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	routeTablesClient, err := armnetwork.NewRouteTablesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	virtualMachineExtensionsClient, err := armcompute.NewVirtualMachineExtensionsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	eventHubNamespacesClient, err := armeventhub.NewNamespacesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	eventHubSchemaRegistryClient, err := armeventhub.NewSchemaRegistryClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	eventHubsClient, err := armeventhub.NewEventHubsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	eventHubConsumerGroupsClient, err := armeventhub.NewConsumerGroupsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	serviceBusNamespacesClient, err := armservicebus.NewNamespacesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	appConfigurationStoresClient, err := armappconfiguration.NewConfigurationStoresClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	logAnalyticsWorkspacesClient, err := armoperationalinsights.NewWorkspacesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	logAnalyticsSavedSearchesClient, err := armoperationalinsights.NewSavedSearchesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	logAnalyticsDataExportsClient, err := armoperationalinsights.NewDataExportsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	logAnalyticsLinkedStorageAccountsClient, err := armoperationalinsights.NewLinkedStorageAccountsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	monitorActionGroupsClient, err := armmonitor.NewActionGroupsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	monitorActivityLogAlertsClient, err := armmonitor.NewActivityLogAlertsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	// armmonitor v0.13.0 defaults its MetricAlerts client to api-version 2026-01-01,
	// which ARM rejects outright for this type:
	//
	//	NoRegisteredProviderFound: No registered resource provider found for
	//	location 'Global' and API version '2026-01-01' for type 'metricalerts'.
	//	The supported api-versions are '2017-09-01-preview, 2018-03-01,
	//	2024-01-01-preview, 2024-03-01-preview'.
	//
	// Pin the version this plugin's schema documents. Only this client needs the
	// override, so it gets its own options rather than changing the shared ones.
	metricAlertOptions := &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{APIVersion: "2018-03-01"},
	}
	monitorMetricAlertsClient, err := armmonitor.NewMetricAlertsClient(cfg.SubscriptionId, cred, metricAlertOptions)
	if err != nil {
		return nil, err
	}

	// Pinned for the same reason as the metric alerts client above: this pre-1.0
	// module's default api-version runs ahead of what the service accepts. 2021-08-01
	// is the GA version the schema documents.
	scheduledQueryRuleOptions := &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{APIVersion: "2021-08-01"},
	}
	monitorScheduledQueryRulesClient, err := armmonitor.NewScheduledQueryRulesClient(cfg.SubscriptionId, cred, scheduledQueryRuleOptions)
	if err != nil {
		return nil, err
	}

	monitorDiagnosticSettingsClient, err := armmonitor.NewDiagnosticSettingsClient(cred, clientOptions)
	if err != nil {
		return nil, err
	}

	// Unlike MetricAlerts and ScheduledQueryRules above, this client's default
	// api-version (2024-03-11) is the newest ARM lists for dataCollectionEndpoints,
	// so it needs no pin.
	monitorDataCollectionEndpointsClient, err := armmonitor.NewDataCollectionEndpointsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	// Same api-version story as the endpoints client above: the SDK default
	// (2024-03-11) is ARM's newest for dataCollectionRules, so no pin.
	monitorDataCollectionRulesClient, err := armmonitor.NewDataCollectionRulesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	// armmonitor v0.13.0 sends api-version 2023-06-01 for private link scopes, which
	// ARM does not offer at all for this type — its list runs 2023-06-01-PREVIEW,
	// 2021-09-01, 2021-07-01-preview, 2019-10-17-preview. Pin the newest stable one.
	privateLinkScopeOptions := &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{APIVersion: "2021-09-01"},
	}
	monitorPrivateLinkScopesClient, err := armmonitor.NewPrivateLinkScopesClient(cfg.SubscriptionId, cred, privateLinkScopeOptions)
	if err != nil {
		return nil, err
	}

	// Same pin as the scope above, for the same reason: the SDK default 2023-06-01
	// does not exist for privateLinkScopes/scopedResources either — only
	// 2023-06-01-preview and older.
	monitorPrivateLinkScopedResourcesClient, err := armmonitor.NewPrivateLinkScopedResourcesClient(cfg.SubscriptionId, cred, privateLinkScopeOptions)
	if err != nil {
		return nil, err
	}

	appInsightsComponentsClient, err := armapplicationinsights.NewComponentsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	containerGroupsClient, err := armcontainerinstance.NewContainerGroupsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	mySQLFlexibleServersClient, err := armmysqlflexibleservers.NewServersClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cosmosDatabaseAccountsClient, err := armcosmos.NewDatabaseAccountsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	searchServicesClient, err := armsearch.NewServicesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	batchAccountClient, err := armbatch.NewAccountClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	dnsResolversClient, err := armdnsresolver.NewDNSResolversClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	dnsResolverInboundEndpointsClient, err := armdnsresolver.NewInboundEndpointsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	dnsResolverOutboundEndpointsClient, err := armdnsresolver.NewOutboundEndpointsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	dnsForwardingRulesetsClient, err := armdnsresolver.NewDNSForwardingRulesetsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	dnsForwardingRulesClient, err := armdnsresolver.NewForwardingRulesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	dnsForwardingRulesetVNetLinksClient, err := armdnsresolver.NewVirtualNetworkLinksClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	dnsResolverPoliciesClient, err := armdnsresolver.NewPoliciesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	dnsResolverDomainListsClient, err := armdnsresolver.NewDomainListsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	dnsSecurityRulesClient, err := armdnsresolver.NewDNSSecurityRulesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	dnsResolverPolicyVNetLinksClient, err := armdnsresolver.NewPolicyVirtualNetworkLinksClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	relayNamespacesClient, err := armrelay.NewNamespacesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	relayHybridConnectionsClient, err := armrelay.NewHybridConnectionsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	notificationHubNamespacesClient, err := armnotificationhubs.NewNamespacesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	notificationHubsClient, err := armnotificationhubs.NewClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	netAppAccountsClient, err := armnetapp.NewAccountsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	redisClient, err := armredis.NewClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	iotHubResourceClient, err := armiothub.NewResourceClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	trafficManagerProfilesClient, err := armtrafficmanager.NewProfilesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	backupVaultsClient, err := armdataprotection.NewBackupVaultsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	signalRClient, err := armsignalr.NewClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	webPubSubClient, err := armwebpubsub.NewClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	serviceBusQueuesClient, err := armservicebus.NewQueuesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	serviceBusTopicsClient, err := armservicebus.NewTopicsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	serviceBusSubscriptionsClient, err := armservicebus.NewSubscriptionsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	serviceBusRulesClient, err := armservicebus.NewRulesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	eventGridSystemTopicsClient, err := armeventgrid.NewSystemTopicsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	eventGridTopicsClient, err := armeventgrid.NewTopicsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	eventGridEventSubscriptionsClient, err := armeventgrid.NewEventSubscriptionsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	eventGridDomainsClient, err := armeventgrid.NewDomainsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	eventGridDomainTopicsClient, err := armeventgrid.NewDomainTopicsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cognitiveAccountsClient, err := armcognitiveservices.NewAccountsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	grafanaClient, err := armdashboard.NewGrafanaClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	grafanaManagedPrivateEndpointsClient, err := armdashboard.NewManagedPrivateEndpointsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	managedEnvironmentsClient, err := armappcontainers.NewManagedEnvironmentsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	containerAppsClient, err := armappcontainers.NewContainerAppsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cdnProfilesClient, err := armcdn.NewProfilesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cdnAFDEndpointsClient, err := armcdn.NewAFDEndpointsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cdnAFDOriginGroupsClient, err := armcdn.NewAFDOriginGroupsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cdnAFDOriginsClient, err := armcdn.NewAFDOriginsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cdnRoutesClient, err := armcdn.NewRoutesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cdnAFDCustomDomainsClient, err := armcdn.NewAFDCustomDomainsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cdnSecretsClient, err := armcdn.NewSecretsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	appServicePlansClient, err := armappservice.NewPlansClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	appServiceWebAppsClient, err := armappservice.NewWebAppsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	appServiceCertificatesClient, err := armappservice.NewCertificatesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	appServiceStaticSitesClient, err := armappservice.NewStaticSitesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cosmosSQLResourcesClient, err := armcosmos.NewSQLResourcesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cosmosMongoDBResourcesClient, err := armcosmos.NewMongoDBResourcesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cosmosCassandraResourcesClient, err := armcosmos.NewCassandraResourcesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cosmosGremlinResourcesClient, err := armcosmos.NewGremlinResourcesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	cosmosTableResourcesClient, err := armcosmos.NewTableResourcesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	virtualNetworkGatewaysClient, err := armnetwork.NewVirtualNetworkGatewaysClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	virtualNetworkGatewayConnectionsClient, err := armnetwork.NewVirtualNetworkGatewayConnectionsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	virtualWansClient, err := armnetwork.NewVirtualWansClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	virtualHubsClient, err := armnetwork.NewVirtualHubsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	vpnGatewaysClient, err := armnetwork.NewVPNGatewaysClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	vpnSitesClient, err := armnetwork.NewVPNSitesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	bastionHostsClient, err := armnetwork.NewBastionHostsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	// Create a low-level ARM client for pipeline access (needed for resuming pollers)
	armClient, err := arm.NewClient(moduleName, moduleVersion, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	return &Client{
		Config:                                   cfg,
		ResourceGroupsClient:                     rgClient,
		VirtualNetworksClient:                    vnetClient,
		VirtualNetworkPeeringsClient:             virtualNetworkPeeringsClient,
		FirewallPoliciesClient:                   firewallPoliciesClient,
		FirewallPolicyRuleCollectionGroupsClient: firewallPolicyRuleCollectionGroupsClient,
		LocalNetworkGatewaysClient:               localNetworkGatewaysClient,
		SubnetsClient:                            subnetClient,
		SecurityGroupsClient:                     securityGroupsClient,
		ApplicationSecurityGroupsClient:          applicationSecurityGroupsClient,
		IPGroupsClient:                           ipGroupsClient,
		PublicIPAddressesClient:                  publicIPAddressesClient,
		PublicIPPrefixesClient:                   publicIPPrefixesClient,
		NatGatewaysClient:                        natGatewaysClient,
		WatchersClient:                           watchersClient,
		FlowLogsClient:                           flowLogsClient,
		LoadBalancersClient:                      loadBalancersClient,
		ApplicationGatewaysClient:                applicationGatewaysClient,
		WebApplicationFirewallPoliciesClient:     webApplicationFirewallPoliciesClient,
		InterfacesClient:                         interfacesClient,
		PrivateEndpointsClient:                   privateEndpointsClient,
		PrivateDnsZoneGroupsClient:               privateDnsZoneGroupsClient,
		PrivateDnsZonesClient:                    privateDnsZonesClient,
		PrivateDnsVNetLinksClient:                privateDnsVNetLinksClient,
		PrivateDnsRecordSetsClient:               privateDnsRecordSetsClient,
		DnsZonesClient:                           dnsZonesClient,
		RecordSetsClient:                         recordSetsClient,
		VirtualMachinesClient:                    virtualMachinesClient,
		AvailabilitySetsClient:                   availabilitySetsClient,
		DisksClient:                              disksClient,
		SnapshotsClient:                          snapshotsClient,
		ImagesClient:                             imagesClient,
		GalleriesClient:                          galleriesClient,
		GalleryImagesClient:                      galleryImagesClient,
		GalleryApplicationsClient:                galleryApplicationsClient,
		DiskAccessesClient:                       diskAccessesClient,
		ProximityPlacementGroupsClient:           proximityPlacementGroupsClient,
		SSHPublicKeysClient:                      sshPublicKeysClient,
		VMScaleSetsClient:                        vmScaleSetsClient,
		StorageAccountsClient:                    storageAccountsClient,
		StorageEncryptionScopesClient:            storageEncryptionScopesClient,
		BlobContainersClient:                     blobContainersClient,
		StorageQueuesClient:                      storageQueuesClient,
		StorageTablesClient:                      storageTablesClient,
		FileSharesClient:                         fileSharesClient,
		StorageManagementPoliciesClient:          storageManagementPoliciesClient,
		VaultsClient:                             vaultsClient,
		ManagedClustersClient:                    managedClustersClient,
		MaintenanceConfigurationsClient:          maintenanceConfigurationsClient,
		TrustedAccessRoleBindingsClient:          trustedAccessRoleBindingsClient,
		ExtensionsClient:                         extensionsClient,
		FluxConfigurationsClient:                 fluxConfigurationsClient,
		RegistriesClient:                         registriesClient,
		ContainerRegistryWebhooksClient:          containerRegistryWebhooksClient,
		ContainerRegistryScopeMapsClient:         containerRegistryScopeMapsClient,
		ContainerRegistryTokensClient:            containerRegistryTokensClient,
		UserAssignedIdentitiesClient:             userAssignedIdentitiesClient,
		FederatedIdentityCredentialsClient:       federatedIdentityCredentialsClient,
		RoleAssignmentsClient:                    roleAssignmentsClient,
		RoleDefinitionsClient:                    roleDefinitionsClient,
		PolicyDefinitionsClient:                  policyDefinitionsClient,
		PolicyAssignmentsClient:                  policyAssignmentsClient,
		PolicySetDefinitionsClient:               policySetDefinitionsClient,
		FlexibleServersClient:                    flexibleServersClient,
		FirewallRulesClient:                      firewallRulesClient,
		DatabasesClient:                          databasesClient,
		ConfigurationsClient:                     configurationsClient,
		SQLServersClient:                         sqlServersClient,
		SQLDatabasesClient:                       sqlDatabasesClient,
		SQLElasticPoolsClient:                    sqlElasticPoolsClient,
		SQLFirewallRulesClient:                   sqlFirewallRulesClient,
		SQLServerAzureADAdministratorsClient:     sqlServerAzureADAdministratorsClient,
		SQLServerDNSAliasesClient:                sqlServerDNSAliasesClient,
		SQLOutboundFirewallRulesClient:           sqlOutboundFirewallRulesClient,
		SQLVirtualNetworkRulesClient:             sqlVirtualNetworkRulesClient,
		RouteTablesClient:                        routeTablesClient,
		VirtualMachineExtensionsClient:           virtualMachineExtensionsClient,
		EventHubNamespacesClient:                 eventHubNamespacesClient,
		EventHubSchemaRegistryClient:             eventHubSchemaRegistryClient,
		EventHubsClient:                          eventHubsClient,
		EventHubConsumerGroupsClient:             eventHubConsumerGroupsClient,
		ServiceBusNamespacesClient:               serviceBusNamespacesClient,
		AppConfigurationStoresClient:             appConfigurationStoresClient,
		LogAnalyticsWorkspacesClient:             logAnalyticsWorkspacesClient,
		LogAnalyticsSavedSearchesClient:          logAnalyticsSavedSearchesClient,
		LogAnalyticsDataExportsClient:            logAnalyticsDataExportsClient,
		LogAnalyticsLinkedStorageAccountsClient:  logAnalyticsLinkedStorageAccountsClient,
		MonitorActionGroupsClient:                monitorActionGroupsClient,
		MonitorActivityLogAlertsClient:           monitorActivityLogAlertsClient,
		MonitorMetricAlertsClient:                monitorMetricAlertsClient,
		MonitorScheduledQueryRulesClient:         monitorScheduledQueryRulesClient,
		MonitorDiagnosticSettingsClient:          monitorDiagnosticSettingsClient,
		MonitorDataCollectionEndpointsClient:     monitorDataCollectionEndpointsClient,
		MonitorDataCollectionRulesClient:         monitorDataCollectionRulesClient,
		MonitorPrivateLinkScopesClient:           monitorPrivateLinkScopesClient,
		MonitorPrivateLinkScopedResourcesClient:  monitorPrivateLinkScopedResourcesClient,
		AppInsightsComponentsClient:              appInsightsComponentsClient,
		ContainerGroupsClient:                    containerGroupsClient,
		MySQLFlexibleServersClient:               mySQLFlexibleServersClient,
		CosmosDatabaseAccountsClient:             cosmosDatabaseAccountsClient,
		SearchServicesClient:                     searchServicesClient,
		BatchAccountClient:                       batchAccountClient,
		DNSResolversClient:                       dnsResolversClient,
		DNSResolverInboundEndpointsClient:        dnsResolverInboundEndpointsClient,
		DNSResolverOutboundEndpointsClient:       dnsResolverOutboundEndpointsClient,
		DNSForwardingRulesetsClient:              dnsForwardingRulesetsClient,
		DNSForwardingRulesClient:                 dnsForwardingRulesClient,
		DNSForwardingRulesetVNetLinksClient:      dnsForwardingRulesetVNetLinksClient,
		DNSResolverPoliciesClient:                dnsResolverPoliciesClient,
		DNSResolverDomainListsClient:             dnsResolverDomainListsClient,
		DNSSecurityRulesClient:                   dnsSecurityRulesClient,
		DNSResolverPolicyVNetLinksClient:         dnsResolverPolicyVNetLinksClient,
		RelayNamespacesClient:                    relayNamespacesClient,
		RelayHybridConnectionsClient:             relayHybridConnectionsClient,
		NotificationHubNamespacesClient:          notificationHubNamespacesClient,
		NotificationHubsClient:                   notificationHubsClient,
		NetAppAccountsClient:                     netAppAccountsClient,
		RedisClient:                              redisClient,
		IotHubResourceClient:                     iotHubResourceClient,
		TrafficManagerProfilesClient:             trafficManagerProfilesClient,
		BackupVaultsClient:                       backupVaultsClient,
		SignalRClient:                            signalRClient,
		WebPubSubClient:                          webPubSubClient,
		ServiceBusQueuesClient:                   serviceBusQueuesClient,
		ServiceBusTopicsClient:                   serviceBusTopicsClient,
		ServiceBusSubscriptionsClient:            serviceBusSubscriptionsClient,
		ServiceBusRulesClient:                    serviceBusRulesClient,
		EventGridSystemTopicsClient:              eventGridSystemTopicsClient,
		EventGridTopicsClient:                    eventGridTopicsClient,
		EventGridEventSubscriptionsClient:        eventGridEventSubscriptionsClient,
		EventGridDomainsClient:                   eventGridDomainsClient,
		EventGridDomainTopicsClient:              eventGridDomainTopicsClient,
		CognitiveAccountsClient:                  cognitiveAccountsClient,
		GrafanaClient:                            grafanaClient,
		GrafanaManagedPrivateEndpointsClient:     grafanaManagedPrivateEndpointsClient,
		ManagedEnvironmentsClient:                managedEnvironmentsClient,
		ContainerAppsClient:                      containerAppsClient,
		CdnProfilesClient:                        cdnProfilesClient,
		CdnAFDEndpointsClient:                    cdnAFDEndpointsClient,
		CdnAFDOriginGroupsClient:                 cdnAFDOriginGroupsClient,
		CdnAFDOriginsClient:                      cdnAFDOriginsClient,
		CdnRoutesClient:                          cdnRoutesClient,
		CdnAFDCustomDomainsClient:                cdnAFDCustomDomainsClient,
		CdnSecretsClient:                         cdnSecretsClient,
		AppServicePlansClient:                    appServicePlansClient,
		AppServiceWebAppsClient:                  appServiceWebAppsClient,
		AppServiceCertificatesClient:             appServiceCertificatesClient,
		AppServiceStaticSitesClient:              appServiceStaticSitesClient,
		CosmosSQLResourcesClient:                 cosmosSQLResourcesClient,
		CosmosMongoDBResourcesClient:             cosmosMongoDBResourcesClient,
		CosmosCassandraResourcesClient:           cosmosCassandraResourcesClient,
		CosmosGremlinResourcesClient:             cosmosGremlinResourcesClient,
		CosmosTableResourcesClient:               cosmosTableResourcesClient,
		VirtualNetworkGatewaysClient:             virtualNetworkGatewaysClient,
		VirtualNetworkGatewayConnectionsClient:   virtualNetworkGatewayConnectionsClient,
		VirtualWansClient:                        virtualWansClient,
		VirtualHubsClient:                        virtualHubsClient,
		VPNGatewaysClient:                        vpnGatewaysClient,
		VPNSitesClient:                           vpnSitesClient,
		BastionHostsClient:                       bastionHostsClient,
		credential:                               cred,
		clientOptions:                            clientOptions,
		armClient:                                armClient,
	}, nil
}

// Pipeline returns the low-level ARM pipeline for resuming pollers.
func (c *Client) Pipeline() runtime.Pipeline {
	return c.armClient.Pipeline()
}

// Credential exposes the token credential for building per-endpoint data-plane clients (e.g. azsecrets).
func (c *Client) Credential() azcore.TokenCredential {
	return c.credential
}

// ResumeDeleteResourceGroupPoller reconstructs a delete poller from a resume token.
// This allows tracking the status of a long-running delete operation across process restarts.
func (c *Client) ResumeDeleteResourceGroupPoller(token string) (*runtime.Poller[armresources.ResourceGroupsClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armresources.ResourceGroupsClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateVirtualNetworkPoller reconstructs a create/update VNet poller from a resume token.
func (c *Client) ResumeCreateVirtualNetworkPoller(token string) (*runtime.Poller[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armnetwork.VirtualNetworksClientCreateOrUpdateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeleteVirtualNetworkPoller reconstructs a delete VNet poller from a resume token.
func (c *Client) ResumeDeleteVirtualNetworkPoller(token string) (*runtime.Poller[armnetwork.VirtualNetworksClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armnetwork.VirtualNetworksClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateSubnetPoller reconstructs a create/update Subnet poller from a resume token.
func (c *Client) ResumeCreateSubnetPoller(token string) (*runtime.Poller[armnetwork.SubnetsClientCreateOrUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armnetwork.SubnetsClientCreateOrUpdateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeleteSubnetPoller reconstructs a delete Subnet poller from a resume token.
func (c *Client) ResumeDeleteSubnetPoller(token string) (*runtime.Poller[armnetwork.SubnetsClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armnetwork.SubnetsClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateSecurityGroupPoller reconstructs a create/update NSG poller from a resume token.
func (c *Client) ResumeCreateSecurityGroupPoller(token string) (*runtime.Poller[armnetwork.SecurityGroupsClientCreateOrUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armnetwork.SecurityGroupsClientCreateOrUpdateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeleteSecurityGroupPoller reconstructs a delete NSG poller from a resume token.
func (c *Client) ResumeDeleteSecurityGroupPoller(token string) (*runtime.Poller[armnetwork.SecurityGroupsClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armnetwork.SecurityGroupsClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreatePublicIPAddressPoller reconstructs a create/update PublicIP poller from a resume token.
func (c *Client) ResumeCreatePublicIPAddressPoller(token string) (*runtime.Poller[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeletePublicIPAddressPoller reconstructs a delete PublicIP poller from a resume token.
func (c *Client) ResumeDeletePublicIPAddressPoller(token string) (*runtime.Poller[armnetwork.PublicIPAddressesClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armnetwork.PublicIPAddressesClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateStorageAccountPoller reconstructs a create StorageAccount poller from a resume token.
func (c *Client) ResumeCreateStorageAccountPoller(token string) (*runtime.Poller[armstorage.AccountsClientCreateResponse], error) {
	return runtime.NewPollerFromResumeToken[armstorage.AccountsClientCreateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeleteStorageAccountPoller reconstructs a delete StorageAccount poller from a resume token.
// Note: Storage account delete is synchronous, but we include this for consistency.
func (c *Client) ResumeDeleteStorageAccountPoller(token string) (*runtime.Poller[armstorage.AccountsClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armstorage.AccountsClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateKeyVaultPoller reconstructs a create KeyVault poller from a resume token.
func (c *Client) ResumeCreateKeyVaultPoller(token string) (*runtime.Poller[armkeyvault.VaultsClientCreateOrUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armkeyvault.VaultsClientCreateOrUpdateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeleteKeyVaultPoller reconstructs a purge (permanent delete) KeyVault poller from a resume token.
func (c *Client) ResumeDeleteKeyVaultPoller(token string) (*runtime.Poller[armkeyvault.VaultsClientPurgeDeletedResponse], error) {
	return runtime.NewPollerFromResumeToken[armkeyvault.VaultsClientPurgeDeletedResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateNetworkInterfacePoller reconstructs a create/update NetworkInterface poller from a resume token.
func (c *Client) ResumeCreateNetworkInterfacePoller(token string) (*runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armnetwork.InterfacesClientCreateOrUpdateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeleteNetworkInterfacePoller reconstructs a delete NetworkInterface poller from a resume token.
func (c *Client) ResumeDeleteNetworkInterfacePoller(token string) (*runtime.Poller[armnetwork.InterfacesClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armnetwork.InterfacesClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateVirtualMachinePoller reconstructs a create/update VirtualMachine poller from a resume token.
func (c *Client) ResumeCreateVirtualMachinePoller(token string) (*runtime.Poller[armcompute.VirtualMachinesClientCreateOrUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armcompute.VirtualMachinesClientCreateOrUpdateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeleteVirtualMachinePoller reconstructs a delete VirtualMachine poller from a resume token.
func (c *Client) ResumeDeleteVirtualMachinePoller(token string) (*runtime.Poller[armcompute.VirtualMachinesClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armcompute.VirtualMachinesClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateManagedClusterPoller reconstructs a create/update ManagedCluster poller from a resume token.
func (c *Client) ResumeCreateManagedClusterPoller(token string) (*runtime.Poller[armcontainerservice.ManagedClustersClientCreateOrUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armcontainerservice.ManagedClustersClientCreateOrUpdateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeleteManagedClusterPoller reconstructs a delete ManagedCluster poller from a resume token.
func (c *Client) ResumeDeleteManagedClusterPoller(token string) (*runtime.Poller[armcontainerservice.ManagedClustersClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armcontainerservice.ManagedClustersClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateContainerRegistryPoller reconstructs a create Registry poller from a resume token.
func (c *Client) ResumeCreateContainerRegistryPoller(token string) (*runtime.Poller[armcontainerregistry.RegistriesClientCreateResponse], error) {
	return runtime.NewPollerFromResumeToken[armcontainerregistry.RegistriesClientCreateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeUpdateContainerRegistryPoller reconstructs an update Registry poller from a resume token.
func (c *Client) ResumeUpdateContainerRegistryPoller(token string) (*runtime.Poller[armcontainerregistry.RegistriesClientUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armcontainerregistry.RegistriesClientUpdateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeleteContainerRegistryPoller reconstructs a delete Registry poller from a resume token.
func (c *Client) ResumeDeleteContainerRegistryPoller(token string) (*runtime.Poller[armcontainerregistry.RegistriesClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armcontainerregistry.RegistriesClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateFlexibleServerPoller reconstructs a create/update FlexibleServer poller from a resume token.
func (c *Client) ResumeCreateFlexibleServerPoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientCreateResponse], error) {
	return runtime.NewPollerFromResumeToken[armpostgresqlflexibleservers.ServersClientCreateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeUpdateFlexibleServerPoller reconstructs an update FlexibleServer poller from a resume token.
func (c *Client) ResumeUpdateFlexibleServerPoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armpostgresqlflexibleservers.ServersClientUpdateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeleteFlexibleServerPoller reconstructs a delete FlexibleServer poller from a resume token.
func (c *Client) ResumeDeleteFlexibleServerPoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.ServersClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armpostgresqlflexibleservers.ServersClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateFirewallRulePoller reconstructs a create/update FirewallRule poller from a resume token.
func (c *Client) ResumeCreateFirewallRulePoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armpostgresqlflexibleservers.FirewallRulesClientCreateOrUpdateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeleteFirewallRulePoller reconstructs a delete FirewallRule poller from a resume token.
func (c *Client) ResumeDeleteFirewallRulePoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.FirewallRulesClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armpostgresqlflexibleservers.FirewallRulesClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateDatabasePoller reconstructs a create Database poller from a resume token.
func (c *Client) ResumeCreateDatabasePoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientCreateResponse], error) {
	return runtime.NewPollerFromResumeToken[armpostgresqlflexibleservers.DatabasesClientCreateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeDeleteDatabasePoller reconstructs a delete Database poller from a resume token.
func (c *Client) ResumeDeleteDatabasePoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.DatabasesClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armpostgresqlflexibleservers.DatabasesClientDeleteResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeUpdateConfigurationPoller reconstructs an update Configuration poller from a resume token.
func (c *Client) ResumeUpdateConfigurationPoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armpostgresqlflexibleservers.ConfigurationsClientUpdateResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumePutConfigurationPoller reconstructs a put Configuration poller from a resume token.
func (c *Client) ResumePutConfigurationPoller(token string) (*runtime.Poller[armpostgresqlflexibleservers.ConfigurationsClientPutResponse], error) {
	return runtime.NewPollerFromResumeToken[armpostgresqlflexibleservers.ConfigurationsClientPutResponse](
		token,
		c.armClient.Pipeline(),
		nil,
	)
}

// ResumeCreateTrustedAccessRoleBindingPoller reconstructs a create TrustedAccessRoleBinding poller from a resume token.
func (c *Client) ResumeCreateTrustedAccessRoleBindingPoller(token string) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armcontainerservice.TrustedAccessRoleBindingsClientCreateOrUpdateResponse](token, c.armClient.Pipeline(), nil)
}

// ResumeDeleteTrustedAccessRoleBindingPoller reconstructs a delete TrustedAccessRoleBinding poller from a resume token.
func (c *Client) ResumeDeleteTrustedAccessRoleBindingPoller(token string) (*runtime.Poller[armcontainerservice.TrustedAccessRoleBindingsClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armcontainerservice.TrustedAccessRoleBindingsClientDeleteResponse](token, c.armClient.Pipeline(), nil)
}

// ResumeCreateExtensionPoller reconstructs a create Extension poller from a resume token.
func (c *Client) ResumeCreateExtensionPoller(token string) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientCreateResponse], error) {
	return runtime.NewPollerFromResumeToken[armkubernetesconfiguration.ExtensionsClientCreateResponse](token, c.armClient.Pipeline(), nil)
}

// ResumeUpdateExtensionPoller reconstructs an update Extension poller from a resume token.
func (c *Client) ResumeUpdateExtensionPoller(token string) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armkubernetesconfiguration.ExtensionsClientUpdateResponse](token, c.armClient.Pipeline(), nil)
}

// ResumeDeleteExtensionPoller reconstructs a delete Extension poller from a resume token.
func (c *Client) ResumeDeleteExtensionPoller(token string) (*runtime.Poller[armkubernetesconfiguration.ExtensionsClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armkubernetesconfiguration.ExtensionsClientDeleteResponse](token, c.armClient.Pipeline(), nil)
}

// ResumeCreateFluxConfigurationPoller reconstructs a create FluxConfiguration poller from a resume token.
func (c *Client) ResumeCreateFluxConfigurationPoller(token string) (*runtime.Poller[armkubernetesconfiguration.FluxConfigurationsClientCreateOrUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armkubernetesconfiguration.FluxConfigurationsClientCreateOrUpdateResponse](token, c.armClient.Pipeline(), nil)
}

// ResumeUpdateFluxConfigurationPoller reconstructs an update FluxConfiguration poller from a resume token.
func (c *Client) ResumeUpdateFluxConfigurationPoller(token string) (*runtime.Poller[armkubernetesconfiguration.FluxConfigurationsClientUpdateResponse], error) {
	return runtime.NewPollerFromResumeToken[armkubernetesconfiguration.FluxConfigurationsClientUpdateResponse](token, c.armClient.Pipeline(), nil)
}

// ResumeDeleteFluxConfigurationPoller reconstructs a delete FluxConfiguration poller from a resume token.
func (c *Client) ResumeDeleteFluxConfigurationPoller(token string) (*runtime.Poller[armkubernetesconfiguration.FluxConfigurationsClientDeleteResponse], error) {
	return runtime.NewPollerFromResumeToken[armkubernetesconfiguration.FluxConfigurationsClientDeleteResponse](token, c.armClient.Pipeline(), nil)
}
