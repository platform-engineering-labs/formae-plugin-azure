// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
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
	Config                       *config.Config
	ResourceGroupsClient         *armresources.ResourceGroupsClient
	VirtualNetworksClient        *armnetwork.VirtualNetworksClient
	SubnetsClient                *armnetwork.SubnetsClient
	SecurityGroupsClient         *armnetwork.SecurityGroupsClient
	PublicIPAddressesClient      *armnetwork.PublicIPAddressesClient
	InterfacesClient             *armnetwork.InterfacesClient
	VirtualMachinesClient        *armcompute.VirtualMachinesClient
	StorageAccountsClient        *armstorage.AccountsClient
	VaultsClient                 *armkeyvault.VaultsClient
	ManagedClustersClient        *armcontainerservice.ManagedClustersClient
	RegistriesClient             *armcontainerregistry.RegistriesClient
	UserAssignedIdentitiesClient *armmsi.UserAssignedIdentitiesClient
	RoleAssignmentsClient        *armauthorization.RoleAssignmentsClient
	FlexibleServersClient        *armpostgresqlflexibleservers.ServersClient
	FirewallRulesClient          *armpostgresqlflexibleservers.FirewallRulesClient
	credential                   azcore.TokenCredential
	clientOptions                *arm.ClientOptions
	// armClient provides access to the pipeline for resuming pollers
	armClient *arm.Client
}

// NewClient creates a new Azure client wrapper
func NewClient(cfg *config.Config) (*Client, error) {
	ctx := context.Background()
	cred, err := cfg.ToAzureCredential(ctx)
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

	subnetClient, err := armnetwork.NewSubnetsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	securityGroupsClient, err := armnetwork.NewSecurityGroupsClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	publicIPAddressesClient, err := armnetwork.NewPublicIPAddressesClient(cfg.SubscriptionId, cred, clientOptions)
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

	storageAccountsClient, err := armstorage.NewAccountsClient(cfg.SubscriptionId, cred, clientOptions)
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

	registriesClient, err := armcontainerregistry.NewRegistriesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	userAssignedIdentitiesClient, err := armmsi.NewUserAssignedIdentitiesClient(cfg.SubscriptionId, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	roleAssignmentsClient, err := armauthorization.NewRoleAssignmentsClient(cfg.SubscriptionId, cred, clientOptions)
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

	// Create a low-level ARM client for pipeline access (needed for resuming pollers)
	armClient, err := arm.NewClient(moduleName, moduleVersion, cred, clientOptions)
	if err != nil {
		return nil, err
	}

	return &Client{
		Config:                       cfg,
		ResourceGroupsClient:         rgClient,
		VirtualNetworksClient:        vnetClient,
		SubnetsClient:                subnetClient,
		SecurityGroupsClient:         securityGroupsClient,
		PublicIPAddressesClient:      publicIPAddressesClient,
		InterfacesClient:             interfacesClient,
		VirtualMachinesClient:        virtualMachinesClient,
		StorageAccountsClient:        storageAccountsClient,
		VaultsClient:                 vaultsClient,
		ManagedClustersClient:        managedClustersClient,
		RegistriesClient:             registriesClient,
		UserAssignedIdentitiesClient: userAssignedIdentitiesClient,
		RoleAssignmentsClient:        roleAssignmentsClient,
		FlexibleServersClient:        flexibleServersClient,
		FirewallRulesClient:          firewallRulesClient,
		credential:                   cred,
		clientOptions:                clientOptions,
		armClient:                    armClient,
	}, nil
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
