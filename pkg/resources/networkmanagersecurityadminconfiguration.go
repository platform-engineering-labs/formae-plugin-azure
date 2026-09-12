// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeNetworkManagerSecurityAdminConfiguration = "AZURE::Network::NetworkManagerSecurityAdminConfiguration"

// networkManagerSecurityAdminConfigurationsAPI is the
// armnetwork.SecurityAdminConfigurationsClient surface used here. CreateOrUpdate
// doubles as the update verb and is synchronous; only Delete is an LRO, and its
// options struct carries the `force` query parameter ARM needs to remove a
// configuration that has been deployed.
type networkManagerSecurityAdminConfigurationsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, securityAdminConfiguration armnetwork.SecurityAdminConfiguration, options *armnetwork.SecurityAdminConfigurationsClientCreateOrUpdateOptions) (armnetwork.SecurityAdminConfigurationsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, options *armnetwork.SecurityAdminConfigurationsClientGetOptions) (armnetwork.SecurityAdminConfigurationsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, options *armnetwork.SecurityAdminConfigurationsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SecurityAdminConfigurationsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, networkManagerName string, options *armnetwork.SecurityAdminConfigurationsClientListOptions) *runtime.Pager[armnetwork.SecurityAdminConfigurationsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkManagerSecurityAdminConfiguration, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkManagerSecurityAdminConfiguration{
			api:      c.NetworkManagerSecurityAdminConfigurationsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NetworkManagerSecurityAdminConfiguration is the provisioner for security admin
// configurations
// (Microsoft.Network/networkManagers/securityAdminConfigurations).
//
// The configuration is the container for admin rule collections, which hold the
// rules that outrank network security groups. Like a connectivity configuration it
// is INERT until committed, and this plugin never commits one — that is what keeps
// it deletable.
type NetworkManagerSecurityAdminConfiguration struct {
	api      networkManagerSecurityAdminConfigurationsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// networkManagerSecurityAdminConfigurationProps mirrors
// schema/pkl/network/networkmanagersecurityadminconfiguration.pkl.
type networkManagerSecurityAdminConfigurationProps struct {
	Name                                    string   `json:"name"`
	ResourceGroupName                       string   `json:"resourceGroupName"`
	NetworkManagerName                      string   `json:"networkManagerName"`
	ApplyOnNetworkIntentPolicyBasedServices []string `json:"applyOnNetworkIntentPolicyBasedServices"`
	Description                             *string  `json:"description"`
}

func networkManagerSecurityAdminConfigurationIDParts(resourceID string) (rgName, managerName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "networkmanagers", "securityadminconfigurations")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["networkmanagers"], names["securityadminconfigurations"], nil
}

func buildSecurityAdminConfigurationParams(props *networkManagerSecurityAdminConfigurationProps) armnetwork.SecurityAdminConfiguration {
	configProps := &armnetwork.SecurityAdminConfigurationPropertiesFormat{}

	if len(props.ApplyOnNetworkIntentPolicyBasedServices) > 0 {
		services := make([]*armnetwork.NetworkIntentPolicyBasedService, 0, len(props.ApplyOnNetworkIntentPolicyBasedServices))
		for _, svc := range props.ApplyOnNetworkIntentPolicyBasedServices {
			services = append(services, to.Ptr(armnetwork.NetworkIntentPolicyBasedService(svc)))
		}
		configProps.ApplyOnNetworkIntentPolicyBasedServices = services
	}
	if props.Description != nil && *props.Description != "" {
		configProps.Description = to.Ptr(*props.Description)
	}

	return armnetwork.SecurityAdminConfiguration{Properties: configProps}
}

func (s *NetworkManagerSecurityAdminConfiguration) buildPropertiesFromResult(config *armnetwork.SecurityAdminConfiguration, rgName, managerName string) map[string]any {
	props := make(map[string]any)

	// Both parents come from the native ID: ARM echoes neither on the body.
	props["resourceGroupName"] = rgName
	props["networkManagerName"] = managerName

	if config.ID != nil {
		props["id"] = *config.ID
	}
	if config.Name != nil {
		props["name"] = *config.Name
	}

	if p := config.Properties; p != nil {
		if len(p.ApplyOnNetworkIntentPolicyBasedServices) > 0 {
			services := make([]string, 0, len(p.ApplyOnNetworkIntentPolicyBasedServices))
			for _, svc := range p.ApplyOnNetworkIntentPolicyBasedServices {
				if svc != nil {
					services = append(services, canonicalizeEnum(string(*svc), "All", "AllowRulesOnly", "None"))
				}
			}
			props["applyOnNetworkIntentPolicyBasedServices"] = services
		}
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		// provisioningState and resourceGuid are dropped: neither is desired state.
	}

	return props
}

func (s *NetworkManagerSecurityAdminConfiguration) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props networkManagerSecurityAdminConfigurationProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.NetworkManagerName == "" {
		return nil, fmt.Errorf("networkManagerName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	result, err := s.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.NetworkManagerName, name,
		buildSecurityAdminConfigurationParams(&props), nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.SecurityAdminConfiguration,
		props.ResourceGroupName, props.NetworkManagerName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (s *NetworkManagerSecurityAdminConfiguration) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, managerName, name, err := networkManagerSecurityAdminConfigurationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, managerName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.SecurityAdminConfiguration, rgName, managerName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkManagerSecurityAdminConfiguration,
		Properties:   string(propsJSON),
	}, nil
}

func (s *NetworkManagerSecurityAdminConfiguration) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, managerName, name, err := networkManagerSecurityAdminConfigurationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props networkManagerSecurityAdminConfigurationProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	result, err := s.api.CreateOrUpdate(ctx, rgName, managerName, name,
		buildSecurityAdminConfigurationParams(&props), nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.SecurityAdminConfiguration, rgName, managerName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           request.NativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

// Delete removes the configuration and its rule collections.
//
// Force is set deliberately: the delete verb's `force` query parameter is the only
// way past ARM's refusal to remove a configuration that has been deployed
// (committed) to a region, and without it such a configuration is undeletable
// through this plugin — commits are not modelled, so there would be no way to
// un-deploy it either. This plugin never commits a configuration, so force only
// matters for one someone committed by hand.
func (s *NetworkManagerSecurityAdminConfiguration) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, managerName, name, err := networkManagerSecurityAdminConfigurationIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := s.api.BeginDelete(ctx, rgName, managerName, name,
		&armnetwork.SecurityAdminConfigurationsClientBeginDeleteOptions{Force: to.Ptr(true)})
	if err != nil {
		if isDeleteSuccessError(err) {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       operationErrorCode(err),
					StatusMessage:   err.Error(),
				},
			}, nil
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Status only ever sees a delete: create and update are synchronous.
func (s *NetworkManagerSecurityAdminConfiguration) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.SecurityAdminConfigurationsClientDeleteResponse], error) {
				return resumePoller[armnetwork.SecurityAdminConfigurationsClientDeleteResponse](s.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// List enumerates the security admin configurations of one manager. There is no
// subscription-wide pager, so without both parents there is nothing to enumerate.
func (s *NetworkManagerSecurityAdminConfiguration) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	managerName := request.AdditionalProperties["networkManagerName"]
	if rgName == "" || managerName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := s.api.NewListPager(rgName, managerName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list security admin configurations: %w", err)
		}
		for _, config := range page.Value {
			if config != nil && config.ID != nil {
				nativeIDs = append(nativeIDs, *config.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
