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

const ResourceTypeNetworkManagerAdminRuleCollection = "AZURE::Network::NetworkManagerAdminRuleCollection"

// networkManagerAdminRuleCollectionsAPI is the
// armnetwork.AdminRuleCollectionsClient surface used here. CreateOrUpdate doubles
// as the update verb and is synchronous; only Delete is an LRO.
type networkManagerAdminRuleCollectionsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, ruleCollection armnetwork.AdminRuleCollection, options *armnetwork.AdminRuleCollectionsClientCreateOrUpdateOptions) (armnetwork.AdminRuleCollectionsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, options *armnetwork.AdminRuleCollectionsClientGetOptions) (armnetwork.AdminRuleCollectionsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, networkManagerName string, configurationName string, ruleCollectionName string, options *armnetwork.AdminRuleCollectionsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.AdminRuleCollectionsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, networkManagerName string, configurationName string, options *armnetwork.AdminRuleCollectionsClientListOptions) *runtime.Pager[armnetwork.AdminRuleCollectionsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeNetworkManagerAdminRuleCollection, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetworkManagerAdminRuleCollection{
			api:      c.NetworkManagerAdminRuleCollectionsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// NetworkManagerAdminRuleCollection is the provisioner for admin rule collections
// (Microsoft.Network/networkManagers/securityAdminConfigurations/ruleCollections).
//
// The collection is the middle level of the configuration → collection → rule
// chain. It carries no verdict itself: its job is to bind the rules inside it to
// the network groups named in appliesToGroups.
type NetworkManagerAdminRuleCollection struct {
	api      networkManagerAdminRuleCollectionsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// adminRuleCollectionGroupItemProps mirrors the AdminRuleCollectionGroupItem class
// in schema/pkl/network/networkmanageradminrulecollection.pkl.
type adminRuleCollectionGroupItemProps struct {
	NetworkGroupID string `json:"networkGroupId"`
}

// networkManagerAdminRuleCollectionProps mirrors
// schema/pkl/network/networkmanageradminrulecollection.pkl.
type networkManagerAdminRuleCollectionProps struct {
	Name                           string                              `json:"name"`
	ResourceGroupName              string                              `json:"resourceGroupName"`
	NetworkManagerName             string                              `json:"networkManagerName"`
	SecurityAdminConfigurationName string                              `json:"securityAdminConfigurationName"`
	AppliesToGroups                []adminRuleCollectionGroupItemProps `json:"appliesToGroups"`
	Description                    *string                             `json:"description"`
}

func networkManagerAdminRuleCollectionIDParts(resourceID string) (rgName, managerName, configName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "networkmanagers", "securityadminconfigurations", "rulecollections")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names["networkmanagers"], names["securityadminconfigurations"], names["rulecollections"], nil
}

func buildAdminRuleCollectionParams(props *networkManagerAdminRuleCollectionProps) (armnetwork.AdminRuleCollection, error) {
	if len(props.AppliesToGroups) == 0 {
		return armnetwork.AdminRuleCollection{}, fmt.Errorf("appliesToGroups is required")
	}

	groups := make([]*armnetwork.ManagerSecurityGroupItem, 0, len(props.AppliesToGroups))
	for i := range props.AppliesToGroups {
		if props.AppliesToGroups[i].NetworkGroupID == "" {
			return armnetwork.AdminRuleCollection{}, fmt.Errorf("appliesToGroups.networkGroupId is required")
		}
		groups = append(groups, &armnetwork.ManagerSecurityGroupItem{
			NetworkGroupID: to.Ptr(props.AppliesToGroups[i].NetworkGroupID),
		})
	}

	collectionProps := &armnetwork.AdminRuleCollectionPropertiesFormat{AppliesToGroups: groups}
	if props.Description != nil && *props.Description != "" {
		collectionProps.Description = to.Ptr(*props.Description)
	}

	return armnetwork.AdminRuleCollection{Properties: collectionProps}, nil
}

func (r *NetworkManagerAdminRuleCollection) buildPropertiesFromResult(collection *armnetwork.AdminRuleCollection, rgName, managerName, configName string) map[string]any {
	props := make(map[string]any)

	// All three parents come from the native ID: ARM echoes none of them on the
	// collection body.
	props["resourceGroupName"] = rgName
	props["networkManagerName"] = managerName
	props["securityAdminConfigurationName"] = configName

	if collection.ID != nil {
		props["id"] = *collection.ID
	}
	if collection.Name != nil {
		props["name"] = *collection.Name
	}

	if p := collection.Properties; p != nil {
		if len(p.AppliesToGroups) > 0 {
			groups := make([]map[string]any, 0, len(p.AppliesToGroups))
			for _, group := range p.AppliesToGroups {
				if group == nil || group.NetworkGroupID == nil {
					continue
				}
				groups = append(groups, map[string]any{"networkGroupId": *group.NetworkGroupID})
			}
			props["appliesToGroups"] = groups
		}
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		// provisioningState and resourceGuid are dropped: neither is desired state.
	}

	return props
}

func (r *NetworkManagerAdminRuleCollection) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props networkManagerAdminRuleCollectionProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.NetworkManagerName == "" {
		return nil, fmt.Errorf("networkManagerName is required")
	}
	if props.SecurityAdminConfigurationName == "" {
		return nil, fmt.Errorf("securityAdminConfigurationName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := buildAdminRuleCollectionParams(&props)
	if err != nil {
		return nil, err
	}

	result, err := r.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.NetworkManagerName,
		props.SecurityAdminConfigurationName, name, params, nil)
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
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.AdminRuleCollection,
		props.ResourceGroupName, props.NetworkManagerName, props.SecurityAdminConfigurationName))
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

func (r *NetworkManagerAdminRuleCollection) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, managerName, configName, name, err := networkManagerAdminRuleCollectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, managerName, configName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.AdminRuleCollection, rgName, managerName, configName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNetworkManagerAdminRuleCollection,
		Properties:   string(propsJSON),
	}, nil
}

func (r *NetworkManagerAdminRuleCollection) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, managerName, configName, name, err := networkManagerAdminRuleCollectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props networkManagerAdminRuleCollectionProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params, err := buildAdminRuleCollectionParams(&props)
	if err != nil {
		return nil, err
	}

	result, err := r.api.CreateOrUpdate(ctx, rgName, managerName, configName, name, params, nil)
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

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.AdminRuleCollection, rgName, managerName, configName))
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

// Delete removes the collection and its rules. Force is set for the same reason as
// on the parent configuration: it is the only way past ARM's refusal to remove a
// collection belonging to a deployed (committed) configuration.
func (r *NetworkManagerAdminRuleCollection) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, managerName, configName, name, err := networkManagerAdminRuleCollectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := r.api.BeginDelete(ctx, rgName, managerName, configName, name,
		&armnetwork.AdminRuleCollectionsClientBeginDeleteOptions{Force: to.Ptr(true)})
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
func (r *NetworkManagerAdminRuleCollection) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.AdminRuleCollectionsClientDeleteResponse], error) {
				return resumePoller[armnetwork.AdminRuleCollectionsClientDeleteResponse](r.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// List enumerates the rule collections of one security admin configuration. There
// is no subscription-wide pager, so without all three parents there is nothing to
// enumerate.
func (r *NetworkManagerAdminRuleCollection) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	managerName := request.AdditionalProperties["networkManagerName"]
	configName := request.AdditionalProperties["securityAdminConfigurationName"]
	if rgName == "" || managerName == "" || configName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := r.api.NewListPager(rgName, managerName, configName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list admin rule collections: %w", err)
		}
		for _, collection := range page.Value {
			if collection != nil && collection.ID != nil {
				nativeIDs = append(nativeIDs, *collection.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
