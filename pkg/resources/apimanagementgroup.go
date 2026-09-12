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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApiManagementGroup = "AZURE::ApiManagement::Group"

// apiManagementGroupsAPI is the armapimanagement surface used here. All
// synchronous, with ifMatch passed positionally on the PATCH and the delete.
type apiManagementGroupsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, groupID string, parameters armapimanagement.GroupCreateParameters, options *armapimanagement.GroupClientCreateOrUpdateOptions) (armapimanagement.GroupClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, groupID string, options *armapimanagement.GroupClientGetOptions) (armapimanagement.GroupClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, groupID string, ifMatch string, parameters armapimanagement.GroupUpdateParameters, options *armapimanagement.GroupClientUpdateOptions) (armapimanagement.GroupClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, groupID string, ifMatch string, options *armapimanagement.GroupClientDeleteOptions) (armapimanagement.GroupClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.GroupClientListByServiceOptions) *runtime.Pager[armapimanagement.GroupClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementGroup{
			api:    c.ApiManagementGroupClient,
			config: cfg,
		}
	})
}

// ApiManagementGroup is the provisioner for developer groups
// (Microsoft.ApiManagement/service/groups).
//
// The Consumption tier has no group store — groups belong to the developer
// portal feature set, which Consumption does not have — so this resource is
// only usable on a dedicated tier. See the schema for the doc reference.
type ApiManagementGroup struct {
	api    apiManagementGroupsAPI
	config *config.Config
}

// apiManagementGroupProps mirrors
// schema/pkl/apimanagement/apimanagementgroup.pkl.
//
// groupType rather than type: `type` collides with the resource-type field
// every formae resource already carries.
type apiManagementGroupProps struct {
	Name              string  `json:"name"`
	ResourceGroupName string  `json:"resourceGroupName"`
	ServiceName       string  `json:"serviceName"`
	DisplayName       string  `json:"displayName"`
	Description       *string `json:"description"`
	GroupType         string  `json:"groupType"`
	ExternalID        *string `json:"externalId"`
}

func apiManagementGroupIDParts(resourceID string) (rgName, serviceName, groupID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "groups")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func apiManagementGroupType(groupType string) *armapimanagement.GroupType {
	if groupType == "" {
		return nil
	}
	return to.Ptr(armapimanagement.GroupType(groupType))
}

func (g *ApiManagementGroup) buildPropertiesFromResult(group *armapimanagement.GroupContract, rgName, serviceName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
	}
	if group.ID != nil {
		props["id"] = *group.ID
	}
	if group.Name != nil {
		props["name"] = *group.Name
	}
	if gp := group.Properties; gp != nil {
		if gp.DisplayName != nil {
			props["displayName"] = *gp.DisplayName
		}
		if gp.Description != nil {
			props["description"] = *gp.Description
		}
		if gp.Type != nil {
			props["groupType"] = canonicalizeEnum(string(*gp.Type), "custom", "system", "external")
		}
		if gp.ExternalID != nil {
			props["externalId"] = *gp.ExternalID
		}
	}
	return props
}

func (g *ApiManagementGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementGroupProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.DisplayName == "" {
		return nil, fmt.Errorf("displayName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armapimanagement.GroupCreateParameters{
		Properties: &armapimanagement.GroupCreateParametersProperties{
			DisplayName: to.Ptr(props.DisplayName),
			Description: props.Description,
			Type:        apiManagementGroupType(props.GroupType),
			ExternalID:  props.ExternalID,
		},
	}

	result, err := g.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name, params, nil)
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
	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.GroupContract,
		props.ResourceGroupName, props.ServiceName))
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

func (g *ApiManagementGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, groupID, err := apiManagementGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := g.api.Get(ctx, rgName, serviceName, groupID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.GroupContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementGroup,
		Properties:   string(propsJSON),
	}, nil
}

func (g *ApiManagementGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, groupID, err := apiManagementGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementGroupProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.GroupUpdateParametersProperties{
		Description: props.Description,
		Type:        apiManagementGroupType(props.GroupType),
		ExternalID:  props.ExternalID,
	}
	if props.DisplayName != "" {
		updateProps.DisplayName = to.Ptr(props.DisplayName)
	}

	result, err := g.api.Update(ctx, rgName, serviceName, groupID, apimIfMatchAny,
		armapimanagement.GroupUpdateParameters{Properties: updateProps}, nil)
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

	propsJSON, err := json.Marshal(g.buildPropertiesFromResult(&result.GroupContract, rgName, serviceName))
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

func (g *ApiManagementGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, groupID, err := apiManagementGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := g.api.Delete(ctx, rgName, serviceName, groupID, apimIfMatchAny, nil); err != nil &&
		!isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: group writes are synchronous.
func (g *ApiManagementGroup) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of groups.
func (g *ApiManagementGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := g.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management groups: %w", err)
		}
		for _, group := range page.Value {
			if group.ID != nil {
				nativeIDs = append(nativeIDs, *group.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
