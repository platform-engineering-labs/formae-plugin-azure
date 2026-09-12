// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApiManagementProductGroup = "AZURE::ApiManagement::ProductGroup"

// apiManagementProductGroupsAPI is the armapimanagement surface used here.
//
// Note what is NOT here: there is no Get and no request body. A link's PUT
// carries nothing, and ARM's read verb is CheckEntityExists, which answers with
// a bare bool. ListByProduct answers with the group contracts, whose ids are
// the groups' own ids rather than the link's, so the link id is composed rather
// than read out of the response.
type apiManagementProductGroupsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, productID string, groupID string, options *armapimanagement.ProductGroupClientCreateOrUpdateOptions) (armapimanagement.ProductGroupClientCreateOrUpdateResponse, error)
	CheckEntityExists(ctx context.Context, resourceGroupName string, serviceName string, productID string, groupID string, options *armapimanagement.ProductGroupClientCheckEntityExistsOptions) (armapimanagement.ProductGroupClientCheckEntityExistsResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, productID string, groupID string, options *armapimanagement.ProductGroupClientDeleteOptions) (armapimanagement.ProductGroupClientDeleteResponse, error)
	NewListByProductPager(resourceGroupName string, serviceName string, productID string, options *armapimanagement.ProductGroupClientListByProductOptions) *runtime.Pager[armapimanagement.ProductGroupClientListByProductResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementProductGroup, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementProductGroup{
			api:    c.ApiManagementProductGroupClient,
			config: cfg,
		}
	})
}

// ApiManagementProductGroup provisions the visibility of one product to one
// group (Microsoft.ApiManagement/service/products/groups). It is a pure link:
// no properties beyond the names of the two ends.
type ApiManagementProductGroup struct {
	api    apiManagementProductGroupsAPI
	config *config.Config
}

// apiManagementProductGroupProps mirrors
// schema/pkl/apimanagement/apimanagementproductgroup.pkl.
type apiManagementProductGroupProps struct {
	ResourceGroupName string `json:"resourceGroupName"`
	ServiceName       string `json:"serviceName"`
	ProductName       string `json:"productName"`
	GroupName         string `json:"groupName"`
}

func apiManagementProductGroupIDParts(resourceID string) (rgName, serviceName, productID, groupID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "products", "groups")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

func (l *ApiManagementProductGroup) nativeID(rgName, serviceName, productID, groupID string) string {
	return fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/products/%s/groups/%s",
		l.config.SubscriptionId, rgName, serviceName, productID, groupID)
}

func apiManagementProductGroupProperties(rgName, serviceName, productID, groupID, nativeID string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
		"productName":       productID,
		"groupName":         groupID,
	}
	if nativeID != "" {
		props["id"] = nativeID
	}
	return props
}

func (l *ApiManagementProductGroup) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementProductGroupProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.ProductName == "" {
		return nil, fmt.Errorf("productName is required")
	}
	if props.GroupName == "" {
		return nil, fmt.Errorf("groupName is required")
	}

	if _, err := l.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName,
		props.ProductName, props.GroupName, nil); err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	// The response carries the group contract, whose ID is the group's own id,
	// not the link's. The link id is composed from the four names instead.
	nativeID := l.nativeID(props.ResourceGroupName, props.ServiceName, props.ProductName, props.GroupName)
	propsJSON, err := json.Marshal(apiManagementProductGroupProperties(props.ResourceGroupName,
		props.ServiceName, props.ProductName, props.GroupName, nativeID))
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

// Read reports the link's existence. ARM has no Get for it: CheckEntityExists
// is a HEAD that answers with a bool, and a false answer is a NotFound as far
// as formae is concerned so that an out-of-band unlink is seen as a deletion.
func (l *ApiManagementProductGroup) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, productID, groupID, err := apiManagementProductGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := l.api.CheckEntityExists(ctx, rgName, serviceName, productID, groupID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	if !result.Success {
		return &resource.ReadResult{ErrorCode: resource.OperationErrorCodeNotFound}, nil
	}

	propsJSON, err := json.Marshal(apiManagementProductGroupProperties(rgName, serviceName,
		productID, groupID, request.NativeID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementProductGroup,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the link, which ARM treats as idempotent. Every field is
// createOnly, so formae replaces rather than updates when one changes; this
// exists so a reconcile of an unchanged link is a no-op rather than an error.
func (l *ApiManagementProductGroup) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, productID, groupID, err := apiManagementProductGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := l.api.CreateOrUpdate(ctx, rgName, serviceName, productID, groupID, nil); err != nil {
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

	propsJSON, err := json.Marshal(apiManagementProductGroupProperties(rgName, serviceName,
		productID, groupID, request.NativeID))
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

func (l *ApiManagementProductGroup) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, productID, groupID, err := apiManagementProductGroupIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := l.api.Delete(ctx, rgName, serviceName, productID, groupID, nil); err != nil &&
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

// Status is never reached with real work to do: link writes are synchronous.
func (l *ApiManagementProductGroup) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs the resource group, the service and the product. The pager hands
// back group contracts, so each link id is composed from the group's name.
func (l *ApiManagementProductGroup) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	productName := request.AdditionalProperties["productName"]
	if rgName == "" || serviceName == "" || productName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := l.api.NewListByProductPager(rgName, serviceName, productName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management product groups: %w", err)
		}
		for _, group := range page.Value {
			if group.Name == nil {
				continue
			}
			nativeIDs = append(nativeIDs, l.nativeID(rgName, serviceName, productName, *group.Name))
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
