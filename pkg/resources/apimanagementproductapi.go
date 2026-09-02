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

const ResourceTypeApiManagementProductApi = "AZURE::ApiManagement::ProductApi"

// apiManagementProductAPIsAPI is the armapimanagement surface used here.
//
// Note what is NOT here: there is no Get and no request body. A link's PUT
// carries nothing, and ARM's read verb is CheckEntityExists, which answers with
// a bare bool. ListByProduct answers with the API contracts, whose ids are the
// APIs' own ids rather than the link's, so the link id is composed rather than
// read out of the response.
type apiManagementProductAPIsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, productID string, apiID string, options *armapimanagement.ProductAPIClientCreateOrUpdateOptions) (armapimanagement.ProductAPIClientCreateOrUpdateResponse, error)
	CheckEntityExists(ctx context.Context, resourceGroupName string, serviceName string, productID string, apiID string, options *armapimanagement.ProductAPIClientCheckEntityExistsOptions) (armapimanagement.ProductAPIClientCheckEntityExistsResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, productID string, apiID string, options *armapimanagement.ProductAPIClientDeleteOptions) (armapimanagement.ProductAPIClientDeleteResponse, error)
	NewListByProductPager(resourceGroupName string, serviceName string, productID string, options *armapimanagement.ProductAPIClientListByProductOptions) *runtime.Pager[armapimanagement.ProductAPIClientListByProductResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementProductApi, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementProductApi{
			api:    c.ApiManagementProductAPIClient,
			config: cfg,
		}
	})
}

// ApiManagementProductApi provisions the membership of one API in one product
// (Microsoft.ApiManagement/service/products/apis). It is a pure link: no
// properties beyond the names of the two ends.
type ApiManagementProductApi struct {
	api    apiManagementProductAPIsAPI
	config *config.Config
}

// apiManagementProductApiProps mirrors
// schema/pkl/apimanagement/apimanagementproductapi.pkl.
type apiManagementProductApiProps struct {
	ResourceGroupName string `json:"resourceGroupName"`
	ServiceName       string `json:"serviceName"`
	ProductName       string `json:"productName"`
	APIName           string `json:"apiName"`
}

func apiManagementProductApiIDParts(resourceID string) (rgName, serviceName, productID, apiID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "products", "apis")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

func (l *ApiManagementProductApi) nativeID(rgName, serviceName, productID, apiID string) string {
	return fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/products/%s/apis/%s",
		l.config.SubscriptionId, rgName, serviceName, productID, apiID)
}

func apiManagementProductApiProperties(rgName, serviceName, productID, apiID, nativeID string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
		"productName":       productID,
		"apiName":           apiID,
	}
	if nativeID != "" {
		props["id"] = nativeID
	}
	return props
}

func (l *ApiManagementProductApi) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementProductApiProps
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
	if props.APIName == "" {
		return nil, fmt.Errorf("apiName is required")
	}

	if _, err := l.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName,
		props.ProductName, props.APIName, nil); err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	// The response carries the API contract, whose ID is the API's own id, not
	// the link's. The link id is composed from the four names instead.
	nativeID := l.nativeID(props.ResourceGroupName, props.ServiceName, props.ProductName, props.APIName)
	propsJSON, err := json.Marshal(apiManagementProductApiProperties(props.ResourceGroupName,
		props.ServiceName, props.ProductName, props.APIName, nativeID))
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
func (l *ApiManagementProductApi) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, productID, apiID, err := apiManagementProductApiIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := l.api.CheckEntityExists(ctx, rgName, serviceName, productID, apiID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	if !result.Success {
		return &resource.ReadResult{ErrorCode: resource.OperationErrorCodeNotFound}, nil
	}

	propsJSON, err := json.Marshal(apiManagementProductApiProperties(rgName, serviceName,
		productID, apiID, request.NativeID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementProductApi,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the link, which ARM treats as idempotent. Every field is
// createOnly, so formae replaces rather than updates when one changes; this
// exists so a reconcile of an unchanged link is a no-op rather than an error.
func (l *ApiManagementProductApi) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, productID, apiID, err := apiManagementProductApiIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := l.api.CreateOrUpdate(ctx, rgName, serviceName, productID, apiID, nil); err != nil {
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

	propsJSON, err := json.Marshal(apiManagementProductApiProperties(rgName, serviceName,
		productID, apiID, request.NativeID))
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

func (l *ApiManagementProductApi) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, productID, apiID, err := apiManagementProductApiIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := l.api.Delete(ctx, rgName, serviceName, productID, apiID, nil); err != nil &&
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
func (l *ApiManagementProductApi) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs the resource group, the service and the product. The pager hands
// back API contracts, so each link id is composed from the API's name.
func (l *ApiManagementProductApi) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
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
			return nil, fmt.Errorf("failed to list api management product apis: %w", err)
		}
		for _, api := range page.Value {
			if api.Name == nil {
				continue
			}
			nativeIDs = append(nativeIDs, l.nativeID(rgName, serviceName, productName, *api.Name))
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
