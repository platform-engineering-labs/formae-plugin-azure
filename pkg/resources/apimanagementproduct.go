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

const ResourceTypeApiManagementProduct = "AZURE::ApiManagement::Product"

// apiManagementProductsAPI is the armapimanagement surface used here. All
// synchronous, with ifMatch passed positionally on the PATCH and the delete.
type apiManagementProductsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, productID string, parameters armapimanagement.ProductContract, options *armapimanagement.ProductClientCreateOrUpdateOptions) (armapimanagement.ProductClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, productID string, options *armapimanagement.ProductClientGetOptions) (armapimanagement.ProductClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, productID string, ifMatch string, parameters armapimanagement.ProductUpdateParameters, options *armapimanagement.ProductClientUpdateOptions) (armapimanagement.ProductClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, productID string, ifMatch string, options *armapimanagement.ProductClientDeleteOptions) (armapimanagement.ProductClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.ProductClientListByServiceOptions) *runtime.Pager[armapimanagement.ProductClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementProduct, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementProduct{
			api:    c.ApiManagementProductClient,
			config: cfg,
		}
	})
}

// ApiManagementProduct is the provisioner for API Management products
// (Microsoft.ApiManagement/service/products).
type ApiManagementProduct struct {
	api    apiManagementProductsAPI
	config *config.Config
}

// apiManagementProductProps mirrors
// schema/pkl/apimanagement/apimanagementproduct.pkl.
type apiManagementProductProps struct {
	Name                 string  `json:"name"`
	ResourceGroupName    string  `json:"resourceGroupName"`
	ServiceName          string  `json:"serviceName"`
	DisplayName          string  `json:"displayName"`
	Description          *string `json:"description"`
	Terms                *string `json:"terms"`
	SubscriptionRequired *bool   `json:"subscriptionRequired"`
	ApprovalRequired     *bool   `json:"approvalRequired"`
	SubscriptionsLimit   *int32  `json:"subscriptionsLimit"`
	State                string  `json:"state"`
}

func apiManagementProductIDParts(resourceID string) (rgName, serviceName, productID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "products")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func apiManagementProductState(state string) *armapimanagement.ProductState {
	if state == "" {
		return nil
	}
	return to.Ptr(armapimanagement.ProductState(state))
}

func (p *ApiManagementProduct) buildPropertiesFromResult(product *armapimanagement.ProductContract, rgName, serviceName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
	}
	if product.ID != nil {
		props["id"] = *product.ID
	}
	if product.Name != nil {
		props["name"] = *product.Name
	}
	if pp := product.Properties; pp != nil {
		if pp.DisplayName != nil {
			props["displayName"] = *pp.DisplayName
		}
		if pp.Description != nil {
			props["description"] = *pp.Description
		}
		if pp.Terms != nil {
			props["terms"] = *pp.Terms
		}
		if pp.SubscriptionRequired != nil {
			props["subscriptionRequired"] = *pp.SubscriptionRequired
		}
		if pp.ApprovalRequired != nil {
			props["approvalRequired"] = *pp.ApprovalRequired
		}
		if pp.SubscriptionsLimit != nil {
			props["subscriptionsLimit"] = *pp.SubscriptionsLimit
		}
		if pp.State != nil {
			props["state"] = canonicalizeEnum(string(*pp.State), "published", "notPublished")
		}
	}
	return props
}

func (p *ApiManagementProduct) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementProductProps
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

	params := armapimanagement.ProductContract{
		Properties: &armapimanagement.ProductContractProperties{
			DisplayName:          to.Ptr(props.DisplayName),
			Description:          props.Description,
			Terms:                props.Terms,
			SubscriptionRequired: props.SubscriptionRequired,
			ApprovalRequired:     props.ApprovalRequired,
			SubscriptionsLimit:   props.SubscriptionsLimit,
			State:                apiManagementProductState(props.State),
		},
	}

	result, err := p.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name, params, nil)
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
	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.ProductContract,
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

func (p *ApiManagementProduct) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, productID, err := apiManagementProductIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, serviceName, productID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.ProductContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementProduct,
		Properties:   string(propsJSON),
	}, nil
}

func (p *ApiManagementProduct) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, productID, err := apiManagementProductIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementProductProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.ProductUpdateProperties{
		Description:          props.Description,
		Terms:                props.Terms,
		SubscriptionRequired: props.SubscriptionRequired,
		ApprovalRequired:     props.ApprovalRequired,
		SubscriptionsLimit:   props.SubscriptionsLimit,
		State:                apiManagementProductState(props.State),
	}
	if props.DisplayName != "" {
		updateProps.DisplayName = to.Ptr(props.DisplayName)
	}

	result, err := p.api.Update(ctx, rgName, serviceName, productID, apimIfMatchAny,
		armapimanagement.ProductUpdateParameters{Properties: updateProps}, nil)
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

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.ProductContract, rgName, serviceName))
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

// Delete passes deleteSubscriptions=true. Without it ARM refuses to delete a
// product that still has subscriptions against it, and those subscriptions are
// not resources this plugin can see from here.
func (p *ApiManagementProduct) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, productID, err := apiManagementProductIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	opts := &armapimanagement.ProductClientDeleteOptions{DeleteSubscriptions: to.Ptr(true)}
	if _, err := p.api.Delete(ctx, rgName, serviceName, productID, apimIfMatchAny, opts); err != nil &&
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

// Status is never reached with real work to do: product writes are synchronous.
func (p *ApiManagementProduct) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of products.
func (p *ApiManagementProduct) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := p.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management products: %w", err)
		}
		for _, product := range page.Value {
			if product.ID != nil {
				nativeIDs = append(nativeIDs, *product.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
