// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApiManagementProductPolicy = "AZURE::ApiManagement::ProductPolicy"

// apiManagementProductPoliciesAPI is the armapimanagement surface used here. All
// synchronous, no PATCH verb, and ListByProduct answers with a collection rather
// than a pager because there is at most one policy per product.
type apiManagementProductPoliciesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, productID string, policyID armapimanagement.PolicyIDName, parameters armapimanagement.PolicyContract, options *armapimanagement.ProductPolicyClientCreateOrUpdateOptions) (armapimanagement.ProductPolicyClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, productID string, policyID armapimanagement.PolicyIDName, options *armapimanagement.ProductPolicyClientGetOptions) (armapimanagement.ProductPolicyClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, productID string, policyID armapimanagement.PolicyIDName, ifMatch string, options *armapimanagement.ProductPolicyClientDeleteOptions) (armapimanagement.ProductPolicyClientDeleteResponse, error)
	ListByProduct(ctx context.Context, resourceGroupName string, serviceName string, productID string, options *armapimanagement.ProductPolicyClientListByProductOptions) (armapimanagement.ProductPolicyClientListByProductResponse, error)
}

func init() {
	registry.Register(ResourceTypeApiManagementProductPolicy, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementProductPolicy{
			api:    c.ApiManagementProductPolicyClient,
			config: cfg,
		}
	})
}

// ApiManagementProductPolicy provisions the policy of one product
// (Microsoft.ApiManagement/service/products/policies/policy). The ARM name is
// always "policy", so the resource has no name property.
//
// The document handling — comparing the caller's XML canonically against ARM's
// re-serialization of it so reformatting is not read as drift — is shared with
// the other three policy resources in apimanagementpolicybody.go.
type ApiManagementProductPolicy struct {
	api    apiManagementProductPoliciesAPI
	config *config.Config
}

// apiManagementProductPolicyProps mirrors
// schema/pkl/apimanagement/apimanagementproductpolicy.pkl.
type apiManagementProductPolicyProps struct {
	ResourceGroupName string `json:"resourceGroupName"`
	ServiceName       string `json:"serviceName"`
	ProductName       string `json:"productName"`
	apimPolicyBodyProps
}

func apiManagementProductPolicyIDParts(resourceID string) (rgName, serviceName, productID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "products", "policies")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func (p *ApiManagementProductPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementProductPolicyProps
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
	if props.Value == "" {
		return nil, fmt.Errorf("value is required")
	}

	result, err := p.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, props.ProductName,
		armapimanagement.PolicyIDNamePolicy, apimPolicyContract(props.apimPolicyBodyProps), nil)
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

	nativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/products/%s/policies/%s",
		p.config.SubscriptionId, props.ResourceGroupName, props.ServiceName, props.ProductName, apimPolicyName)
	if result.ID != nil {
		nativeID = *result.ID
	}

	propsJSON, err := json.Marshal(p.writeBackProperties(props, nativeID))
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

func (p *ApiManagementProductPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, productID, err := apiManagementProductPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, serviceName, productID, armapimanagement.PolicyIDNamePolicy, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
		"productName":       productID,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	apimPolicyReadProps(props, result.Properties, request.PriorProperties)

	propsJSON, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementProductPolicy,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through CreateOrUpdate: a policy has no PATCH verb.
func (p *ApiManagementProductPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, productID, err := apiManagementProductPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementProductPolicyProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Value == "" {
		return nil, fmt.Errorf("value is required")
	}
	props.ResourceGroupName, props.ServiceName, props.ProductName = rgName, serviceName, productID

	if _, err := p.api.CreateOrUpdate(ctx, rgName, serviceName, productID,
		armapimanagement.PolicyIDNamePolicy, apimPolicyContract(props.apimPolicyBodyProps), nil); err != nil {
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

	propsJSON, err := json.Marshal(p.writeBackProperties(props, request.NativeID))
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

func (p *ApiManagementProductPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, productID, err := apiManagementProductPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := p.api.Delete(ctx, rgName, serviceName, productID, armapimanagement.PolicyIDNamePolicy,
		apimIfMatchAny, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: policy writes are synchronous.
func (p *ApiManagementProductPolicy) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires the resource group, the service and the product: ARM has no
// service-wide listing of product policies.
func (p *ApiManagementProductPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	productName := request.AdditionalProperties["productName"]
	if rgName == "" || serviceName == "" || productName == "" {
		return &resource.ListResult{}, nil
	}

	result, err := p.api.ListByProduct(ctx, rgName, serviceName, productName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list api management product policies: %w", err)
	}

	var nativeIDs []string
	for _, policy := range result.Value {
		if policy.ID != nil {
			nativeIDs = append(nativeIDs, *policy.ID)
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

// writeBackProperties is the read-back after a create or update. It reports the
// document the caller just sent rather than ARM's re-serialization of it: see
// apimanagementpolicybody.go for why the two differ.
func (p *ApiManagementProductPolicy) writeBackProperties(props apiManagementProductPolicyProps, nativeID string) map[string]any {
	out := map[string]any{
		"resourceGroupName": props.ResourceGroupName,
		"serviceName":       props.ServiceName,
		"productName":       props.ProductName,
	}
	if nativeID != "" {
		out["id"] = nativeID
	}
	apimPolicyWriteBackProps(out, props.apimPolicyBodyProps)
	return out
}
