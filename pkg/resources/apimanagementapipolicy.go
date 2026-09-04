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

const ResourceTypeApiManagementApiPolicy = "AZURE::ApiManagement::ApiPolicy"

// apiManagementAPIPoliciesAPI is the armapimanagement surface used here. All
// synchronous, no PATCH verb, and ListByAPI answers with a collection rather
// than a pager because there is at most one policy per API.
type apiManagementAPIPoliciesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, apiID string, policyID armapimanagement.PolicyIDName, parameters armapimanagement.PolicyContract, options *armapimanagement.APIPolicyClientCreateOrUpdateOptions) (armapimanagement.APIPolicyClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, apiID string, policyID armapimanagement.PolicyIDName, options *armapimanagement.APIPolicyClientGetOptions) (armapimanagement.APIPolicyClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, apiID string, policyID armapimanagement.PolicyIDName, ifMatch string, options *armapimanagement.APIPolicyClientDeleteOptions) (armapimanagement.APIPolicyClientDeleteResponse, error)
	ListByAPI(ctx context.Context, resourceGroupName string, serviceName string, apiID string, options *armapimanagement.APIPolicyClientListByAPIOptions) (armapimanagement.APIPolicyClientListByAPIResponse, error)
}

func init() {
	registry.Register(ResourceTypeApiManagementApiPolicy, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementApiPolicy{
			api:    c.ApiManagementAPIPolicyClient,
			config: cfg,
		}
	})
}

// ApiManagementApiPolicy provisions the policy of one API
// (Microsoft.ApiManagement/service/apis/policies/policy). The ARM name is
// always "policy", so the resource has no name property.
type ApiManagementApiPolicy struct {
	api    apiManagementAPIPoliciesAPI
	config *config.Config
}

// apiManagementApiPolicyProps mirrors
// schema/pkl/apimanagement/apimanagementapipolicy.pkl.
type apiManagementApiPolicyProps struct {
	ResourceGroupName string `json:"resourceGroupName"`
	ServiceName       string `json:"serviceName"`
	APIName           string `json:"apiName"`
	apimPolicyBodyProps
}

func apiManagementApiPolicyIDParts(resourceID string) (rgName, serviceName, apiID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "apis", "policies")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func (p *ApiManagementApiPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementApiPolicyProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.APIName == "" {
		return nil, fmt.Errorf("apiName is required")
	}
	if props.Value == "" {
		return nil, fmt.Errorf("value is required")
	}

	result, err := p.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, props.APIName,
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

	nativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/apis/%s/policies/%s",
		p.config.SubscriptionId, props.ResourceGroupName, props.ServiceName, props.APIName, apimPolicyName)
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

func (p *ApiManagementApiPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, apiID, err := apiManagementApiPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, serviceName, apiID, armapimanagement.PolicyIDNamePolicy, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
		"apiName":           apiID,
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
		ResourceType: ResourceTypeApiManagementApiPolicy,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through CreateOrUpdate: a policy has no PATCH verb.
func (p *ApiManagementApiPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, apiID, err := apiManagementApiPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementApiPolicyProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Value == "" {
		return nil, fmt.Errorf("value is required")
	}
	props.ResourceGroupName, props.ServiceName, props.APIName = rgName, serviceName, apiID

	if _, err := p.api.CreateOrUpdate(ctx, rgName, serviceName, apiID,
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

func (p *ApiManagementApiPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, apiID, err := apiManagementApiPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := p.api.Delete(ctx, rgName, serviceName, apiID, armapimanagement.PolicyIDNamePolicy,
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
func (p *ApiManagementApiPolicy) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires the resource group, the service and the API: ARM has no
// service-wide listing of API policies.
func (p *ApiManagementApiPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	apiName := request.AdditionalProperties["apiName"]
	if rgName == "" || serviceName == "" || apiName == "" {
		return &resource.ListResult{}, nil
	}

	result, err := p.api.ListByAPI(ctx, rgName, serviceName, apiName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list api management api policies: %w", err)
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
func (p *ApiManagementApiPolicy) writeBackProperties(props apiManagementApiPolicyProps, nativeID string) map[string]any {
	out := map[string]any{
		"resourceGroupName": props.ResourceGroupName,
		"serviceName":       props.ServiceName,
		"apiName":           props.APIName,
	}
	if nativeID != "" {
		out["id"] = nativeID
	}
	apimPolicyWriteBackProps(out, props.apimPolicyBodyProps)
	return out
}
