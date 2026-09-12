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

const ResourceTypeApiManagementApiOperationPolicy = "AZURE::ApiManagement::ApiOperationPolicy"

// apiManagementAPIOperationPoliciesAPI is the armapimanagement surface used
// here. All synchronous, no PATCH verb, and ListByOperation answers with a
// collection rather than a pager because there is at most one policy per
// operation.
type apiManagementAPIOperationPoliciesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, apiID string, operationID string, policyID armapimanagement.PolicyIDName, parameters armapimanagement.PolicyContract, options *armapimanagement.APIOperationPolicyClientCreateOrUpdateOptions) (armapimanagement.APIOperationPolicyClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, apiID string, operationID string, policyID armapimanagement.PolicyIDName, options *armapimanagement.APIOperationPolicyClientGetOptions) (armapimanagement.APIOperationPolicyClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, apiID string, operationID string, policyID armapimanagement.PolicyIDName, ifMatch string, options *armapimanagement.APIOperationPolicyClientDeleteOptions) (armapimanagement.APIOperationPolicyClientDeleteResponse, error)
	ListByOperation(ctx context.Context, resourceGroupName string, serviceName string, apiID string, operationID string, options *armapimanagement.APIOperationPolicyClientListByOperationOptions) (armapimanagement.APIOperationPolicyClientListByOperationResponse, error)
}

func init() {
	registry.Register(ResourceTypeApiManagementApiOperationPolicy, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementApiOperationPolicy{
			api:    c.ApiManagementAPIOperationPolicyClient,
			config: cfg,
		}
	})
}

// ApiManagementApiOperationPolicy provisions the policy of one API operation
// (Microsoft.ApiManagement/service/apis/operations/policies/policy). The ARM
// name is always "policy", so the resource has no name property.
type ApiManagementApiOperationPolicy struct {
	api    apiManagementAPIOperationPoliciesAPI
	config *config.Config
}

// apiManagementApiOperationPolicyProps mirrors
// schema/pkl/apimanagement/apimanagementapioperationpolicy.pkl.
type apiManagementApiOperationPolicyProps struct {
	ResourceGroupName string `json:"resourceGroupName"`
	ServiceName       string `json:"serviceName"`
	APIName           string `json:"apiName"`
	OperationName     string `json:"operationName"`
	apimPolicyBodyProps
}

func apiManagementApiOperationPolicyIDParts(resourceID string) (rgName, serviceName, apiID, operationID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "apis", "operations", "policies")
	if err != nil {
		return "", "", "", "", err
	}
	return rgName, names[0], names[1], names[2], nil
}

func (p *ApiManagementApiOperationPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementApiOperationPolicyProps
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
	if props.OperationName == "" {
		return nil, fmt.Errorf("operationName is required")
	}
	if props.Value == "" {
		return nil, fmt.Errorf("value is required")
	}

	result, err := p.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, props.APIName,
		props.OperationName, armapimanagement.PolicyIDNamePolicy, apimPolicyContract(props.apimPolicyBodyProps), nil)
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

	nativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/apis/%s/operations/%s/policies/%s",
		p.config.SubscriptionId, props.ResourceGroupName, props.ServiceName, props.APIName, props.OperationName, apimPolicyName)
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

func (p *ApiManagementApiOperationPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, apiID, operationID, err := apiManagementApiOperationPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, serviceName, apiID, operationID, armapimanagement.PolicyIDNamePolicy, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
		"apiName":           apiID,
		"operationName":     operationID,
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
		ResourceType: ResourceTypeApiManagementApiOperationPolicy,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through CreateOrUpdate: a policy has no PATCH verb.
func (p *ApiManagementApiOperationPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, apiID, operationID, err := apiManagementApiOperationPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementApiOperationPolicyProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Value == "" {
		return nil, fmt.Errorf("value is required")
	}
	props.ResourceGroupName, props.ServiceName = rgName, serviceName
	props.APIName, props.OperationName = apiID, operationID

	if _, err := p.api.CreateOrUpdate(ctx, rgName, serviceName, apiID, operationID,
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

func (p *ApiManagementApiOperationPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, apiID, operationID, err := apiManagementApiOperationPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := p.api.Delete(ctx, rgName, serviceName, apiID, operationID,
		armapimanagement.PolicyIDNamePolicy, apimIfMatchAny, nil); err != nil && !isDeleteSuccessError(err) {
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
func (p *ApiManagementApiOperationPolicy) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires the whole parent chain down to the operation: ARM has no
// API-wide listing of operation policies.
func (p *ApiManagementApiOperationPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	apiName := request.AdditionalProperties["apiName"]
	operationName := request.AdditionalProperties["operationName"]
	if rgName == "" || serviceName == "" || apiName == "" || operationName == "" {
		return &resource.ListResult{}, nil
	}

	result, err := p.api.ListByOperation(ctx, rgName, serviceName, apiName, operationName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list api management api operation policies: %w", err)
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
func (p *ApiManagementApiOperationPolicy) writeBackProperties(props apiManagementApiOperationPolicyProps, nativeID string) map[string]any {
	out := map[string]any{
		"resourceGroupName": props.ResourceGroupName,
		"serviceName":       props.ServiceName,
		"apiName":           props.APIName,
		"operationName":     props.OperationName,
	}
	if nativeID != "" {
		out["id"] = nativeID
	}
	apimPolicyWriteBackProps(out, props.apimPolicyBodyProps)
	return out
}
