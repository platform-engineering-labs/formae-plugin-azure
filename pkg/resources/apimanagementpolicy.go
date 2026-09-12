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

const ResourceTypeApiManagementPolicy = "AZURE::ApiManagement::Policy"

// apiManagementPoliciesAPI is the armapimanagement surface used here. All
// synchronous, and there is no PATCH: an update is another CreateOrUpdate.
// ListByService is a plain call rather than a pager — there is at most one
// service policy, so there is nothing to page.
type apiManagementPoliciesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, policyID armapimanagement.PolicyIDName, parameters armapimanagement.PolicyContract, options *armapimanagement.PolicyClientCreateOrUpdateOptions) (armapimanagement.PolicyClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, policyID armapimanagement.PolicyIDName, options *armapimanagement.PolicyClientGetOptions) (armapimanagement.PolicyClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, policyID armapimanagement.PolicyIDName, ifMatch string, options *armapimanagement.PolicyClientDeleteOptions) (armapimanagement.PolicyClientDeleteResponse, error)
	ListByService(ctx context.Context, resourceGroupName string, serviceName string, options *armapimanagement.PolicyClientListByServiceOptions) (armapimanagement.PolicyClientListByServiceResponse, error)
}

func init() {
	registry.Register(ResourceTypeApiManagementPolicy, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementPolicy{
			api:    c.ApiManagementPolicyClient,
			config: cfg,
		}
	})
}

// ApiManagementPolicy provisions the service-wide policy of an API Management
// instance (Microsoft.ApiManagement/service/policies/policy). The ARM name is
// always "policy", so the resource has no name property.
type ApiManagementPolicy struct {
	api    apiManagementPoliciesAPI
	config *config.Config
}

// apiManagementPolicyProps mirrors schema/pkl/apimanagement/apimanagementpolicy.pkl.
type apiManagementPolicyProps struct {
	ResourceGroupName string `json:"resourceGroupName"`
	ServiceName       string `json:"serviceName"`
	apimPolicyBodyProps
}

func apiManagementPolicyIDParts(resourceID string) (rgName, serviceName string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "policies")
	if err != nil {
		return "", "", err
	}
	return rgName, names[0], nil
}

func apiManagementPolicyNativeID(subscriptionID, rgName, serviceName string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/policies/%s",
		subscriptionID, rgName, serviceName, apimPolicyName)
}

func (p *ApiManagementPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementPolicyProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.Value == "" {
		return nil, fmt.Errorf("value is required")
	}

	result, err := p.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName,
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

	nativeID := apiManagementPolicyNativeID(p.config.SubscriptionId, props.ResourceGroupName, props.ServiceName)
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

func (p *ApiManagementPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, err := apiManagementPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, serviceName, armapimanagement.PolicyIDNamePolicy, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
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
		ResourceType: ResourceTypeApiManagementPolicy,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through CreateOrUpdate: a policy has no PATCH verb.
func (p *ApiManagementPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, err := apiManagementPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementPolicyProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.Value == "" {
		return nil, fmt.Errorf("value is required")
	}
	props.ResourceGroupName, props.ServiceName = rgName, serviceName

	if _, err := p.api.CreateOrUpdate(ctx, rgName, serviceName,
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

func (p *ApiManagementPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, err := apiManagementPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := p.api.Delete(ctx, rgName, serviceName, armapimanagement.PolicyIDNamePolicy,
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
func (p *ApiManagementPolicy) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name. ARM answers with a
// collection rather than a pager because there is at most one service policy.
func (p *ApiManagementPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	result, err := p.api.ListByService(ctx, rgName, serviceName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list api management policies: %w", err)
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
func (p *ApiManagementPolicy) writeBackProperties(props apiManagementPolicyProps, nativeID string) map[string]any {
	out := map[string]any{
		"resourceGroupName": props.ResourceGroupName,
		"serviceName":       props.ServiceName,
	}
	if nativeID != "" {
		out["id"] = nativeID
	}
	apimPolicyWriteBackProps(out, props.apimPolicyBodyProps)
	return out
}
