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

const ResourceTypeApiManagementOpenIdConnectProvider = "AZURE::ApiManagement::OpenIdConnectProvider"

// apiManagementOpenIDConnectProvidersAPI is the armapimanagement surface used
// here. All synchronous, with ifMatch passed positionally on the PATCH and the
// delete. ListSecrets is deliberately not part of this interface: the client
// secret is never read back into resource state.
type apiManagementOpenIDConnectProvidersAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, opid string, parameters armapimanagement.OpenidConnectProviderContract, options *armapimanagement.OpenIDConnectProviderClientCreateOrUpdateOptions) (armapimanagement.OpenIDConnectProviderClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, opid string, options *armapimanagement.OpenIDConnectProviderClientGetOptions) (armapimanagement.OpenIDConnectProviderClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, opid string, ifMatch string, parameters armapimanagement.OpenidConnectProviderUpdateContract, options *armapimanagement.OpenIDConnectProviderClientUpdateOptions) (armapimanagement.OpenIDConnectProviderClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, opid string, ifMatch string, options *armapimanagement.OpenIDConnectProviderClientDeleteOptions) (armapimanagement.OpenIDConnectProviderClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.OpenIDConnectProviderClientListByServiceOptions) *runtime.Pager[armapimanagement.OpenIDConnectProviderClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementOpenIdConnectProvider, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementOpenIdConnectProvider{
			api:    c.ApiManagementOpenIDConnectProviderClient,
			config: cfg,
		}
	})
}

// ApiManagementOpenIdConnectProvider is the provisioner for OpenID Connect
// provider registrations
// (Microsoft.ApiManagement/service/openidConnectProviders).
//
// The client secret is written but never serialized back: ARM returns it only
// from a separate ListSecrets call, so putting it in resource state would
// persist a live credential.
type ApiManagementOpenIdConnectProvider struct {
	api    apiManagementOpenIDConnectProvidersAPI
	config *config.Config
}

// apiManagementOpenIdConnectProviderProps mirrors
// schema/pkl/apimanagement/apimanagementopenidconnectprovider.pkl.
type apiManagementOpenIdConnectProviderProps struct {
	Name              string  `json:"name"`
	ResourceGroupName string  `json:"resourceGroupName"`
	ServiceName       string  `json:"serviceName"`
	DisplayName       string  `json:"displayName"`
	MetadataEndpoint  string  `json:"metadataEndpoint"`
	ClientID          string  `json:"clientId"`
	ClientSecret      *string `json:"clientSecret"`
	Description       *string `json:"description"`
}

func apiManagementOpenIdConnectProviderIDParts(resourceID string) (rgName, serviceName, opid string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "openidConnectProviders")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func (o *ApiManagementOpenIdConnectProvider) buildPropertiesFromResult(provider *armapimanagement.OpenidConnectProviderContract, rgName, serviceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serviceName"] = serviceName

	if provider.ID != nil {
		props["id"] = *provider.ID
	}
	if provider.Name != nil {
		props["name"] = *provider.Name
	}

	if p := provider.Properties; p != nil {
		if p.DisplayName != nil {
			props["displayName"] = *p.DisplayName
		}
		if p.MetadataEndpoint != nil {
			props["metadataEndpoint"] = *p.MetadataEndpoint
		}
		if p.ClientID != nil {
			props["clientId"] = *p.ClientID
		}
		if p.Description != nil {
			props["description"] = *p.Description
		}
		// clientSecret is deliberately dropped: it is a live credential, and
		// ARM does not return it from a Get anyway.
	}

	return props
}

func (o *ApiManagementOpenIdConnectProvider) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementOpenIdConnectProviderProps
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
	if props.MetadataEndpoint == "" {
		return nil, fmt.Errorf("metadataEndpoint is required")
	}
	if props.ClientID == "" {
		return nil, fmt.Errorf("clientId is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armapimanagement.OpenidConnectProviderContract{
		Properties: &armapimanagement.OpenidConnectProviderContractProperties{
			DisplayName:      to.Ptr(props.DisplayName),
			MetadataEndpoint: to.Ptr(props.MetadataEndpoint),
			ClientID:         to.Ptr(props.ClientID),
			ClientSecret:     props.ClientSecret,
			Description:      props.Description,
		},
	}

	result, err := o.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name, params, nil)
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
	propsJSON, err := json.Marshal(o.buildPropertiesFromResult(&result.OpenidConnectProviderContract,
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

func (o *ApiManagementOpenIdConnectProvider) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, opid, err := apiManagementOpenIdConnectProviderIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := o.api.Get(ctx, rgName, serviceName, opid, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(o.buildPropertiesFromResult(&result.OpenidConnectProviderContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementOpenIdConnectProvider,
		Properties:   string(propsJSON),
	}, nil
}

func (o *ApiManagementOpenIdConnectProvider) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, opid, err := apiManagementOpenIdConnectProviderIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementOpenIdConnectProviderProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.OpenidConnectProviderUpdateContractProperties{
		ClientSecret: props.ClientSecret,
		Description:  props.Description,
	}
	if props.DisplayName != "" {
		updateProps.DisplayName = to.Ptr(props.DisplayName)
	}
	if props.MetadataEndpoint != "" {
		updateProps.MetadataEndpoint = to.Ptr(props.MetadataEndpoint)
	}
	if props.ClientID != "" {
		updateProps.ClientID = to.Ptr(props.ClientID)
	}

	if _, err := o.api.Update(ctx, rgName, serviceName, opid, apimIfMatchAny,
		armapimanagement.OpenidConnectProviderUpdateContract{Properties: updateProps}, nil); err != nil {
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

	// The PATCH answers 204 with no body, so the current state has to be
	// re-read to report it.
	result, err := o.api.Get(ctx, rgName, serviceName, opid, nil)
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

	propsJSON, err := json.Marshal(o.buildPropertiesFromResult(&result.OpenidConnectProviderContract, rgName, serviceName))
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

func (o *ApiManagementOpenIdConnectProvider) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, opid, err := apiManagementOpenIdConnectProviderIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := o.api.Delete(ctx, rgName, serviceName, opid, apimIfMatchAny, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: every write here is
// synchronous.
func (o *ApiManagementOpenIdConnectProvider) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of OpenID Connect providers.
func (o *ApiManagementOpenIdConnectProvider) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := o.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management openid connect providers: %w", err)
		}
		for _, provider := range page.Value {
			if provider.ID != nil {
				nativeIDs = append(nativeIDs, *provider.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
