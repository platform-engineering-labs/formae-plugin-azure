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

const ResourceTypeApiManagementAuthorizationServer = "AZURE::ApiManagement::AuthorizationServer"

// apiManagementAuthorizationServersAPI is the armapimanagement surface used
// here. All synchronous, with ifMatch passed positionally on the PATCH and the
// delete. ListSecrets is deliberately not part of this interface: the client
// secret is never read back into resource state.
type apiManagementAuthorizationServersAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, authsid string, parameters armapimanagement.AuthorizationServerContract, options *armapimanagement.AuthorizationServerClientCreateOrUpdateOptions) (armapimanagement.AuthorizationServerClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, authsid string, options *armapimanagement.AuthorizationServerClientGetOptions) (armapimanagement.AuthorizationServerClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, authsid string, ifMatch string, parameters armapimanagement.AuthorizationServerUpdateContract, options *armapimanagement.AuthorizationServerClientUpdateOptions) (armapimanagement.AuthorizationServerClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, authsid string, ifMatch string, options *armapimanagement.AuthorizationServerClientDeleteOptions) (armapimanagement.AuthorizationServerClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.AuthorizationServerClientListByServiceOptions) *runtime.Pager[armapimanagement.AuthorizationServerClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementAuthorizationServer, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementAuthorizationServer{
			api:    c.ApiManagementAuthorizationServerClient,
			config: cfg,
		}
	})
}

// ApiManagementAuthorizationServer is the provisioner for OAuth 2.0
// authorization-server registrations
// (Microsoft.ApiManagement/service/authorizationServers).
//
// The client secret is written but never serialized back: ARM returns it only
// from a separate ListSecrets call, so putting it in resource state would
// persist a live credential.
type ApiManagementAuthorizationServer struct {
	api    apiManagementAuthorizationServersAPI
	config *config.Config
}

// apiManagementAuthorizationServerProps mirrors
// schema/pkl/apimanagement/apimanagementauthorizationserver.pkl.
type apiManagementAuthorizationServerProps struct {
	Name                       string   `json:"name"`
	ResourceGroupName          string   `json:"resourceGroupName"`
	ServiceName                string   `json:"serviceName"`
	DisplayName                string   `json:"displayName"`
	AuthorizationEndpoint      string   `json:"authorizationEndpoint"`
	ClientRegistrationEndpoint string   `json:"clientRegistrationEndpoint"`
	ClientID                   string   `json:"clientId"`
	GrantTypes                 []string `json:"grantTypes"`
	TokenEndpoint              *string  `json:"tokenEndpoint"`
	ClientSecret               *string  `json:"clientSecret"`
	DefaultScope               *string  `json:"defaultScope"`
	Description                *string  `json:"description"`
	AuthorizationMethods       []string `json:"authorizationMethods"`
	BearerTokenSendingMethods  []string `json:"bearerTokenSendingMethods"`
	ClientAuthenticationMethod []string `json:"clientAuthenticationMethod"`
	SupportState               *bool    `json:"supportState"`
}

func apiManagementAuthorizationServerIDParts(resourceID string) (rgName, serviceName, authsid string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "authorizationServers")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func apimGrantTypes(values []string) []*armapimanagement.GrantType {
	if len(values) == 0 {
		return nil
	}
	out := make([]*armapimanagement.GrantType, 0, len(values))
	for _, v := range values {
		out = append(out, to.Ptr(armapimanagement.GrantType(v)))
	}
	return out
}

func apimAuthorizationMethods(values []string) []*armapimanagement.AuthorizationMethod {
	if len(values) == 0 {
		return nil
	}
	out := make([]*armapimanagement.AuthorizationMethod, 0, len(values))
	for _, v := range values {
		out = append(out, to.Ptr(armapimanagement.AuthorizationMethod(v)))
	}
	return out
}

func apimBearerTokenSendingMethods(values []string) []*armapimanagement.BearerTokenSendingMethod {
	if len(values) == 0 {
		return nil
	}
	out := make([]*armapimanagement.BearerTokenSendingMethod, 0, len(values))
	for _, v := range values {
		out = append(out, to.Ptr(armapimanagement.BearerTokenSendingMethod(v)))
	}
	return out
}

func apimClientAuthenticationMethods(values []string) []*armapimanagement.ClientAuthenticationMethod {
	if len(values) == 0 {
		return nil
	}
	out := make([]*armapimanagement.ClientAuthenticationMethod, 0, len(values))
	for _, v := range values {
		out = append(out, to.Ptr(armapimanagement.ClientAuthenticationMethod(v)))
	}
	return out
}

func (a *ApiManagementAuthorizationServer) buildPropertiesFromResult(server *armapimanagement.AuthorizationServerContract, rgName, serviceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serviceName"] = serviceName

	if server.ID != nil {
		props["id"] = *server.ID
	}
	if server.Name != nil {
		props["name"] = *server.Name
	}

	if p := server.Properties; p != nil {
		if p.DisplayName != nil {
			props["displayName"] = *p.DisplayName
		}
		if p.AuthorizationEndpoint != nil {
			props["authorizationEndpoint"] = *p.AuthorizationEndpoint
		}
		if p.ClientRegistrationEndpoint != nil {
			props["clientRegistrationEndpoint"] = *p.ClientRegistrationEndpoint
		}
		if p.ClientID != nil {
			props["clientId"] = *p.ClientID
		}
		if len(p.GrantTypes) > 0 {
			props["grantTypes"] = stringsFromPointers(asStringPtrs(p.GrantTypes, func(g armapimanagement.GrantType) string { return string(g) }))
		}
		if p.TokenEndpoint != nil {
			props["tokenEndpoint"] = *p.TokenEndpoint
		}
		if p.DefaultScope != nil {
			props["defaultScope"] = *p.DefaultScope
		}
		if p.Description != nil {
			props["description"] = *p.Description
		}
		if len(p.AuthorizationMethods) > 0 {
			props["authorizationMethods"] = stringsFromPointers(asStringPtrs(p.AuthorizationMethods, func(m armapimanagement.AuthorizationMethod) string { return string(m) }))
		}
		if len(p.BearerTokenSendingMethods) > 0 {
			props["bearerTokenSendingMethods"] = stringsFromPointers(asStringPtrs(p.BearerTokenSendingMethods, func(m armapimanagement.BearerTokenSendingMethod) string { return string(m) }))
		}
		if len(p.ClientAuthenticationMethod) > 0 {
			props["clientAuthenticationMethod"] = stringsFromPointers(asStringPtrs(p.ClientAuthenticationMethod, func(m armapimanagement.ClientAuthenticationMethod) string { return string(m) }))
		}
		if p.SupportState != nil {
			props["supportState"] = *p.SupportState
		}
		// clientSecret, resourceOwnerUsername, resourceOwnerPassword and
		// tokenBodyParameters are deliberately dropped: the first three are
		// credentials, and ARM does not return the secret from a Get anyway.
	}

	return props
}

// asStringPtrs converts a slice of pointers to a typed enum into the
// []*string shape stringsFromPointers takes, skipping nils.
func asStringPtrs[T any](values []*T, render func(T) string) []*string {
	out := make([]*string, 0, len(values))
	for _, v := range values {
		if v == nil {
			continue
		}
		out = append(out, to.Ptr(render(*v)))
	}
	return out
}

func (a *ApiManagementAuthorizationServer) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementAuthorizationServerProps
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
	if props.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("authorizationEndpoint is required")
	}
	if props.ClientRegistrationEndpoint == "" {
		return nil, fmt.Errorf("clientRegistrationEndpoint is required")
	}
	if props.ClientID == "" {
		return nil, fmt.Errorf("clientId is required")
	}
	if len(props.GrantTypes) == 0 {
		return nil, fmt.Errorf("grantTypes is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armapimanagement.AuthorizationServerContract{
		Properties: &armapimanagement.AuthorizationServerContractProperties{
			DisplayName:                to.Ptr(props.DisplayName),
			AuthorizationEndpoint:      to.Ptr(props.AuthorizationEndpoint),
			ClientRegistrationEndpoint: to.Ptr(props.ClientRegistrationEndpoint),
			ClientID:                   to.Ptr(props.ClientID),
			GrantTypes:                 apimGrantTypes(props.GrantTypes),
			TokenEndpoint:              props.TokenEndpoint,
			ClientSecret:               props.ClientSecret,
			DefaultScope:               props.DefaultScope,
			Description:                props.Description,
			AuthorizationMethods:       apimAuthorizationMethods(props.AuthorizationMethods),
			BearerTokenSendingMethods:  apimBearerTokenSendingMethods(props.BearerTokenSendingMethods),
			ClientAuthenticationMethod: apimClientAuthenticationMethods(props.ClientAuthenticationMethod),
			SupportState:               props.SupportState,
		},
	}

	result, err := a.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name, params, nil)
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
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AuthorizationServerContract,
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

func (a *ApiManagementAuthorizationServer) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, authsid, err := apiManagementAuthorizationServerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, serviceName, authsid, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AuthorizationServerContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementAuthorizationServer,
		Properties:   string(propsJSON),
	}, nil
}

func (a *ApiManagementAuthorizationServer) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, authsid, err := apiManagementAuthorizationServerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementAuthorizationServerProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.AuthorizationServerUpdateContractProperties{
		GrantTypes:                 apimGrantTypes(props.GrantTypes),
		TokenEndpoint:              props.TokenEndpoint,
		ClientSecret:               props.ClientSecret,
		DefaultScope:               props.DefaultScope,
		Description:                props.Description,
		AuthorizationMethods:       apimAuthorizationMethods(props.AuthorizationMethods),
		BearerTokenSendingMethods:  apimBearerTokenSendingMethods(props.BearerTokenSendingMethods),
		ClientAuthenticationMethod: apimClientAuthenticationMethods(props.ClientAuthenticationMethod),
		SupportState:               props.SupportState,
	}
	if props.DisplayName != "" {
		updateProps.DisplayName = to.Ptr(props.DisplayName)
	}
	if props.AuthorizationEndpoint != "" {
		updateProps.AuthorizationEndpoint = to.Ptr(props.AuthorizationEndpoint)
	}
	if props.ClientRegistrationEndpoint != "" {
		updateProps.ClientRegistrationEndpoint = to.Ptr(props.ClientRegistrationEndpoint)
	}
	if props.ClientID != "" {
		updateProps.ClientID = to.Ptr(props.ClientID)
	}

	if _, err := a.api.Update(ctx, rgName, serviceName, authsid, apimIfMatchAny,
		armapimanagement.AuthorizationServerUpdateContract{Properties: updateProps}, nil); err != nil {
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
	result, err := a.api.Get(ctx, rgName, serviceName, authsid, nil)
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AuthorizationServerContract, rgName, serviceName))
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

func (a *ApiManagementAuthorizationServer) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, authsid, err := apiManagementAuthorizationServerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := a.api.Delete(ctx, rgName, serviceName, authsid, apimIfMatchAny, nil); err != nil && !isDeleteSuccessError(err) {
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
func (a *ApiManagementAuthorizationServer) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of authorization servers.
func (a *ApiManagementAuthorizationServer) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := a.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management authorization servers: %w", err)
		}
		for _, server := range page.Value {
			if server.ID != nil {
				nativeIDs = append(nativeIDs, *server.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
