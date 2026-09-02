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

const ResourceTypeApiManagementBackend = "AZURE::ApiManagement::Backend"

// apiManagementBackendsAPI is the armapimanagement surface used here. All
// synchronous, with ifMatch passed positionally on the PATCH and the delete.
type apiManagementBackendsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, backendID string, parameters armapimanagement.BackendContract, options *armapimanagement.BackendClientCreateOrUpdateOptions) (armapimanagement.BackendClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, backendID string, options *armapimanagement.BackendClientGetOptions) (armapimanagement.BackendClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, backendID string, ifMatch string, parameters armapimanagement.BackendUpdateParameters, options *armapimanagement.BackendClientUpdateOptions) (armapimanagement.BackendClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, backendID string, ifMatch string, options *armapimanagement.BackendClientDeleteOptions) (armapimanagement.BackendClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.BackendClientListByServiceOptions) *runtime.Pager[armapimanagement.BackendClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementBackend, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementBackend{
			api:    c.ApiManagementBackendClient,
			config: cfg,
		}
	})
}

// ApiManagementBackend is the provisioner for backends
// (Microsoft.ApiManagement/service/backends) — a named destination an API or a
// `set-backend-service` policy can forward to.
type ApiManagementBackend struct {
	api    apiManagementBackendsAPI
	config *config.Config
}

// apiManagementBackendTLSProps mirrors the BackendTls class in the schema.
type apiManagementBackendTLSProps struct {
	ValidateCertificateChain *bool `json:"validateCertificateChain"`
	ValidateCertificateName  *bool `json:"validateCertificateName"`
}

// apiManagementBackendCredentialsProps mirrors the BackendCredentials class.
type apiManagementBackendCredentialsProps struct {
	AuthorizationScheme    string   `json:"authorizationScheme"`
	AuthorizationParameter string   `json:"authorizationParameter"`
	CertificateIDs         []string `json:"certificateIds"`
}

// apiManagementBackendProps mirrors
// schema/pkl/apimanagement/apimanagementbackend.pkl.
type apiManagementBackendProps struct {
	Name              string                                `json:"name"`
	ResourceGroupName string                                `json:"resourceGroupName"`
	ServiceName       string                                `json:"serviceName"`
	URL               string                                `json:"url"`
	Protocol          string                                `json:"protocol"`
	Title             *string                               `json:"title"`
	Description       *string                               `json:"description"`
	ResourceID        *string                               `json:"resourceId"`
	TLS               *apiManagementBackendTLSProps         `json:"tls"`
	Credentials       *apiManagementBackendCredentialsProps `json:"credentials"`
}

func apiManagementBackendIDParts(resourceID string) (rgName, serviceName, backendID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "backends")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

func (b *apiManagementBackendProps) tlsContract() *armapimanagement.BackendTLSProperties {
	if b.TLS == nil {
		return nil
	}
	return &armapimanagement.BackendTLSProperties{
		ValidateCertificateChain: b.TLS.ValidateCertificateChain,
		ValidateCertificateName:  b.TLS.ValidateCertificateName,
	}
}

// credentialsContract builds ARM's credentials block. An authorization header
// needs BOTH halves — ARM marks scheme and parameter REQUIRED inside it — so a
// half-filled declaration sends no header rather than an invalid one.
func (b *apiManagementBackendProps) credentialsContract() *armapimanagement.BackendCredentialsContract {
	if b.Credentials == nil {
		return nil
	}
	out := &armapimanagement.BackendCredentialsContract{
		CertificateIDs: stringPointers(b.Credentials.CertificateIDs),
	}
	if b.Credentials.AuthorizationScheme != "" && b.Credentials.AuthorizationParameter != "" {
		out.Authorization = &armapimanagement.BackendAuthorizationHeaderCredentials{
			Scheme:    to.Ptr(b.Credentials.AuthorizationScheme),
			Parameter: to.Ptr(b.Credentials.AuthorizationParameter),
		}
	}
	return out
}

// buildPropertiesFromResult reports only what the schema declares.
//
// The authorization parameter is never reported: it is write-only, and ARM
// returns a masked placeholder rather than the value, which would read as
// drift on every sync.
func (b *ApiManagementBackend) buildPropertiesFromResult(backend *armapimanagement.BackendContract, rgName, serviceName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
	}
	if backend.ID != nil {
		props["id"] = *backend.ID
	}
	if backend.Name != nil {
		props["name"] = *backend.Name
	}
	bp := backend.Properties
	if bp == nil {
		return props
	}
	if bp.URL != nil {
		props["url"] = *bp.URL
	}
	if bp.Protocol != nil {
		props["protocol"] = canonicalizeEnum(string(*bp.Protocol), "http", "soap")
	}
	if bp.Title != nil {
		props["title"] = *bp.Title
	}
	if bp.Description != nil {
		props["description"] = *bp.Description
	}
	if bp.ResourceID != nil {
		props["resourceId"] = *bp.ResourceID
	}
	if bp.TLS != nil {
		tls := map[string]any{}
		if bp.TLS.ValidateCertificateChain != nil {
			tls["validateCertificateChain"] = *bp.TLS.ValidateCertificateChain
		}
		if bp.TLS.ValidateCertificateName != nil {
			tls["validateCertificateName"] = *bp.TLS.ValidateCertificateName
		}
		if len(tls) > 0 {
			props["tls"] = tls
		}
	}
	if bp.Credentials != nil {
		creds := map[string]any{}
		if bp.Credentials.Authorization != nil && bp.Credentials.Authorization.Scheme != nil {
			creds["authorizationScheme"] = *bp.Credentials.Authorization.Scheme
		}
		if ids := stringsFromPointers(bp.Credentials.CertificateIDs); len(ids) > 0 {
			creds["certificateIds"] = ids
		}
		if len(creds) > 0 {
			props["credentials"] = creds
		}
	}
	return props
}

func (b *ApiManagementBackend) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementBackendProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.URL == "" {
		return nil, fmt.Errorf("url is required")
	}
	if props.Protocol == "" {
		return nil, fmt.Errorf("protocol is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armapimanagement.BackendContract{
		Properties: &armapimanagement.BackendContractProperties{
			URL:         to.Ptr(props.URL),
			Protocol:    to.Ptr(armapimanagement.BackendProtocol(props.Protocol)),
			Title:       props.Title,
			Description: props.Description,
			ResourceID:  props.ResourceID,
			TLS:         props.tlsContract(),
			Credentials: props.credentialsContract(),
		},
	}

	result, err := b.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name, params, nil)
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
	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&result.BackendContract,
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

func (b *ApiManagementBackend) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, backendID, err := apiManagementBackendIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := b.api.Get(ctx, rgName, serviceName, backendID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&result.BackendContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementBackend,
		Properties:   string(propsJSON),
	}, nil
}

func (b *ApiManagementBackend) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, backendID, err := apiManagementBackendIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementBackendProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.BackendUpdateParameterProperties{
		Title:       props.Title,
		Description: props.Description,
		ResourceID:  props.ResourceID,
		TLS:         props.tlsContract(),
		Credentials: props.credentialsContract(),
	}
	if props.URL != "" {
		updateProps.URL = to.Ptr(props.URL)
	}
	if props.Protocol != "" {
		updateProps.Protocol = to.Ptr(armapimanagement.BackendProtocol(props.Protocol))
	}

	result, err := b.api.Update(ctx, rgName, serviceName, backendID, apimIfMatchAny,
		armapimanagement.BackendUpdateParameters{Properties: updateProps}, nil)
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

	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&result.BackendContract, rgName, serviceName))
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

func (b *ApiManagementBackend) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, backendID, err := apiManagementBackendIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := b.api.Delete(ctx, rgName, serviceName, backendID, apimIfMatchAny, nil); err != nil &&
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

// Status is never reached with real work to do: backend writes are synchronous.
func (b *ApiManagementBackend) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of backends.
func (b *ApiManagementBackend) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := b.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management backends: %w", err)
		}
		for _, backend := range page.Value {
			if backend.ID != nil {
				nativeIDs = append(nativeIDs, *backend.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
