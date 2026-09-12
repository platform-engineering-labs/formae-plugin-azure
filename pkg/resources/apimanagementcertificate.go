// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApiManagementCertificate = "AZURE::ApiManagement::Certificate"

// apiManagementCertificatesAPI is the armapimanagement surface used here.
//
// There is no PATCH: a certificate is replaced by re-PUTting it, which is what
// Update does. RefreshSecret is deliberately absent — it re-fetches a Key Vault
// certificate on demand, which is an operation rather than a desired state.
type apiManagementCertificatesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, certificateID string, parameters armapimanagement.CertificateCreateOrUpdateParameters, options *armapimanagement.CertificateClientCreateOrUpdateOptions) (armapimanagement.CertificateClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, certificateID string, options *armapimanagement.CertificateClientGetOptions) (armapimanagement.CertificateClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, certificateID string, ifMatch string, options *armapimanagement.CertificateClientDeleteOptions) (armapimanagement.CertificateClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.CertificateClientListByServiceOptions) *runtime.Pager[armapimanagement.CertificateClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementCertificate, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementCertificate{
			api:    c.ApiManagementCertificateClient,
			config: cfg,
		}
	})
}

// ApiManagementCertificate is the provisioner for client certificates
// (Microsoft.ApiManagement/service/certificates) — a certificate the gateway
// PRESENTS to a backend, not the one it serves to callers.
type ApiManagementCertificate struct {
	api    apiManagementCertificatesAPI
	config *config.Config
}

// apiManagementCertificateProps mirrors
// schema/pkl/apimanagement/apimanagementcertificate.pkl.
type apiManagementCertificateProps struct {
	Name                     string `json:"name"`
	ResourceGroupName        string `json:"resourceGroupName"`
	ServiceName              string `json:"serviceName"`
	Data                     string `json:"data"`
	Password                 string `json:"password"`
	KeyVaultSecretIdentifier string `json:"keyVaultSecretIdentifier"`
	KeyVaultIdentityClientID string `json:"keyVaultIdentityClientId"`
}

func apiManagementCertificateIDParts(resourceID string) (rgName, serviceName, certificateID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "certificates")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

// createParameters builds the request body for either shape. Validation of
// which fields may appear together happens in the caller.
func (c *apiManagementCertificateProps) createParameters() armapimanagement.CertificateCreateOrUpdateParameters {
	createProps := &armapimanagement.CertificateCreateOrUpdateProperties{}
	if c.Data != "" {
		createProps.Data = to.Ptr(c.Data)
	}
	if c.Password != "" {
		createProps.Password = to.Ptr(c.Password)
	}
	if c.KeyVaultSecretIdentifier != "" {
		kv := &armapimanagement.KeyVaultContractCreateProperties{
			SecretIdentifier: to.Ptr(c.KeyVaultSecretIdentifier),
		}
		if c.KeyVaultIdentityClientID != "" {
			kv.IdentityClientID = to.Ptr(c.KeyVaultIdentityClientID)
		}
		createProps.KeyVault = kv
	}
	return armapimanagement.CertificateCreateOrUpdateParameters{Properties: createProps}
}

// validate enforces ARM's own either/or: a certificate comes from an inline
// blob or from Key Vault, never both and never neither.
func (c *apiManagementCertificateProps) validate() error {
	if c.ResourceGroupName == "" {
		return fmt.Errorf("resourceGroupName is required")
	}
	if c.ServiceName == "" {
		return fmt.Errorf("serviceName is required")
	}
	if c.Data == "" && c.KeyVaultSecretIdentifier == "" {
		return fmt.Errorf("either data or keyVaultSecretIdentifier is required")
	}
	if c.Data != "" && c.KeyVaultSecretIdentifier != "" {
		return fmt.Errorf("data and keyVaultSecretIdentifier are mutually exclusive")
	}
	return nil
}

// buildPropertiesFromResult reports only what the schema declares.
//
// `data` and `password` are never reported: ARM does not return either, so
// echoing anything for them would report drift on every sync.
func (c *ApiManagementCertificate) buildPropertiesFromResult(cert *armapimanagement.CertificateContract, rgName, serviceName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
	}
	if cert.ID != nil {
		props["id"] = *cert.ID
	}
	if cert.Name != nil {
		props["name"] = *cert.Name
	}
	if cp := cert.Properties; cp != nil {
		if cp.Subject != nil {
			props["subject"] = *cp.Subject
		}
		if cp.Thumbprint != nil {
			props["thumbprint"] = *cp.Thumbprint
		}
		if cp.ExpirationDate != nil {
			props["expirationDate"] = cp.ExpirationDate.UTC().Format(time.RFC3339)
		}
		if cp.KeyVault != nil {
			if cp.KeyVault.SecretIdentifier != nil {
				props["keyVaultSecretIdentifier"] = *cp.KeyVault.SecretIdentifier
			}
			if cp.KeyVault.IdentityClientID != nil {
				props["keyVaultIdentityClientId"] = *cp.KeyVault.IdentityClientID
			}
		}
	}
	return props
}

func (c *ApiManagementCertificate) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementCertificateProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if err := props.validate(); err != nil {
		return nil, err
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	result, err := c.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name,
		props.createParameters(), nil)
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
	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.CertificateContract,
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

func (c *ApiManagementCertificate) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, certificateID, err := apiManagementCertificateIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := c.api.Get(ctx, rgName, serviceName, certificateID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.CertificateContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementCertificate,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through CreateOrUpdate: a certificate has no PATCH verb, and
// replacing the blob under the same id is how a certificate is rotated without
// every backend that names it having to be repointed.
func (c *ApiManagementCertificate) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, certificateID, err := apiManagementCertificateIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementCertificateProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	props.ResourceGroupName, props.ServiceName = rgName, serviceName
	if err := props.validate(); err != nil {
		return nil, err
	}

	result, err := c.api.CreateOrUpdate(ctx, rgName, serviceName, certificateID, props.createParameters(), nil)
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

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.CertificateContract, rgName, serviceName))
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

func (c *ApiManagementCertificate) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, certificateID, err := apiManagementCertificateIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := c.api.Delete(ctx, rgName, serviceName, certificateID, apimIfMatchAny, nil); err != nil &&
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

// Status is never reached with real work to do: certificate writes are
// synchronous.
func (c *ApiManagementCertificate) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of API Management certificates.
func (c *ApiManagementCertificate) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := c.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management certificates: %w", err)
		}
		for _, cert := range page.Value {
			if cert.ID != nil {
				nativeIDs = append(nativeIDs, *cert.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
