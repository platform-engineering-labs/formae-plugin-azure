// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeWebCertificate = "AZURE::Web::Certificate"

// webCertificatesAPI is the subset of *armappservice.CertificatesClient used here.
// Every operation is synchronous — an App Service certificate is metadata plus key
// material, so there is nothing to provision and no poller anywhere.
type webCertificatesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, name string, certificateEnvelope armappservice.AppCertificate, options *armappservice.CertificatesClientCreateOrUpdateOptions) (armappservice.CertificatesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, name string, options *armappservice.CertificatesClientGetOptions) (armappservice.CertificatesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, name string, options *armappservice.CertificatesClientDeleteOptions) (armappservice.CertificatesClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armappservice.CertificatesClientListByResourceGroupOptions) *runtime.Pager[armappservice.CertificatesClientListByResourceGroupResponse]
	NewListPager(options *armappservice.CertificatesClientListOptions) *runtime.Pager[armappservice.CertificatesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeWebCertificate, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &WebCertificate{api: c.AppServiceCertificatesClient, config: cfg}
	})
}

// WebCertificate is the provisioner for App Service certificates
// (Microsoft.Web/certificates).
//
// The certificate material arrives either as a base-64 PFX plus password, or as a
// Key Vault reference. Both are write-only: Azure returns only derived metadata
// (thumbprint, subject, issuer, host names), never the key material, so drift in
// the material itself cannot be detected.
//
// Named WebCertificate rather than Certificate because AZURE::KeyVault::Certificate
// already owns that identifier in this package.
type WebCertificate struct {
	api    webCertificatesAPI
	config *config.Config
}

func webCertificateIDParts(resourceID string) (rgName, certName string, err error) {
	rgName, names, err := armIDParts(resourceID, "certificates")
	if err != nil {
		return "", "", err
	}
	return rgName, names["certificates"], nil
}

// buildWebCertificateParams converts the formae property map into an
// armappservice.AppCertificate. Shared by Create and Update so the body shape stays
// identical across operations.
func buildWebCertificateParams(props map[string]any, location string) (armappservice.AppCertificate, error) {
	params := armappservice.AppCertificate{
		Location:   stringPtr(location),
		Properties: &armappservice.AppCertificateProperties{},
	}

	if farmID, ok := resolvableString(props["serverFarmId"]); ok {
		params.Properties.ServerFarmID = stringPtr(farmID)
	}

	// The PKL field carries base-64 text; the SDK model is a byte slice that it
	// re-encodes on the wire, so decode here rather than shipping the text as bytes.
	if blob, ok := opaqueString(props["pfxBlob"]); ok {
		decoded, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			return params, fmt.Errorf("pfxBlob is not valid base-64: %w", err)
		}
		params.Properties.PfxBlob = decoded
	}
	if password, ok := opaqueString(props["password"]); ok {
		params.Properties.Password = stringPtr(password)
	}
	if vaultID, ok := resolvableString(props["keyVaultId"]); ok {
		params.Properties.KeyVaultID = stringPtr(vaultID)
	}
	if secretName, ok := props["keyVaultSecretName"].(string); ok && secretName != "" {
		params.Properties.KeyVaultSecretName = stringPtr(secretName)
	}
	if canonicalName, ok := props["canonicalName"].(string); ok && canonicalName != "" {
		params.Properties.CanonicalName = stringPtr(canonicalName)
	}
	if method, ok := props["domainValidationMethod"].(string); ok && method != "" {
		params.Properties.DomainValidationMethod = stringPtr(method)
	}
	if hostNamesRaw, ok := props["hostNames"].([]any); ok && len(hostNamesRaw) > 0 {
		hostNames := make([]string, 0, len(hostNamesRaw))
		for _, entry := range hostNamesRaw {
			if host, ok := entry.(string); ok && host != "" {
				hostNames = append(hostNames, host)
			}
		}
		params.Properties.HostNames = stringPointers(hostNames)
	}

	if params.Properties.PfxBlob == nil && params.Properties.KeyVaultID == nil && params.Properties.CanonicalName == nil {
		return params, fmt.Errorf("one of pfxBlob, keyVaultId or canonicalName is required")
	}

	return params, nil
}

// buildPropertiesFromResult converts an ARM AppCertificate into formae property
// format. Key material is never echoed back by Azure and is not serialized.
func (c *WebCertificate) buildPropertiesFromResult(cert *armappservice.AppCertificate, rgName, certName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if cert.Name != nil {
		props["name"] = *cert.Name
	} else {
		props["name"] = certName
	}
	if cert.Location != nil {
		props["location"] = normalizeAzureLocation(*cert.Location)
	}
	if cert.ID != nil {
		props["id"] = *cert.ID
	}

	if p := cert.Properties; p != nil {
		if p.ServerFarmID != nil {
			props["serverFarmId"] = *p.ServerFarmID
		}
		if p.KeyVaultID != nil && *p.KeyVaultID != "" {
			props["keyVaultId"] = *p.KeyVaultID
		}
		if p.KeyVaultSecretName != nil && *p.KeyVaultSecretName != "" {
			props["keyVaultSecretName"] = *p.KeyVaultSecretName
		}
		if p.CanonicalName != nil && *p.CanonicalName != "" {
			props["canonicalName"] = *p.CanonicalName
		}
		if p.DomainValidationMethod != nil && *p.DomainValidationMethod != "" {
			props["domainValidationMethod"] = *p.DomainValidationMethod
		}
		if hostNames := stringsFromPointers(p.HostNames); hostNames != nil {
			props["hostNames"] = hostNames
		}
		if p.Thumbprint != nil {
			props["thumbprint"] = *p.Thumbprint
		}
		if p.SubjectName != nil {
			props["subjectName"] = *p.SubjectName
		}
		if p.Issuer != nil {
			props["issuer"] = *p.Issuer
		}
	}

	if tags := azureTagsToFormaeTags(cert.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// upsert backs both Create and Update: ARM's CreateOrUpdate replaces the
// certificate body, and there is no separate create verb.
func (c *WebCertificate) upsert(ctx context.Context, payload json.RawMessage, label string) (armappservice.AppCertificate, string, string, error) {
	var props map[string]any
	if err := json.Unmarshal(payload, &props); err != nil {
		return armappservice.AppCertificate{}, "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return armappservice.AppCertificate{}, "", "", fmt.Errorf("resourceGroupName is required")
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return armappservice.AppCertificate{}, "", "", fmt.Errorf("location is required")
	}
	certName, ok := props["name"].(string)
	if !ok || certName == "" {
		certName = label
	}
	if certName == "" {
		return armappservice.AppCertificate{}, "", "", fmt.Errorf("name is required")
	}

	params, err := buildWebCertificateParams(props, location)
	if err != nil {
		return armappservice.AppCertificate{}, "", "", err
	}
	if azureTags := formaeTagsToAzureTags(payload); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := c.api.CreateOrUpdate(ctx, rgName, certName, params, nil)
	if err != nil {
		return armappservice.AppCertificate{}, rgName, certName, err
	}
	return result.AppCertificate, rgName, certName, nil
}

func (c *WebCertificate) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	cert, rgName, certName, err := c.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if rgName == "" || certName == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&cert, rgName, certName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize WebCertificate properties: %w", err)
	}

	nativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/certificates/%s",
		c.config.SubscriptionId, rgName, certName)
	if cert.ID != nil {
		nativeID = *cert.ID
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

func (c *WebCertificate) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, certName, err := webCertificateIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or certificate name from %s: %w", request.NativeID, err)
	}

	result, err := c.api.Get(ctx, rgName, certName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.AppCertificate, rgName, certName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize WebCertificate properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeWebCertificate,
		Properties:   string(propsJSON),
	}, nil
}

func (c *WebCertificate) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	cert, rgName, certName, err := c.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if rgName == "" || certName == "" {
			return nil, err
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&cert, rgName, certName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize WebCertificate properties after update: %w", err)
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

func (c *WebCertificate) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, certName, err := webCertificateIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or certificate name from %s: %w", request.NativeID, err)
	}

	if _, err := c.api.Delete(ctx, rgName, certName, nil); err != nil && !isDeleteSuccessError(err) {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
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

// All certificate operations are synchronous, so Status just re-reads.
func (c *WebCertificate) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, certName, err := webCertificateIDParts(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	result, err := c.api.Get(ctx, rgName, certName, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to get WebCertificate status: %w", err)
	}

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.AppCertificate, rgName, certName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize WebCertificate properties: %w", err)
	}
	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (c *WebCertificate) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := c.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list app service certificates: %w", err)
			}
			for _, cert := range page.Value {
				if cert != nil && cert.ID != nil {
					nativeIDs = append(nativeIDs, *cert.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := c.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list app service certificates: %w", err)
		}
		for _, cert := range page.Value {
			if cert != nil && cert.ID != nil {
				nativeIDs = append(nativeIDs, *cert.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
