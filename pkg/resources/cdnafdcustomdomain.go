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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeCdnAFDCustomDomain = "AZURE::Cdn::AFDCustomDomain"

// cdnAFDCustomDomainsAPI is the narrow slice of *armcdn.AFDCustomDomainsClient
// used by the provisioner. Create/Delete are LRO; Get is synchronous. Update
// goes through BeginCreate (PUT create-or-update).
type cdnAFDCustomDomainsAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, profileName string, customDomainName string, customDomain armcdn.AFDDomain, options *armcdn.AFDCustomDomainsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDCustomDomainsClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, profileName string, customDomainName string, options *armcdn.AFDCustomDomainsClientGetOptions) (armcdn.AFDCustomDomainsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, profileName string, customDomainName string, options *armcdn.AFDCustomDomainsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDCustomDomainsClientDeleteResponse], error)
	NewListByProfilePager(resourceGroupName string, profileName string, options *armcdn.AFDCustomDomainsClientListByProfileOptions) *runtime.Pager[armcdn.AFDCustomDomainsClientListByProfileResponse]
}

func init() {
	registry.Register(ResourceTypeCdnAFDCustomDomain, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CdnAFDCustomDomain{
			api:      c.CdnAFDCustomDomainsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CdnAFDCustomDomain is the provisioner for a Front Door custom domain
// (Microsoft.Cdn/profiles/customDomains).
type CdnAFDCustomDomain struct {
	api      cdnAFDCustomDomainsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func cdnAFDCustomDomainIDParts(resourceID string) (rgName, profileName, customDomainName string, err error) {
	rgName, names, err := armIDParts(resourceID, "profiles", "customDomains")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["profiles"], names["customDomains"], nil
}

func buildCdnAFDCustomDomainParams(props map[string]any) armcdn.AFDDomain {
	dp := &armcdn.AFDDomainProperties{}
	if v, ok := props["hostName"].(string); ok && v != "" {
		dp.HostName = stringPtr(v)
	}
	// Managed certificate is the default when no tlsSettings are supplied.
	if tlsRaw, ok := props["tlsSettings"].(map[string]any); ok {
		tls := &armcdn.AFDDomainHTTPSParameters{}
		certType := armcdn.AfdCertificateTypeManagedCertificate
		if v, ok := tlsRaw["certificateType"].(string); ok && v != "" {
			certType = armcdn.AfdCertificateType(v)
		}
		tls.CertificateType = &certType
		if v, ok := tlsRaw["minimumTlsVersion"].(string); ok && v != "" {
			tls.MinimumTLSVersion = to.Ptr(armcdn.AfdMinimumTLSVersion(v))
		}
		// BYO TLS references an AFD Secret by full ARM id.
		if id, ok := resolvableString(tlsRaw["secretId"]); ok {
			tls.Secret = &armcdn.ResourceReference{ID: stringPtr(id)}
		}
		dp.TLSSettings = tls
	}
	// Optional Azure DNS zone reference (full ARM id) for pre-validated domains.
	if id, ok := resolvableString(props["azureDnsZoneId"]); ok {
		dp.AzureDNSZone = &armcdn.ResourceReference{ID: stringPtr(id)}
	}
	return armcdn.AFDDomain{Properties: dp}
}

func serializeCdnAFDCustomDomainProperties(result armcdn.AFDDomain, rgName, profileName, customDomainName string) (json.RawMessage, error) {
	props := make(map[string]any)
	props["resourceGroupName"] = rgName
	props["profileName"] = profileName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = customDomainName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if p := result.Properties; p != nil {
		if p.HostName != nil {
			props["hostName"] = *p.HostName
		}
		if tls := p.TLSSettings; tls != nil {
			m := make(map[string]any)
			if tls.CertificateType != nil {
				m["certificateType"] = string(*tls.CertificateType)
			}
			if tls.MinimumTLSVersion != nil {
				m["minimumTlsVersion"] = string(*tls.MinimumTLSVersion)
			}
			if tls.Secret != nil && tls.Secret.ID != nil {
				m["secretId"] = *tls.Secret.ID
			}
			props["tlsSettings"] = m
		}
		if p.AzureDNSZone != nil && p.AzureDNSZone.ID != nil {
			props["azureDnsZoneId"] = *p.AzureDNSZone.ID
		}
		if p.ValidationProperties != nil {
			vp := make(map[string]any)
			if p.ValidationProperties.ValidationToken != nil {
				vp["validationToken"] = *p.ValidationProperties.ValidationToken
			}
			if p.ValidationProperties.ExpirationDate != nil {
				vp["expirationDate"] = *p.ValidationProperties.ExpirationDate
			}
			if len(vp) > 0 {
				props["validationProperties"] = vp
			}
		}
	}
	return json.Marshal(props)
}

func (d *CdnAFDCustomDomain) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	profileName, ok := props["profileName"].(string)
	if !ok || profileName == "" {
		return nil, fmt.Errorf("profileName is required")
	}
	customDomainName, ok := props["name"].(string)
	if !ok || customDomainName == "" {
		customDomainName = request.Label
	}

	params := buildCdnAFDCustomDomainParams(props)

	poller, err := d.api.BeginCreate(ctx, rgName, profileName, customDomainName, params, nil)
	if err != nil {
		return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusFailure,
			ErrorCode:       operationErrorCode(err),
		}}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Cdn/profiles/%s/customDomains/%s",
		d.config.SubscriptionId, rgName, profileName, customDomainName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			}}, nil
		}
		propsJSON, err := serializeCdnAFDCustomDomainProperties(result.AFDDomain, rgName, profileName, customDomainName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize AFDCustomDomain properties: %w", err)
		}
		return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		}}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}
	return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationCreate,
		OperationStatus: resource.OperationStatusInProgress,
		RequestID:       reqIDJSON,
		NativeID:        expectedNativeID,
	}}, nil
}

func (d *CdnAFDCustomDomain) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, profileName, customDomainName, err := cdnAFDCustomDomainIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	result, err := d.api.Get(ctx, rgName, profileName, customDomainName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeCdnAFDCustomDomainProperties(result.AFDDomain, rgName, profileName, customDomainName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AFDCustomDomain properties: %w", err)
	}
	return &resource.ReadResult{ResourceType: ResourceTypeCdnAFDCustomDomain, Properties: string(propsJSON)}, nil
}

func (d *CdnAFDCustomDomain) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, profileName, customDomainName, err := cdnAFDCustomDomainIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := buildCdnAFDCustomDomainParams(props)

	poller, err := d.api.BeginCreate(ctx, rgName, profileName, customDomainName, params, nil)
	if err != nil {
		return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        request.NativeID,
			ErrorCode:       operationErrorCode(err),
		}}, nil
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			}}, nil
		}
		propsJSON, err := serializeCdnAFDCustomDomainProperties(result.AFDDomain, rgName, profileName, customDomainName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize AFDCustomDomain properties: %w", err)
		}
		return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		}}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}
	return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationUpdate,
		OperationStatus: resource.OperationStatusInProgress,
		RequestID:       reqIDJSON,
		NativeID:        request.NativeID,
	}}, nil
}

func (d *CdnAFDCustomDomain) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, profileName, customDomainName, err := cdnAFDCustomDomainIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	poller, err := d.api.BeginDelete(ctx, rgName, profileName, customDomainName, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			}}, nil
		}
		return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        request.NativeID,
			ErrorCode:       operationErrorCode(err),
		}}, fmt.Errorf("failed to start AFDCustomDomain deletion: %w", err)
	}
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}
	return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationDelete,
		OperationStatus: resource.OperationStatusInProgress,
		RequestID:       reqIDJSON,
		NativeID:        request.NativeID,
	}}, nil
}

func (d *CdnAFDCustomDomain) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       request.RequestID,
			ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
		}}, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armcdn.AFDCustomDomainsClientCreateResponse], error) {
				return resumePoller[armcdn.AFDCustomDomainsClientCreateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armcdn.AFDCustomDomainsClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				rgName, profileName, customDomainName, err := cdnAFDCustomDomainIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := serializeCdnAFDCustomDomainProperties(result.AFDDomain, rgName, profileName, customDomainName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize AFDCustomDomain properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcdn.AFDCustomDomainsClientDeleteResponse], error) {
				return resumePoller[armcdn.AFDCustomDomainsClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return &resource.StatusResult{ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       request.RequestID,
			ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
		}}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *CdnAFDCustomDomain) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	profileName := request.AdditionalProperties["profileName"]
	if rgName == "" || profileName == "" {
		return &resource.ListResult{}, nil
	}
	var nativeIDs []string
	pager := d.api.NewListByProfilePager(rgName, profileName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list afd custom domains: %w", err)
		}
		for _, x := range page.Value {
			if x != nil && x.ID != nil {
				nativeIDs = append(nativeIDs, *x.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
