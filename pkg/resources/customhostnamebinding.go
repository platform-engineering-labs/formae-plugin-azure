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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeCustomHostnameBinding = "AZURE::Web::CustomHostnameBinding"

// webHostNameBindingsAPI is the hostname-binding method family of
// *armappservice.WebAppsClient. Every operation is synchronous: a binding is a
// routing table entry, so there is nothing to provision and no poller anywhere.
type webHostNameBindingsAPI interface {
	CreateOrUpdateHostNameBinding(ctx context.Context, resourceGroupName string, name string, hostName string, hostNameBinding armappservice.HostNameBinding, options *armappservice.WebAppsClientCreateOrUpdateHostNameBindingOptions) (armappservice.WebAppsClientCreateOrUpdateHostNameBindingResponse, error)
	GetHostNameBinding(ctx context.Context, resourceGroupName string, name string, hostName string, options *armappservice.WebAppsClientGetHostNameBindingOptions) (armappservice.WebAppsClientGetHostNameBindingResponse, error)
	DeleteHostNameBinding(ctx context.Context, resourceGroupName string, name string, hostName string, options *armappservice.WebAppsClientDeleteHostNameBindingOptions) (armappservice.WebAppsClientDeleteHostNameBindingResponse, error)
	NewListHostNameBindingsPager(resourceGroupName string, name string, options *armappservice.WebAppsClientListHostNameBindingsOptions) *runtime.Pager[armappservice.WebAppsClientListHostNameBindingsResponse]
}

func init() {
	registry.Register(ResourceTypeCustomHostnameBinding, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CustomHostnameBinding{api: c.AppServiceWebAppsClient, config: cfg}
	})
}

// CustomHostnameBinding is the provisioner for custom hostname bindings on an App
// Service app (Microsoft.Web/sites/{site}/hostNameBindings/{hostname}). It is a
// child of AZURE::Web::WebApp.
//
// Azure verifies domain ownership before it will accept the binding: the hostname
// must already resolve to the app through a CNAME, or through an A record plus an
// `asuid.<host>` TXT record, in the domain's real DNS zone. A subscription that does
// not own the domain cannot create one, which is why the conformance fixture for
// this type cannot pass in CI.
//
// Almost every field is immutable — only sslState and thumbprint can change in
// place, and even those go through the same CreateOrUpdate verb.
type CustomHostnameBinding struct {
	api    webHostNameBindingsAPI
	config *config.Config
}

func customHostnameBindingIDParts(resourceID string) (rgName, siteName, hostName string, err error) {
	rgName, names, err := armIDParts(resourceID, "sites", "hostnamebindings")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["sites"], names["hostnamebindings"], nil
}

// buildCustomHostnameBindingParams converts the formae property map into an
// armappservice.HostNameBinding. Shared by Create and Update so the body shape
// stays identical across operations.
func buildCustomHostnameBindingParams(props map[string]any, siteName string) armappservice.HostNameBinding {
	binding := armappservice.HostNameBinding{
		Properties: &armappservice.HostNameBindingProperties{
			SiteName: stringPtr(siteName),
		},
	}

	if sslState, ok := props["sslState"].(string); ok && sslState != "" {
		binding.Properties.SSLState = to.Ptr(armappservice.SSLState(sslState))
	}
	if thumbprint, ok := resolvableString(props["thumbprint"]); ok {
		binding.Properties.Thumbprint = stringPtr(thumbprint)
	}
	if hostNameType, ok := props["hostNameType"].(string); ok && hostNameType != "" {
		binding.Properties.HostNameType = to.Ptr(armappservice.HostNameType(hostNameType))
	}
	if recordType, ok := props["customHostNameDnsRecordType"].(string); ok && recordType != "" {
		binding.Properties.CustomHostNameDNSRecordType = to.Ptr(armappservice.CustomHostNameDNSRecordType(recordType))
	}
	if azureResourceType, ok := props["azureResourceType"].(string); ok && azureResourceType != "" {
		binding.Properties.AzureResourceType = to.Ptr(armappservice.AzureResourceType(azureResourceType))
	}
	if domainID, ok := resolvableString(props["domainId"]); ok {
		binding.Properties.DomainID = stringPtr(domainID)
	}

	return binding
}

// buildPropertiesFromResult converts an ARM HostNameBinding into formae property
// format. The hostname and the parent site come from the ARM ID rather than from the
// body: ARM reports Name as "<site>/<hostname>", which is not the formae `name`.
func (b *CustomHostnameBinding) buildPropertiesFromResult(binding *armappservice.HostNameBinding, rgName, siteName, hostName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["siteName"] = siteName
	props["name"] = hostName
	if binding.ID != nil {
		props["id"] = *binding.ID
	}

	if p := binding.Properties; p != nil {
		if p.SSLState != nil && *p.SSLState != "" {
			props["sslState"] = canonicalizeEnum(string(*p.SSLState), "Disabled", "SniEnabled", "IpBasedEnabled")
		}
		if p.Thumbprint != nil && *p.Thumbprint != "" {
			props["thumbprint"] = *p.Thumbprint
		}
		if p.HostNameType != nil && *p.HostNameType != "" {
			props["hostNameType"] = canonicalizeEnum(string(*p.HostNameType), "Verified", "Managed")
		}
		if p.CustomHostNameDNSRecordType != nil && *p.CustomHostNameDNSRecordType != "" {
			props["customHostNameDnsRecordType"] = canonicalizeEnum(string(*p.CustomHostNameDNSRecordType), "CName", "A")
		}
		if p.AzureResourceType != nil && *p.AzureResourceType != "" {
			props["azureResourceType"] = canonicalizeEnum(string(*p.AzureResourceType), "Website", "TrafficManager")
		}
		if p.DomainID != nil && *p.DomainID != "" {
			props["domainId"] = *p.DomainID
		}
	}

	return props
}

// upsert backs both Create and Update: ARM has a single CreateOrUpdate verb for a
// hostname binding.
func (b *CustomHostnameBinding) upsert(ctx context.Context, payload json.RawMessage, label string) (armappservice.HostNameBinding, string, string, string, error) {
	var props map[string]any
	if err := json.Unmarshal(payload, &props); err != nil {
		return armappservice.HostNameBinding{}, "", "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return armappservice.HostNameBinding{}, "", "", "", fmt.Errorf("resourceGroupName is required")
	}
	siteName, ok := resolvableString(props["siteName"])
	if !ok {
		return armappservice.HostNameBinding{}, "", "", "", fmt.Errorf("siteName is required")
	}
	hostName, ok := props["name"].(string)
	if !ok || hostName == "" {
		hostName = label
	}
	if hostName == "" {
		return armappservice.HostNameBinding{}, "", "", "", fmt.Errorf("name is required")
	}

	params := buildCustomHostnameBindingParams(props, siteName)
	result, err := b.api.CreateOrUpdateHostNameBinding(ctx, rgName, siteName, hostName, params, nil)
	if err != nil {
		return armappservice.HostNameBinding{}, rgName, siteName, hostName, err
	}
	return result.HostNameBinding, rgName, siteName, hostName, nil
}

func (b *CustomHostnameBinding) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	binding, rgName, siteName, hostName, err := b.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if rgName == "" || siteName == "" || hostName == "" {
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

	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&binding, rgName, siteName, hostName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CustomHostnameBinding properties: %w", err)
	}

	nativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/sites/%s/hostNameBindings/%s",
		b.config.SubscriptionId, rgName, siteName, hostName)
	if binding.ID != nil {
		nativeID = *binding.ID
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

func (b *CustomHostnameBinding) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, siteName, hostName, err := customHostnameBindingIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup, site or hostname from %s: %w", request.NativeID, err)
	}

	result, err := b.api.GetHostNameBinding(ctx, rgName, siteName, hostName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&result.HostNameBinding, rgName, siteName, hostName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CustomHostnameBinding properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeCustomHostnameBinding,
		Properties:   string(propsJSON),
	}, nil
}

func (b *CustomHostnameBinding) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	binding, rgName, siteName, hostName, err := b.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if rgName == "" || siteName == "" || hostName == "" {
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

	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&binding, rgName, siteName, hostName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CustomHostnameBinding properties after update: %w", err)
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

func (b *CustomHostnameBinding) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, siteName, hostName, err := customHostnameBindingIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup, site or hostname from %s: %w", request.NativeID, err)
	}

	if _, err := b.api.DeleteHostNameBinding(ctx, rgName, siteName, hostName, nil); err != nil && !isDeleteSuccessError(err) {
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

// All hostname-binding operations are synchronous, so Status just re-reads.
func (b *CustomHostnameBinding) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, siteName, hostName, err := customHostnameBindingIDParts(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	result, err := b.api.GetHostNameBinding(ctx, rgName, siteName, hostName, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to get CustomHostnameBinding status: %w", err)
	}

	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&result.HostNameBinding, rgName, siteName, hostName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CustomHostnameBinding properties: %w", err)
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

// List enumerates the hostname bindings of one app. ARM has no subscription-wide
// listing, so discovery depends on the parent chain handing down both the resource
// group and the site name.
func (b *CustomHostnameBinding) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	siteName := request.AdditionalProperties["siteName"]

	var nativeIDs []string
	pager := b.api.NewListHostNameBindingsPager(rgName, siteName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list hostname bindings for site %s: %w", siteName, err)
		}
		for _, binding := range page.Value {
			if binding != nil && binding.ID != nil {
				nativeIDs = append(nativeIDs, *binding.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
