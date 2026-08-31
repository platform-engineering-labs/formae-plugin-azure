// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeWebApp = "AZURE::Web::WebApp"

// webSitesAPI is the subset of *armappservice.WebAppsClient that the site-shaped
// resources in this plugin use.
//
// ARM models sites, deployment slots and hostname bindings all under /sites, so one
// client serves AZURE::Web::WebApp, AZURE::Web::FunctionApp, AZURE::Web::WebAppSlot
// and AZURE::Web::CustomHostnameBinding through different method families. Each
// resource declares only the methods it calls; this interface carries the site and
// site-config family used by WebApp and FunctionApp.
//
// Create/update is a long-running operation; Delete and the config calls are
// synchronous.
type webSitesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, name string, siteEnvelope armappservice.Site, options *armappservice.WebAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, name string, options *armappservice.WebAppsClientGetOptions) (armappservice.WebAppsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, name string, options *armappservice.WebAppsClientDeleteOptions) (armappservice.WebAppsClientDeleteResponse, error)
	GetConfiguration(ctx context.Context, resourceGroupName string, name string, options *armappservice.WebAppsClientGetConfigurationOptions) (armappservice.WebAppsClientGetConfigurationResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armappservice.WebAppsClientListByResourceGroupOptions) *runtime.Pager[armappservice.WebAppsClientListByResourceGroupResponse]
	NewListPager(options *armappservice.WebAppsClientListOptions) *runtime.Pager[armappservice.WebAppsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeWebApp, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &WebApp{
			api:      c.AppServiceWebAppsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// WebApp is the provisioner for App Service web apps (Microsoft.Web/sites).
//
// Two ARM quirks shape the implementation:
//
//   - The site GET returns an EMPTY siteConfig on purpose ("this property is not
//     returned in response to normal create and read requests since it may contain
//     sensitive information"), so Read makes a second call to .../config/web and
//     merges the result in.
//   - App settings live behind their own endpoint that also serves
//     platform-injected settings the forma never declared, so `appSettings` is
//     write-only: sent on every create and update, never read back.
type WebApp struct {
	api      webSitesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func webAppIDParts(resourceID string) (rgName, siteName string, err error) {
	rgName, names, err := armIDParts(resourceID, "sites")
	if err != nil {
		return "", "", err
	}
	return rgName, names["sites"], nil
}

// webSiteIsFunctionApp reports whether an ARM site is a function app.
//
// AZURE::Web::WebApp and AZURE::Web::FunctionApp share the Microsoft.Web/sites
// type, so discovery has to partition the listing by kind or every site would be
// reported twice, once under each formae type.
func webSiteIsFunctionApp(kind *string) bool {
	if kind == nil {
		return false
	}
	return strings.Contains(strings.ToLower(*kind), "functionapp")
}

// webSiteConfigFromProps maps the formae `siteConfig` block plus the top-level
// write-only `appSettings` list onto the ARM SiteConfig the site body carries.
//
// Returns nil when neither is declared, so an undeclared config is omitted from the
// request body rather than sent as an empty object (which ARM would read as "reset
// every setting to its default").
func webSiteConfigFromProps(props map[string]any) *armappservice.SiteConfig {
	cfg := &armappservice.SiteConfig{}
	declared := false

	if raw, ok := props["siteConfig"].(map[string]any); ok {
		declared = true
		if v, ok := raw["linuxFxVersion"].(string); ok && v != "" {
			cfg.LinuxFxVersion = stringPtr(v)
		}
		if v, ok := raw["windowsFxVersion"].(string); ok && v != "" {
			cfg.WindowsFxVersion = stringPtr(v)
		}
		if v, ok := raw["netFrameworkVersion"].(string); ok && v != "" {
			cfg.NetFrameworkVersion = stringPtr(v)
		}
		if v, ok := raw["alwaysOn"].(bool); ok {
			cfg.AlwaysOn = to.Ptr(v)
		}
		if v, ok := raw["ftpsState"].(string); ok && v != "" {
			cfg.FtpsState = to.Ptr(armappservice.FtpsState(v))
		}
		if v, ok := raw["minTlsVersion"].(string); ok && v != "" {
			cfg.MinTLSVersion = to.Ptr(armappservice.SupportedTLSVersions(v))
		}
		if v, ok := raw["http20Enabled"].(bool); ok {
			cfg.Http20Enabled = to.Ptr(v)
		}
		if v, ok := raw["healthCheckPath"].(string); ok && v != "" {
			cfg.HealthCheckPath = stringPtr(v)
		}
		if v, ok := webNumber(raw["functionAppScaleLimit"]); ok {
			cfg.FunctionAppScaleLimit = int32Ptr(v)
		}
	}

	if settings := webAppSettingsFromProps(props); settings != nil {
		declared = true
		cfg.AppSettings = settings
	}

	if !declared {
		return nil
	}
	return cfg
}

// webAppSettingsFromProps reads the write-only top-level `appSettings` list into
// the ARM NameValuePair slice. Returns nil when nothing is declared.
func webAppSettingsFromProps(props map[string]any) []*armappservice.NameValuePair {
	raw, ok := props["appSettings"].([]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	settings := make([]*armappservice.NameValuePair, 0, len(raw))
	for _, entry := range raw {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		if name == "" {
			continue
		}
		pair := &armappservice.NameValuePair{Name: stringPtr(name)}
		// A setting may be wrapped in an opaque value so it stays out of state.
		if value, ok := opaqueString(m["value"]); ok {
			pair.Value = stringPtr(value)
		} else {
			pair.Value = stringPtr("")
		}
		settings = append(settings, pair)
	}
	if len(settings) == 0 {
		return nil
	}
	return settings
}

// webSiteConfigToProps is the read-path inverse of webSiteConfigFromProps.
//
// appSettings is deliberately NOT serialized: it is write-only, and the ARM
// endpoint that serves it also returns platform-injected settings the forma never
// declared, which would read as permanent drift.
func webSiteConfigToProps(cfg *armappservice.SiteConfig, includeScaleLimit bool) map[string]any {
	if cfg == nil {
		return nil
	}
	out := make(map[string]any)
	if cfg.LinuxFxVersion != nil && *cfg.LinuxFxVersion != "" {
		out["linuxFxVersion"] = *cfg.LinuxFxVersion
	}
	if cfg.WindowsFxVersion != nil && *cfg.WindowsFxVersion != "" {
		out["windowsFxVersion"] = *cfg.WindowsFxVersion
	}
	if cfg.NetFrameworkVersion != nil && *cfg.NetFrameworkVersion != "" {
		out["netFrameworkVersion"] = *cfg.NetFrameworkVersion
	}
	if cfg.AlwaysOn != nil {
		out["alwaysOn"] = *cfg.AlwaysOn
	}
	if cfg.FtpsState != nil && *cfg.FtpsState != "" {
		out["ftpsState"] = canonicalizeEnum(string(*cfg.FtpsState), "AllAllowed", "FtpsOnly", "Disabled")
	}
	if cfg.MinTLSVersion != nil && *cfg.MinTLSVersion != "" {
		out["minTlsVersion"] = string(*cfg.MinTLSVersion)
	}
	if cfg.Http20Enabled != nil {
		out["http20Enabled"] = *cfg.Http20Enabled
	}
	if cfg.HealthCheckPath != nil && *cfg.HealthCheckPath != "" {
		out["healthCheckPath"] = *cfg.HealthCheckPath
	}
	if includeScaleLimit && cfg.FunctionAppScaleLimit != nil {
		out["functionAppScaleLimit"] = *cfg.FunctionAppScaleLimit
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// webIdentityFromProps maps the formae `identity` block onto an ARM managed service
// identity. The user-assigned map is keyed by identity ARM ID with an empty value —
// ARM fills in clientId/principalId itself.
func webIdentityFromProps(props map[string]any) *armappservice.ManagedServiceIdentity {
	raw, ok := props["identity"].(map[string]any)
	if !ok {
		return nil
	}
	identityType, _ := raw["type"].(string)
	if identityType == "" {
		return nil
	}
	identity := &armappservice.ManagedServiceIdentity{
		Type: to.Ptr(armappservice.ManagedServiceIdentityType(identityType)),
	}
	if ids, ok := raw["userAssignedIdentityIds"].([]any); ok && len(ids) > 0 {
		assigned := make(map[string]*armappservice.UserAssignedIdentity, len(ids))
		for _, entry := range ids {
			id, ok := resolvableString(entry)
			if !ok {
				continue
			}
			assigned[id] = &armappservice.UserAssignedIdentity{}
		}
		if len(assigned) > 0 {
			identity.UserAssignedIdentities = assigned
		}
	}
	return identity
}

// webIdentityToProps is the read-path inverse of webIdentityFromProps. The ARM map
// has no order, so the ID list is sorted to keep reads stable.
func webIdentityToProps(identity *armappservice.ManagedServiceIdentity) map[string]any {
	if identity == nil || identity.Type == nil || *identity.Type == "" {
		return nil
	}
	out := map[string]any{
		"type": canonicalizeEnum(string(*identity.Type),
			"None", "SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"),
	}
	if len(identity.UserAssignedIdentities) > 0 {
		ids := make([]string, 0, len(identity.UserAssignedIdentities))
		for id := range identity.UserAssignedIdentities {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out["userAssignedIdentityIds"] = ids
	}
	return out
}

// buildWebSiteParams converts the formae property map into an armappservice.Site.
// Shared by the WebApp, FunctionApp and WebAppSlot write paths, which differ only
// in whether serverFarmId is mandatory and in what kind they pin.
func buildWebSiteParams(props map[string]any, location string, requireServerFarm bool) (armappservice.Site, error) {
	params := armappservice.Site{
		Location:   stringPtr(location),
		Properties: &armappservice.SiteProperties{},
	}

	if farmID, ok := resolvableString(props["serverFarmId"]); ok {
		params.Properties.ServerFarmID = stringPtr(farmID)
	} else if requireServerFarm {
		return params, fmt.Errorf("serverFarmId is required")
	}

	if kind, ok := props["kind"].(string); ok && kind != "" {
		params.Kind = stringPtr(kind)
	}
	if httpsOnly, ok := props["httpsOnly"].(bool); ok {
		params.Properties.HTTPSOnly = to.Ptr(httpsOnly)
	}
	if clientAffinity, ok := props["clientAffinityEnabled"].(bool); ok {
		params.Properties.ClientAffinityEnabled = to.Ptr(clientAffinity)
	}
	if access, ok := props["publicNetworkAccess"].(string); ok && access != "" {
		params.Properties.PublicNetworkAccess = stringPtr(access)
	}
	if subnetID, ok := resolvableString(props["virtualNetworkSubnetId"]); ok {
		params.Properties.VirtualNetworkSubnetID = stringPtr(subnetID)
	}
	if cfg := webSiteConfigFromProps(props); cfg != nil {
		params.Properties.SiteConfig = cfg
	}
	if identity := webIdentityFromProps(props); identity != nil {
		params.Identity = identity
	}

	return params, nil
}

// serializeWebSiteProperties converts an ARM site plus the separately-fetched site
// config into formae property format.
//
// siteConfig arrives as its own argument because the site GET returns an empty one;
// callers pass the .../config/web response. Pass nil to omit the block.
func serializeWebSiteProperties(site armappservice.Site, siteConfig *armappservice.SiteConfig, rgName, siteName string, includeScaleLimit bool) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if site.Name != nil {
		props["name"] = *site.Name
	} else {
		props["name"] = siteName
	}
	if site.Location != nil {
		props["location"] = normalizeAzureLocation(*site.Location)
	}
	if site.ID != nil {
		props["id"] = *site.ID
	}
	if site.Kind != nil && *site.Kind != "" {
		props["kind"] = *site.Kind
	}

	if p := site.Properties; p != nil {
		if p.ServerFarmID != nil {
			props["serverFarmId"] = *p.ServerFarmID
		}
		if p.HTTPSOnly != nil {
			props["httpsOnly"] = *p.HTTPSOnly
		}
		if p.ClientAffinityEnabled != nil {
			props["clientAffinityEnabled"] = *p.ClientAffinityEnabled
		}
		if p.PublicNetworkAccess != nil && *p.PublicNetworkAccess != "" {
			props["publicNetworkAccess"] = canonicalizeEnum(*p.PublicNetworkAccess, "Enabled", "Disabled")
		}
		if p.VirtualNetworkSubnetID != nil && *p.VirtualNetworkSubnetID != "" {
			props["virtualNetworkSubnetId"] = *p.VirtualNetworkSubnetID
		}
		if p.DefaultHostName != nil {
			props["defaultHostName"] = *p.DefaultHostName
		}
	}

	if cfg := webSiteConfigToProps(siteConfig, includeScaleLimit); cfg != nil {
		props["siteConfig"] = cfg
	}
	if identity := webIdentityToProps(site.Identity); identity != nil {
		props["identity"] = identity
	}
	if tags := azureTagsToFormaeTags(site.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// webReadSiteConfig fetches .../config/web for a site. A NotFound is tolerated: the
// site exists but has no config resource yet, so the block is simply omitted.
//
// Shared by the WebApp and FunctionApp read paths — the site GET returns an empty
// siteConfig for both.
func webReadSiteConfig(ctx context.Context, api webSitesAPI, rgName, siteName string) (*armappservice.SiteConfig, error) {
	cfgResult, err := api.GetConfiguration(ctx, rgName, siteName, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return nil, nil
		}
		return nil, err
	}
	return cfgResult.Properties, nil
}

func (w *WebApp) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}
	siteName, ok := props["name"].(string)
	if !ok || siteName == "" {
		siteName = request.Label
	}
	if siteName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := buildWebSiteParams(props, location, true)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := w.api.BeginCreateOrUpdate(ctx, rgName, siteName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/sites/%s",
		w.config.SubscriptionId, rgName, siteName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}
		siteConfig, err := webReadSiteConfig(ctx, w.api, rgName, siteName)
		if err != nil {
			return nil, fmt.Errorf("failed to read WebApp site config: %w", err)
		}
		propsJSON, err := json.Marshal(serializeWebSiteProperties(result.Site, siteConfig, rgName, siteName, false))
		if err != nil {
			return nil, fmt.Errorf("failed to serialize WebApp properties: %w", err)
		}
		nativeID := expectedNativeID
		if result.ID != nil {
			nativeID = *result.ID
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (w *WebApp) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, siteName, err := webAppIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or site name from %s: %w", request.NativeID, err)
	}

	result, err := w.api.Get(ctx, rgName, siteName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	siteConfig, err := webReadSiteConfig(ctx, w.api, rgName, siteName)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := json.Marshal(serializeWebSiteProperties(result.Site, siteConfig, rgName, siteName, false))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize WebApp properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeWebApp,
		Properties:   string(propsJSON),
	}, nil
}

func (w *WebApp) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, siteName, err := webAppIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or site name from %s: %w", request.NativeID, err)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params, err := buildWebSiteParams(props, location, true)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := w.api.BeginCreateOrUpdate(ctx, rgName, siteName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}
		siteConfig, err := webReadSiteConfig(ctx, w.api, rgName, siteName)
		if err != nil {
			return nil, fmt.Errorf("failed to read WebApp site config: %w", err)
		}
		propsJSON, err := json.Marshal(serializeWebSiteProperties(result.Site, siteConfig, rgName, siteName, false))
		if err != nil {
			return nil, fmt.Errorf("failed to serialize WebApp properties: %w", err)
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Delete is synchronous: ARM deletes a site inline. A 404 is success so the
// operation is idempotent. The App Service plan is left alone — it is its own
// formae resource.
func (w *WebApp) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, siteName, err := webAppIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or site name from %s: %w", request.NativeID, err)
	}

	if _, err := w.api.Delete(ctx, rgName, siteName, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status resumes a create or update poller. Delete is synchronous and never
// returns a request ID, so there is no delete branch.
func (w *WebApp) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateResponse], error) {
				return resumePoller[armappservice.WebAppsClientCreateOrUpdateResponse](w.pipeline, token)
			},
			func(pollCtx context.Context, result armappservice.WebAppsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				if result.ID == nil {
					return "", nil, fmt.Errorf("WebApp create/update returned no resource ID")
				}
				rgName, siteName, err := webAppIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				siteConfig, err := webReadSiteConfig(pollCtx, w.api, rgName, siteName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to read WebApp site config: %w", err)
				}
				propsJSON, err := json.Marshal(serializeWebSiteProperties(result.Site, siteConfig, rgName, siteName, false))
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize WebApp properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unexpected operation type: %s", reqID.OperationType)
	}
}

// List enumerates sites that are NOT function apps; AZURE::Web::FunctionApp
// enumerates the complement. Without that split every site would appear twice in
// discovery, once per formae type.
func (w *WebApp) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	return webListSites(ctx, w.api, request.AdditionalProperties["resourceGroupName"], false)
}

// webListSites walks the site listing, keeping either the function apps or the
// non-function apps. Shared by the WebApp and FunctionApp List implementations.
func webListSites(ctx context.Context, api webSitesAPI, rgName string, wantFunctionApps bool) (*resource.ListResult, error) {
	var nativeIDs []string

	collect := func(sites []*armappservice.Site) {
		for _, site := range sites {
			if site == nil || site.ID == nil {
				continue
			}
			if webSiteIsFunctionApp(site.Kind) != wantFunctionApps {
				continue
			}
			nativeIDs = append(nativeIDs, *site.ID)
		}
	}

	if rgName != "" {
		pager := api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list sites: %w", err)
			}
			collect(page.Value)
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list sites: %w", err)
		}
		collect(page.Value)
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
