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

const ResourceTypeStaticSite = "AZURE::Web::StaticSite"

// staticSitesAPI is the subset of *armappservice.StaticSitesClient used here.
// Create/update and delete are both long-running operations; the GET and the
// listings are synchronous.
type staticSitesAPI interface {
	BeginCreateOrUpdateStaticSite(ctx context.Context, resourceGroupName string, name string, staticSiteEnvelope armappservice.StaticSiteARMResource, options *armappservice.StaticSitesClientBeginCreateOrUpdateStaticSiteOptions) (*runtime.Poller[armappservice.StaticSitesClientCreateOrUpdateStaticSiteResponse], error)
	GetStaticSite(ctx context.Context, resourceGroupName string, name string, options *armappservice.StaticSitesClientGetStaticSiteOptions) (armappservice.StaticSitesClientGetStaticSiteResponse, error)
	BeginDeleteStaticSite(ctx context.Context, resourceGroupName string, name string, options *armappservice.StaticSitesClientBeginDeleteStaticSiteOptions) (*runtime.Poller[armappservice.StaticSitesClientDeleteStaticSiteResponse], error)
	NewGetStaticSitesByResourceGroupPager(resourceGroupName string, options *armappservice.StaticSitesClientGetStaticSitesByResourceGroupOptions) *runtime.Pager[armappservice.StaticSitesClientGetStaticSitesByResourceGroupResponse]
	NewListPager(options *armappservice.StaticSitesClientListOptions) *runtime.Pager[armappservice.StaticSitesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeStaticSite, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &StaticSite{
			api:      c.AppServiceStaticSitesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// StaticSite is the provisioner for Azure Static Web Apps
// (Microsoft.Web/staticSites).
//
// `buildProperties` and `repositoryToken` are write-only: ARM accepts both in the
// create body but returns neither on a GET, so they are sent on every write and
// never read back, and drift in them cannot be detected. Serializing them from the
// read path would report permanent drift instead.
type StaticSite struct {
	api      staticSitesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func staticSiteIDParts(resourceID string) (rgName, siteName string, err error) {
	rgName, names, err := armIDParts(resourceID, "staticsites")
	if err != nil {
		return "", "", err
	}
	return rgName, names["staticsites"], nil
}

// buildStaticSiteBuildProperties maps the write-only `buildProperties` block onto
// the ARM model. Returns nil when nothing is declared.
func buildStaticSiteBuildProperties(raw map[string]any) *armappservice.StaticSiteBuildProperties {
	build := &armappservice.StaticSiteBuildProperties{}
	declared := false

	if v, ok := raw["appLocation"].(string); ok && v != "" {
		build.AppLocation = stringPtr(v)
		declared = true
	}
	if v, ok := raw["apiLocation"].(string); ok && v != "" {
		build.APILocation = stringPtr(v)
		declared = true
	}
	if v, ok := raw["outputLocation"].(string); ok && v != "" {
		build.OutputLocation = stringPtr(v)
		declared = true
	}
	if v, ok := raw["appBuildCommand"].(string); ok && v != "" {
		build.AppBuildCommand = stringPtr(v)
		declared = true
	}
	if v, ok := raw["apiBuildCommand"].(string); ok && v != "" {
		build.APIBuildCommand = stringPtr(v)
		declared = true
	}
	if v, ok := raw["skipGithubActionWorkflowGeneration"].(bool); ok {
		build.SkipGithubActionWorkflowGeneration = to.Ptr(v)
		declared = true
	}

	if !declared {
		return nil
	}
	return build
}

// buildStaticSiteParams converts the formae property map into an
// armappservice.StaticSiteARMResource. Shared by Create and Update so the body
// shape stays identical across operations.
func buildStaticSiteParams(props map[string]any, location string) armappservice.StaticSiteARMResource {
	params := armappservice.StaticSiteARMResource{
		Location:   stringPtr(location),
		Properties: &armappservice.StaticSite{},
	}

	if skuRaw, ok := props["sku"].(map[string]any); ok {
		sku := &armappservice.SKUDescription{}
		if name, ok := skuRaw["name"].(string); ok && name != "" {
			sku.Name = stringPtr(name)
		}
		if tier, ok := skuRaw["tier"].(string); ok && tier != "" {
			sku.Tier = stringPtr(tier)
		}
		if sku.Name != nil || sku.Tier != nil {
			params.SKU = sku
		}
	}

	if v, ok := props["repositoryUrl"].(string); ok && v != "" {
		params.Properties.RepositoryURL = stringPtr(v)
	}
	if v, ok := props["branch"].(string); ok && v != "" {
		params.Properties.Branch = stringPtr(v)
	}
	if v, ok := opaqueString(props["repositoryToken"]); ok {
		params.Properties.RepositoryToken = stringPtr(v)
	}
	if raw, ok := props["buildProperties"].(map[string]any); ok {
		params.Properties.BuildProperties = buildStaticSiteBuildProperties(raw)
	}
	if v, ok := props["stagingEnvironmentPolicy"].(string); ok && v != "" {
		params.Properties.StagingEnvironmentPolicy = to.Ptr(armappservice.StagingEnvironmentPolicy(v))
	}
	if v, ok := props["allowConfigFileUpdates"].(bool); ok {
		params.Properties.AllowConfigFileUpdates = to.Ptr(v)
	}
	if v, ok := props["publicNetworkAccess"].(string); ok && v != "" {
		params.Properties.PublicNetworkAccess = stringPtr(v)
	}

	return params
}

// serializeStaticSiteProperties converts an ARM static site into formae property
// format. buildProperties and repositoryToken are write-only and are not emitted.
func serializeStaticSiteProperties(result armappservice.StaticSiteARMResource, rgName, siteName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = siteName
	}
	if result.Location != nil {
		props["location"] = normalizeAzureLocation(*result.Location)
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if sku := result.SKU; sku != nil {
		skuMap := make(map[string]any)
		if sku.Name != nil {
			skuMap["name"] = canonicalizeEnum(*sku.Name, "Free", "Standard")
		}
		if sku.Tier != nil {
			skuMap["tier"] = canonicalizeEnum(*sku.Tier, "Free", "Standard")
		}
		if len(skuMap) > 0 {
			props["sku"] = skuMap
		}
	}

	if p := result.Properties; p != nil {
		if p.RepositoryURL != nil && *p.RepositoryURL != "" {
			props["repositoryUrl"] = *p.RepositoryURL
		}
		if p.Branch != nil && *p.Branch != "" {
			props["branch"] = *p.Branch
		}
		if p.StagingEnvironmentPolicy != nil && *p.StagingEnvironmentPolicy != "" {
			props["stagingEnvironmentPolicy"] = canonicalizeEnum(string(*p.StagingEnvironmentPolicy), "Enabled", "Disabled")
		}
		if p.AllowConfigFileUpdates != nil {
			props["allowConfigFileUpdates"] = *p.AllowConfigFileUpdates
		}
		if p.PublicNetworkAccess != nil && *p.PublicNetworkAccess != "" {
			props["publicNetworkAccess"] = canonicalizeEnum(*p.PublicNetworkAccess, "Enabled", "Disabled")
		}
		if p.DefaultHostname != nil {
			props["defaultHostname"] = *p.DefaultHostname
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func (s *StaticSite) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	params := buildStaticSiteParams(props, location)
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := s.api.BeginCreateOrUpdateStaticSite(ctx, rgName, siteName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/staticSites/%s",
		s.config.SubscriptionId, rgName, siteName)

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
		propsJSON, err := serializeStaticSiteProperties(result.StaticSiteARMResource, rgName, siteName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize StaticSite properties: %w", err)
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

func (s *StaticSite) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, siteName, err := staticSiteIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or static site name from %s: %w", request.NativeID, err)
	}

	result, err := s.api.GetStaticSite(ctx, rgName, siteName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeStaticSiteProperties(result.StaticSiteARMResource, rgName, siteName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize StaticSite properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeStaticSite,
		Properties:   string(propsJSON),
	}, nil
}

func (s *StaticSite) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, siteName, err := staticSiteIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or static site name from %s: %w", request.NativeID, err)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params := buildStaticSiteParams(props, location)
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := s.api.BeginCreateOrUpdateStaticSite(ctx, rgName, siteName, params, nil)
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
		propsJSON, err := serializeStaticSiteProperties(result.StaticSiteARMResource, rgName, siteName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize StaticSite properties: %w", err)
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

func (s *StaticSite) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, siteName, err := staticSiteIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or static site name from %s: %w", request.NativeID, err)
	}

	poller, err := s.api.BeginDeleteStaticSite(ctx, rgName, siteName, nil)
	if err != nil {
		if isDeleteSuccessError(err) {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to start StaticSite deletion: %w", err)
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       operationErrorCode(err),
				},
			}, fmt.Errorf("failed to get StaticSite delete result: %w", err)
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}
	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (s *StaticSite) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
			func(token string) (*runtime.Poller[armappservice.StaticSitesClientCreateOrUpdateStaticSiteResponse], error) {
				return resumePoller[armappservice.StaticSitesClientCreateOrUpdateStaticSiteResponse](s.pipeline, token)
			},
			func(_ context.Context, result armappservice.StaticSitesClientCreateOrUpdateStaticSiteResponse, _ resource.Operation) (string, json.RawMessage, error) {
				if result.ID == nil {
					return "", nil, fmt.Errorf("StaticSite create/update returned no resource ID")
				}
				rgName, siteName, err := staticSiteIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := serializeStaticSiteProperties(result.StaticSiteARMResource, rgName, siteName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize StaticSite properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armappservice.StaticSitesClientDeleteStaticSiteResponse], error) {
				return resumePoller[armappservice.StaticSitesClientDeleteStaticSiteResponse](s.pipeline, token)
			}, nil)
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

func (s *StaticSite) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := s.api.NewGetStaticSitesByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list static sites: %w", err)
			}
			for _, site := range page.Value {
				if site != nil && site.ID != nil {
					nativeIDs = append(nativeIDs, *site.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := s.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list static sites: %w", err)
		}
		for _, site := range page.Value {
			if site != nil && site.ID != nil {
				nativeIDs = append(nativeIDs, *site.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
