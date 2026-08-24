// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/applicationinsights/armapplicationinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeAppInsightsComponent = "AZURE::Insights::Component"

// appInsightsComponentsAPI is the armapplicationinsights surface used here; all
// operations are synchronous.
type appInsightsComponentsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, insightProperties armapplicationinsights.Component, options *armapplicationinsights.ComponentsClientCreateOrUpdateOptions) (armapplicationinsights.ComponentsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, resourceName string, options *armapplicationinsights.ComponentsClientGetOptions) (armapplicationinsights.ComponentsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, resourceName string, options *armapplicationinsights.ComponentsClientDeleteOptions) (armapplicationinsights.ComponentsClientDeleteResponse, error)
	NewListPager(options *armapplicationinsights.ComponentsClientListOptions) *runtime.Pager[armapplicationinsights.ComponentsClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armapplicationinsights.ComponentsClientListByResourceGroupOptions) *runtime.Pager[armapplicationinsights.ComponentsClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeAppInsightsComponent, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AppInsightsComponent{api: c.AppInsightsComponentsClient, config: cfg}
	})
}

// AppInsightsComponent is the provisioner for Application Insights components
// (Microsoft.Insights/components).
//
// instrumentationKey and connectionString are never serialized: ARM returns them
// on read, but they are ingestion credentials and this plugin has no
// sensitive-output mechanism, so surfacing them would write live keys into
// resource state in the clear.
type AppInsightsComponent struct {
	api    appInsightsComponentsAPI
	config *config.Config
}

// appInsightsComponentProps mirrors schema/pkl/insights/component.pkl.
type appInsightsComponentProps struct {
	Name                            string   `json:"name"`
	Location                        string   `json:"location"`
	ResourceGroupName               string   `json:"resourceGroupName"`
	WorkspaceResourceID             string   `json:"workspaceResourceId"`
	Kind                            string   `json:"kind"`
	ApplicationType                 string   `json:"applicationType"`
	IngestionMode                   string   `json:"ingestionMode"`
	RetentionInDays                 *int32   `json:"retentionInDays"`
	SamplingPercentage              *float64 `json:"samplingPercentage"`
	DisableLocalAuth                *bool    `json:"disableLocalAuth"`
	PublicNetworkAccessForIngestion string   `json:"publicNetworkAccessForIngestion"`
	PublicNetworkAccessForQuery     string   `json:"publicNetworkAccessForQuery"`
}

func appInsightsComponentIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "components")
	if err != nil {
		return "", "", err
	}
	return rgName, names["components"], nil
}

func serializeAppInsightsComponent(c armapplicationinsights.Component, rgName, name string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"name":              name,
	}
	if c.Name != nil {
		props["name"] = *c.Name
	}
	if c.ID != nil {
		props["id"] = *c.ID
	}
	if c.Location != nil {
		props["location"] = strings.ToLower(strings.ReplaceAll(*c.Location, " ", ""))
	}
	if c.Kind != nil {
		props["kind"] = *c.Kind
	}

	if p := c.Properties; p != nil {
		if p.ApplicationType != nil {
			props["applicationType"] = string(*p.ApplicationType)
		}
		if p.IngestionMode != nil {
			props["ingestionMode"] = string(*p.IngestionMode)
		}
		if p.WorkspaceResourceID != nil {
			props["workspaceResourceId"] = *p.WorkspaceResourceID
		}
		if p.RetentionInDays != nil {
			props["retentionInDays"] = *p.RetentionInDays
		}
		if p.SamplingPercentage != nil {
			props["samplingPercentage"] = *p.SamplingPercentage
		}
		if p.DisableLocalAuth != nil {
			props["disableLocalAuth"] = *p.DisableLocalAuth
		}
		if p.PublicNetworkAccessForIngestion != nil {
			props["publicNetworkAccessForIngestion"] = string(*p.PublicNetworkAccessForIngestion)
		}
		if p.PublicNetworkAccessForQuery != nil {
			props["publicNetworkAccessForQuery"] = string(*p.PublicNetworkAccessForQuery)
		}
		// AppID is a query-API identifier, not a credential, so it is safe to
		// surface. InstrumentationKey and ConnectionString are NOT copied here.
		if p.AppID != nil {
			props["appId"] = *p.AppID
		}
	}

	if tags := azureTagsToFormaeTags(c.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func appInsightsComponentParams(props appInsightsComponentProps) armapplicationinsights.Component {
	appType := props.ApplicationType
	if appType == "" {
		appType = "web"
	}
	kind := props.Kind
	if kind == "" {
		kind = "web"
	}
	// Workspace-based components ingest through Log Analytics; classic components
	// are retired, so this is the default rather than an opt-in.
	ingestionMode := props.IngestionMode
	if ingestionMode == "" {
		ingestionMode = string(armapplicationinsights.IngestionModeLogAnalytics)
	}

	componentProps := &armapplicationinsights.ComponentProperties{
		ApplicationType: to.Ptr(armapplicationinsights.ApplicationType(appType)),
		IngestionMode:   to.Ptr(armapplicationinsights.IngestionMode(ingestionMode)),
	}
	if props.WorkspaceResourceID != "" {
		componentProps.WorkspaceResourceID = to.Ptr(props.WorkspaceResourceID)
	}
	if props.RetentionInDays != nil {
		componentProps.RetentionInDays = props.RetentionInDays
	}
	if props.SamplingPercentage != nil {
		componentProps.SamplingPercentage = props.SamplingPercentage
	}
	if props.DisableLocalAuth != nil {
		componentProps.DisableLocalAuth = props.DisableLocalAuth
	}
	if props.PublicNetworkAccessForIngestion != "" {
		componentProps.PublicNetworkAccessForIngestion = to.Ptr(armapplicationinsights.PublicNetworkAccessType(props.PublicNetworkAccessForIngestion))
	}
	if props.PublicNetworkAccessForQuery != "" {
		componentProps.PublicNetworkAccessForQuery = to.Ptr(armapplicationinsights.PublicNetworkAccessType(props.PublicNetworkAccessForQuery))
	}

	return armapplicationinsights.Component{
		Location:   to.Ptr(props.Location),
		Kind:       to.Ptr(kind),
		Properties: componentProps,
	}
}

// upsert backs both Create and Update: ARM's CreateOrUpdate replaces the component
// body, and UpdateTags only covers tags.
func (a *AppInsightsComponent) upsert(ctx context.Context, payload json.RawMessage, label string) (armapplicationinsights.Component, string, string, error) {
	var props appInsightsComponentProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armapplicationinsights.Component{}, "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return armapplicationinsights.Component{}, "", "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return armapplicationinsights.Component{}, "", "", fmt.Errorf("location is required")
	}
	if props.WorkspaceResourceID == "" {
		return armapplicationinsights.Component{}, "", "", fmt.Errorf("workspaceResourceId is required: classic non-workspace components are retired")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return armapplicationinsights.Component{}, "", "", fmt.Errorf("name is required")
	}

	params := appInsightsComponentParams(props)
	if azureTags := formaeTagsToAzureTags(payload); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := a.api.CreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return armapplicationinsights.Component{}, props.ResourceGroupName, name, err
	}
	return result.Component, props.ResourceGroupName, name, nil
}

func (a *AppInsightsComponent) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	comp, rgName, name, err := a.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if rgName == "" || name == "" {
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

	propsJSON, err := serializeAppInsightsComponent(comp, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Component properties: %w", err)
	}

	nativeID := ""
	if comp.ID != nil {
		nativeID = *comp.ID
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

func (a *AppInsightsComponent) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := appInsightsComponentIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeAppInsightsComponent(result.Component, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Component properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAppInsightsComponent,
		Properties:   string(propsJSON),
	}, nil
}

func (a *AppInsightsComponent) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	comp, rgName, name, err := a.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if rgName == "" || name == "" {
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

	propsJSON, err := serializeAppInsightsComponent(comp, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Component properties after update: %w", err)
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

func (a *AppInsightsComponent) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := appInsightsComponentIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := a.api.Delete(ctx, rgName, name, nil); err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
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

// Component writes are synchronous, so Status just re-reads.
func (a *AppInsightsComponent) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, name, err := appInsightsComponentIDParts(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	result, err := a.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to get Component status: %w", err)
	}

	propsJSON, err := serializeAppInsightsComponent(result.Component, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Component properties: %w", err)
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

func (a *AppInsightsComponent) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := a.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list application insights components: %w", err)
			}
			for _, comp := range page.Value {
				if comp.ID != nil {
					nativeIDs = append(nativeIDs, *comp.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := a.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list application insights components: %w", err)
		}
		for _, comp := range page.Value {
			if comp.ID != nil {
				nativeIDs = append(nativeIDs, *comp.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
