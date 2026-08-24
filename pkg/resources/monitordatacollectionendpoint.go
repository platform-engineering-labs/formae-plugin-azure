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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeMonitorDataCollectionEndpoint = "AZURE::Insights::DataCollectionEndpoint"

// monitorDataCollectionEndpointsAPI is the subset of
// *armmonitor.DataCollectionEndpointsClient used here. Everything is synchronous.
// Update is deliberately absent: ResourceForUpdate carries only tags and identity,
// so it cannot change the description or the network access setting.
type monitorDataCollectionEndpointsAPI interface {
	Create(ctx context.Context, resourceGroupName, dataCollectionEndpointName string, body armmonitor.DataCollectionEndpointResource, options *armmonitor.DataCollectionEndpointsClientCreateOptions) (armmonitor.DataCollectionEndpointsClientCreateResponse, error)
	Get(ctx context.Context, resourceGroupName, dataCollectionEndpointName string, options *armmonitor.DataCollectionEndpointsClientGetOptions) (armmonitor.DataCollectionEndpointsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, dataCollectionEndpointName string, options *armmonitor.DataCollectionEndpointsClientDeleteOptions) (armmonitor.DataCollectionEndpointsClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armmonitor.DataCollectionEndpointsClientListByResourceGroupOptions) *runtime.Pager[armmonitor.DataCollectionEndpointsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armmonitor.DataCollectionEndpointsClientListBySubscriptionOptions) *runtime.Pager[armmonitor.DataCollectionEndpointsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeMonitorDataCollectionEndpoint, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MonitorDataCollectionEndpoint{api: c.MonitorDataCollectionEndpointsClient, config: cfg}
	})
}

// MonitorDataCollectionEndpoint is the provisioner for Azure Monitor ingestion
// endpoints (Microsoft.Insights/dataCollectionEndpoints).
type MonitorDataCollectionEndpoint struct {
	api    monitorDataCollectionEndpointsAPI
	config *config.Config
}

// monitorDataCollectionEndpointProps mirrors
// schema/pkl/insights/datacollectionendpoint.pkl. ARM's single-member networkAcls
// block is flattened into publicNetworkAccess.
type monitorDataCollectionEndpointProps struct {
	Name                string  `json:"name"`
	ResourceGroupName   string  `json:"resourceGroupName"`
	Location            string  `json:"location"`
	Kind                *string `json:"kind"`
	Description         *string `json:"description"`
	PublicNetworkAccess *string `json:"publicNetworkAccess"`
}

func monitorDataCollectionEndpointIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "datacollectionendpoints")
	if err != nil {
		return "", "", err
	}
	return rgName, names["datacollectionendpoints"], nil
}

func (m *MonitorDataCollectionEndpoint) buildPropertiesFromResult(endpoint *armmonitor.DataCollectionEndpointResource, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if endpoint.ID != nil {
		props["id"] = *endpoint.ID
	}
	if endpoint.Name != nil {
		props["name"] = *endpoint.Name
	}
	if endpoint.Location != nil {
		props["location"] = normalizeAzureLocation(*endpoint.Location)
	}
	if endpoint.Kind != nil {
		props["kind"] = canonicalizeEnum(string(*endpoint.Kind), "Linux", "Windows")
	}
	if tags := azureTagsToFormaeTags(endpoint.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	if p := endpoint.Properties; p != nil {
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		if p.ImmutableID != nil {
			props["immutableId"] = *p.ImmutableID
		}
		if acls := p.NetworkACLs; acls != nil && acls.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = canonicalizeEnum(string(*acls.PublicNetworkAccess),
				"Enabled", "Disabled", "SecuredByPerimeter")
		}
		// The service assigns these three; agents and data collection rules address
		// the endpoint through them.
		if p.LogsIngestion != nil && p.LogsIngestion.Endpoint != nil {
			props["logsIngestionEndpoint"] = *p.LogsIngestion.Endpoint
		}
		if p.MetricsIngestion != nil && p.MetricsIngestion.Endpoint != nil {
			props["metricsIngestionEndpoint"] = *p.MetricsIngestion.Endpoint
		}
		if p.ConfigurationAccess != nil && p.ConfigurationAccess.Endpoint != nil {
			props["configurationAccessEndpoint"] = *p.ConfigurationAccess.Endpoint
		}
		// provisioningState, metadata, failoverConfiguration and
		// privateLinkScopedResources are service state or unmodelled; systemData and
		// etag never belong in desired state.
	}

	return props
}

// monitorDataCollectionEndpointParams builds the request body shared by create and
// update.
func monitorDataCollectionEndpointParams(props monitorDataCollectionEndpointProps, payload json.RawMessage) armmonitor.DataCollectionEndpointResource {
	params := armmonitor.DataCollectionEndpointResource{
		Location:   to.Ptr(props.Location),
		Properties: &armmonitor.DataCollectionEndpointResourceProperties{},
	}

	if props.Kind != nil && *props.Kind != "" {
		params.Kind = to.Ptr(armmonitor.KnownDataCollectionEndpointResourceKind(*props.Kind))
	}
	if props.Description != nil {
		params.Properties.Description = props.Description
	}
	if props.PublicNetworkAccess != nil && *props.PublicNetworkAccess != "" {
		params.Properties.NetworkACLs = &armmonitor.DataCollectionEndpointNetworkACLs{
			PublicNetworkAccess: to.Ptr(armmonitor.KnownPublicNetworkAccessOptions(*props.PublicNetworkAccess)),
		}
	}
	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}

	return params
}

func (m *MonitorDataCollectionEndpoint) parseProps(payload json.RawMessage, label string) (monitorDataCollectionEndpointProps, string, error) {
	var props monitorDataCollectionEndpointProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return props, "", fmt.Errorf("location is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return props, "", fmt.Errorf("name is required")
	}
	return props, name, nil
}

func (m *MonitorDataCollectionEndpoint) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := m.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Create(ctx, props.ResourceGroupName, name,
		monitorDataCollectionEndpointParams(props, request.Properties), nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.DataCollectionEndpointResource, props.ResourceGroupName))
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

func (m *MonitorDataCollectionEndpoint) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := monitorDataCollectionEndpointIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.DataCollectionEndpointResource, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMonitorDataCollectionEndpoint,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through Create. The SDK's Update verb takes ResourceForUpdate,
// which carries only tags and identity, so it cannot change the description or the
// network access setting; location rides along because a PUT without it is rejected.
func (m *MonitorDataCollectionEndpoint) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := monitorDataCollectionEndpointIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := m.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Create(ctx, rgName, name,
		monitorDataCollectionEndpointParams(props, request.DesiredProperties), nil)
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

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.DataCollectionEndpointResource, rgName))
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

func (m *MonitorDataCollectionEndpoint) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := monitorDataCollectionEndpointIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := m.api.Delete(ctx, rgName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status can only ever be asked about an operation that already finished: every
// write here is synchronous.
func (m *MonitorDataCollectionEndpoint) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List narrows to a resource group when one is given, and otherwise walks the whole
// subscription.
func (m *MonitorDataCollectionEndpoint) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := m.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list data collection endpoints: %w", err)
			}
			for _, endpoint := range page.Value {
				if endpoint != nil && endpoint.ID != nil {
					nativeIDs = append(nativeIDs, *endpoint.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := m.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list data collection endpoints: %w", err)
		}
		for _, endpoint := range page.Value {
			if endpoint != nil && endpoint.ID != nil {
				nativeIDs = append(nativeIDs, *endpoint.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
