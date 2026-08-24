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

const ResourceTypeMonitorDataCollectionRule = "AZURE::Insights::DataCollectionRule"

// monitorDataCollectionRulesAPI is the subset of
// *armmonitor.DataCollectionRulesClient used here. Everything is synchronous. As
// with data collection endpoints, the SDK's Update verb takes ResourceForUpdate
// (tags and identity only), so it cannot carry a change to the rule itself.
type monitorDataCollectionRulesAPI interface {
	Create(ctx context.Context, resourceGroupName, dataCollectionRuleName string, body armmonitor.DataCollectionRuleResource, options *armmonitor.DataCollectionRulesClientCreateOptions) (armmonitor.DataCollectionRulesClientCreateResponse, error)
	Get(ctx context.Context, resourceGroupName, dataCollectionRuleName string, options *armmonitor.DataCollectionRulesClientGetOptions) (armmonitor.DataCollectionRulesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, dataCollectionRuleName string, options *armmonitor.DataCollectionRulesClientDeleteOptions) (armmonitor.DataCollectionRulesClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armmonitor.DataCollectionRulesClientListByResourceGroupOptions) *runtime.Pager[armmonitor.DataCollectionRulesClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armmonitor.DataCollectionRulesClientListBySubscriptionOptions) *runtime.Pager[armmonitor.DataCollectionRulesClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeMonitorDataCollectionRule, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MonitorDataCollectionRule{api: c.MonitorDataCollectionRulesClient, config: cfg}
	})
}

// MonitorDataCollectionRule is the provisioner for Azure Monitor Agent collection
// rules (Microsoft.Insights/dataCollectionRules).
type MonitorDataCollectionRule struct {
	api    monitorDataCollectionRulesAPI
	config *config.Config
}

// monitorDataCollectionRuleProps mirrors
// schema/pkl/insights/datacollectionrule.pkl. ARM's nested dataSources and
// destinations unions are flattened to the one member of each that is modelled.
type monitorDataCollectionRuleProps struct {
	Name                     string                            `json:"name"`
	ResourceGroupName        string                            `json:"resourceGroupName"`
	Location                 string                            `json:"location"`
	Kind                     *string                           `json:"kind"`
	Description              *string                           `json:"description"`
	DataCollectionEndpointID *string                           `json:"dataCollectionEndpointId"`
	PerformanceCounters      []monitorDCRPerfCounterProps      `json:"performanceCounters"`
	LogAnalyticsDestinations []monitorDCRLogAnalyticsDestProps `json:"logAnalyticsDestinations"`
	DataFlows                []monitorDCRDataFlowProps         `json:"dataFlows"`
}

type monitorDCRPerfCounterProps struct {
	Name                       string   `json:"name"`
	Streams                    []string `json:"streams"`
	SamplingFrequencyInSeconds *int32   `json:"samplingFrequencyInSeconds"`
	CounterSpecifiers          []string `json:"counterSpecifiers"`
}

type monitorDCRLogAnalyticsDestProps struct {
	Name                string `json:"name"`
	WorkspaceResourceID string `json:"workspaceResourceId"`
}

type monitorDCRDataFlowProps struct {
	Streams      []string `json:"streams"`
	Destinations []string `json:"destinations"`
	TransformKql *string  `json:"transformKql"`
	OutputStream *string  `json:"outputStream"`
}

func monitorDataCollectionRuleIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "datacollectionrules")
	if err != nil {
		return "", "", err
	}
	return rgName, names["datacollectionrules"], nil
}

func (m *MonitorDataCollectionRule) buildPropertiesFromResult(rule *armmonitor.DataCollectionRuleResource, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if rule.ID != nil {
		props["id"] = *rule.ID
	}
	if rule.Name != nil {
		props["name"] = *rule.Name
	}
	if rule.Location != nil {
		props["location"] = normalizeAzureLocation(*rule.Location)
	}
	if rule.Kind != nil {
		props["kind"] = canonicalizeEnum(string(*rule.Kind), "Linux", "Windows")
	}
	if tags := azureTagsToFormaeTags(rule.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	p := rule.Properties
	if p == nil {
		return props
	}

	if p.Description != nil && *p.Description != "" {
		props["description"] = *p.Description
	}
	if p.DataCollectionEndpointID != nil && *p.DataCollectionEndpointID != "" {
		props["dataCollectionEndpointId"] = *p.DataCollectionEndpointID
	}
	if p.ImmutableID != nil {
		props["immutableId"] = *p.ImmutableID
	}

	// Only the modelled member of each union is read back. The other thirteen data
	// source kinds and nine destination kinds are skipped rather than half-read: a
	// shape the schema cannot express would show as drift on every sync.
	if ds := p.DataSources; ds != nil {
		counters := make([]map[string]any, 0, len(ds.PerformanceCounters))
		for _, counter := range ds.PerformanceCounters {
			if counter == nil {
				continue
			}
			entry := make(map[string]any)
			if counter.Name != nil {
				entry["name"] = *counter.Name
			}
			if counter.SamplingFrequencyInSeconds != nil {
				entry["samplingFrequencyInSeconds"] = *counter.SamplingFrequencyInSeconds
			}
			if specs := stringsFromPointers(counter.CounterSpecifiers); specs != nil {
				entry["counterSpecifiers"] = specs
			}
			if streams := monitorDCRStreamStrings(counter.Streams); streams != nil {
				entry["streams"] = streams
			}
			// transformKql on a data source is not modelled.
			counters = append(counters, entry)
		}
		if len(counters) > 0 {
			props["performanceCounters"] = counters
		}
	}

	if dest := p.Destinations; dest != nil {
		destinations := make([]map[string]any, 0, len(dest.LogAnalytics))
		for _, logAnalytics := range dest.LogAnalytics {
			if logAnalytics == nil {
				continue
			}
			entry := make(map[string]any)
			if logAnalytics.Name != nil {
				entry["name"] = *logAnalytics.Name
			}
			if logAnalytics.WorkspaceResourceID != nil {
				entry["workspaceResourceId"] = *logAnalytics.WorkspaceResourceID
			}
			// workspaceId is the service's own GUID for the workspace. It lives on a
			// nested class, where hasProviderDefault is not honored, so reading it
			// back would drift forever.
			destinations = append(destinations, entry)
		}
		if len(destinations) > 0 {
			props["logAnalyticsDestinations"] = destinations
		}
	}

	flows := make([]map[string]any, 0, len(p.DataFlows))
	for _, flow := range p.DataFlows {
		if flow == nil {
			continue
		}
		entry := make(map[string]any)
		if streams := monitorDCRDataFlowStreamStrings(flow.Streams); streams != nil {
			entry["streams"] = streams
		}
		if destinations := stringsFromPointers(flow.Destinations); destinations != nil {
			entry["destinations"] = destinations
		}
		if flow.TransformKql != nil && *flow.TransformKql != "" {
			entry["transformKql"] = *flow.TransformKql
		}
		if flow.OutputStream != nil && *flow.OutputStream != "" {
			entry["outputStream"] = *flow.OutputStream
		}
		// builtInTransform and captureOverflow are not modelled.
		flows = append(flows, entry)
	}
	if len(flows) > 0 {
		props["dataFlows"] = flows
	}

	// provisioningState, metadata, agentSettings, references, streamDeclarations,
	// endpoints and ingestionQuotas are service state or unmodelled; systemData and
	// etag never belong in desired state.
	return props
}

func monitorDCRStreamStrings(streams []*armmonitor.KnownPerfCounterDataSourceStreams) []string {
	if len(streams) == 0 {
		return nil
	}
	out := make([]string, 0, len(streams))
	for _, stream := range streams {
		if stream == nil {
			continue
		}
		out = append(out, string(*stream))
	}
	return out
}

func monitorDCRDataFlowStreamStrings(streams []*armmonitor.KnownDataFlowStreams) []string {
	if len(streams) == 0 {
		return nil
	}
	out := make([]string, 0, len(streams))
	for _, stream := range streams {
		if stream == nil {
			continue
		}
		out = append(out, string(*stream))
	}
	return out
}

// monitorDataCollectionRuleParams builds the request body shared by create and
// update.
func monitorDataCollectionRuleParams(props monitorDataCollectionRuleProps, payload json.RawMessage) armmonitor.DataCollectionRuleResource {
	counters := make([]*armmonitor.PerfCounterDataSource, 0, len(props.PerformanceCounters))
	for _, counter := range props.PerformanceCounters {
		streams := make([]*armmonitor.KnownPerfCounterDataSourceStreams, 0, len(counter.Streams))
		for _, stream := range counter.Streams {
			streams = append(streams, to.Ptr(armmonitor.KnownPerfCounterDataSourceStreams(stream)))
		}
		counters = append(counters, &armmonitor.PerfCounterDataSource{
			Name:                       to.Ptr(counter.Name),
			Streams:                    streams,
			SamplingFrequencyInSeconds: counter.SamplingFrequencyInSeconds,
			CounterSpecifiers:          stringPointers(counter.CounterSpecifiers),
		})
	}

	destinations := make([]*armmonitor.LogAnalyticsDestination, 0, len(props.LogAnalyticsDestinations))
	for _, destination := range props.LogAnalyticsDestinations {
		destinations = append(destinations, &armmonitor.LogAnalyticsDestination{
			Name:                to.Ptr(destination.Name),
			WorkspaceResourceID: to.Ptr(destination.WorkspaceResourceID),
		})
	}

	flows := make([]*armmonitor.DataFlow, 0, len(props.DataFlows))
	for _, flow := range props.DataFlows {
		streams := make([]*armmonitor.KnownDataFlowStreams, 0, len(flow.Streams))
		for _, stream := range flow.Streams {
			streams = append(streams, to.Ptr(armmonitor.KnownDataFlowStreams(stream)))
		}
		flows = append(flows, &armmonitor.DataFlow{
			Streams:      streams,
			Destinations: stringPointers(flow.Destinations),
			TransformKql: flow.TransformKql,
			OutputStream: flow.OutputStream,
		})
	}

	params := armmonitor.DataCollectionRuleResource{
		Location: to.Ptr(props.Location),
		Properties: &armmonitor.DataCollectionRuleResourceProperties{
			DataSources:  &armmonitor.DataCollectionRuleDataSources{PerformanceCounters: counters},
			Destinations: &armmonitor.DataCollectionRuleDestinations{LogAnalytics: destinations},
			DataFlows:    flows,
			Description:  props.Description,
		},
	}

	if props.Kind != nil && *props.Kind != "" {
		params.Kind = to.Ptr(armmonitor.KnownDataCollectionRuleResourceKind(*props.Kind))
	}
	if props.DataCollectionEndpointID != nil && *props.DataCollectionEndpointID != "" {
		params.Properties.DataCollectionEndpointID = props.DataCollectionEndpointID
	}
	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}

	return params
}

func (m *MonitorDataCollectionRule) parseProps(payload json.RawMessage, label string) (monitorDataCollectionRuleProps, string, error) {
	var props monitorDataCollectionRuleProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return props, "", fmt.Errorf("location is required")
	}
	if len(props.PerformanceCounters) == 0 {
		return props, "", fmt.Errorf("performanceCounters is required")
	}
	if len(props.LogAnalyticsDestinations) == 0 {
		return props, "", fmt.Errorf("logAnalyticsDestinations is required")
	}
	if len(props.DataFlows) == 0 {
		return props, "", fmt.Errorf("dataFlows is required")
	}
	for _, counter := range props.PerformanceCounters {
		if counter.SamplingFrequencyInSeconds == nil {
			return props, "", fmt.Errorf("performanceCounters[].samplingFrequencyInSeconds is required")
		}
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

func (m *MonitorDataCollectionRule) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := m.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Create(ctx, props.ResourceGroupName, name,
		monitorDataCollectionRuleParams(props, request.Properties), nil)
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
	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.DataCollectionRuleResource, props.ResourceGroupName))
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

func (m *MonitorDataCollectionRule) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := monitorDataCollectionRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.DataCollectionRuleResource, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMonitorDataCollectionRule,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs through Create: ResourceForUpdate carries only tags and identity,
// so it cannot change data sources, destinations or flows. Location rides along
// because a PUT without it is rejected.
func (m *MonitorDataCollectionRule) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := monitorDataCollectionRuleIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := m.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Create(ctx, rgName, name,
		monitorDataCollectionRuleParams(props, request.DesiredProperties), nil)
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

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.DataCollectionRuleResource, rgName))
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

func (m *MonitorDataCollectionRule) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := monitorDataCollectionRuleIDParts(request.NativeID)
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
func (m *MonitorDataCollectionRule) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List narrows to a resource group when one is given, and otherwise walks the whole
// subscription.
func (m *MonitorDataCollectionRule) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := m.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list data collection rules: %w", err)
			}
			for _, rule := range page.Value {
				if rule != nil && rule.ID != nil {
					nativeIDs = append(nativeIDs, *rule.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := m.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list data collection rules: %w", err)
		}
		for _, rule := range page.Value {
			if rule != nil && rule.ID != nil {
				nativeIDs = append(nativeIDs, *rule.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
