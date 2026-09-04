// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeLogAnalyticsDataSourceWindowsEvent = "AZURE::OperationalInsights::DataSourceWindowsEvent"

// logAnalyticsDataSourceWindowsEventKind is the ARM `kind` discriminator this
// provisioner owns. It is both the request-body field and the OData filter value
// that keeps List() from returning the other kinds' data sources.
const logAnalyticsDataSourceWindowsEventKind = armoperationalinsights.DataSourceKindWindowsEvent

// logAnalyticsDataSourceWindowsEventTypes is the set ARM accepts in an
// eventTypes entry.
var logAnalyticsDataSourceWindowsEventTypes = []string{"Error", "Warning", "Information"}

func init() {
	registry.Register(ResourceTypeLogAnalyticsDataSourceWindowsEvent, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogAnalyticsDataSourceWindowsEvent{api: c.LogAnalyticsDataSourcesClient, config: cfg}
	})
}

// LogAnalyticsDataSourceWindowsEvent is the provisioner for a WindowsEvent data
// source (`Microsoft.OperationalInsights/workspaces/<ws>/dataSources/<name>` with
// `kind: WindowsEvent`). It is a child of AZURE::OperationalInsights::Workspace,
// and tells the legacy Log Analytics agent which Windows event log to collect.
type LogAnalyticsDataSourceWindowsEvent struct {
	api    logAnalyticsDataSourcesAPI
	config *config.Config
}

// logAnalyticsDataSourceWindowsEventProps mirrors
// schema/pkl/operationalinsights/loganalyticsdatasourcewindowsevent.pkl. ARM's
// `eventTypes` is an array of single-key objects; the schema flattens it to a
// plain list of severities.
type logAnalyticsDataSourceWindowsEventProps struct {
	Name              string   `json:"name"`
	ResourceGroupName string   `json:"resourceGroupName"`
	WorkspaceName     string   `json:"workspaceName"`
	EventLogName      string   `json:"eventLogName"`
	EventTypes        []string `json:"eventTypes"`
}

func (d *LogAnalyticsDataSourceWindowsEvent) buildPropertiesFromResult(source *armoperationalinsights.DataSource, rgName, workspaceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["workspaceName"] = workspaceName

	if source.ID != nil {
		props["id"] = *source.ID
	}
	if source.Name != nil {
		props["name"] = *source.Name
	}

	blob := logAnalyticsDataSourceBlob(source.Properties)
	if blob != nil {
		if logName, ok := logAnalyticsDataSourceString(blob, "eventLogName"); ok {
			props["eventLogName"] = logName
		}
		if raw, ok := blob["eventTypes"].([]any); ok {
			eventTypes := make([]string, 0, len(raw))
			for _, entry := range raw {
				pair, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				value, ok := logAnalyticsDataSourceString(pair, "eventType")
				if !ok {
					continue
				}
				// ARM echoes the severity back with the casing it stored, which
				// is not always the casing the enum declares.
				eventTypes = append(eventTypes, canonicalizeEnum(value, logAnalyticsDataSourceWindowsEventTypes...))
			}
			if len(eventTypes) > 0 {
				props["eventTypes"] = eventTypes
			}
		}
	}

	// kind is fixed by the resource type, and etag is service state: neither is
	// modelled, so neither is surfaced.
	return props
}

// logAnalyticsDataSourceWindowsEventParams builds the request body shared by
// create and update. CreateOrUpdate is the API's only write verb.
func logAnalyticsDataSourceWindowsEventParams(props logAnalyticsDataSourceWindowsEventProps) armoperationalinsights.DataSource {
	eventTypes := make([]any, 0, len(props.EventTypes))
	for _, eventType := range props.EventTypes {
		eventTypes = append(eventTypes, map[string]any{"eventType": eventType})
	}

	return armoperationalinsights.DataSource{
		Kind: to.Ptr(logAnalyticsDataSourceWindowsEventKind),
		Properties: map[string]any{
			"eventLogName": props.EventLogName,
			"eventTypes":   eventTypes,
		},
	}
}

func (d *LogAnalyticsDataSourceWindowsEvent) parseProps(payload json.RawMessage, label string) (logAnalyticsDataSourceWindowsEventProps, string, error) {
	var props logAnalyticsDataSourceWindowsEventProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.WorkspaceName == "" {
		return props, "", fmt.Errorf("workspaceName is required")
	}
	if props.EventLogName == "" {
		return props, "", fmt.Errorf("eventLogName is required")
	}
	if len(props.EventTypes) == 0 {
		return props, "", fmt.Errorf("eventTypes is required")
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

func (d *LogAnalyticsDataSourceWindowsEvent) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := d.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := d.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.WorkspaceName, name,
		logAnalyticsDataSourceWindowsEventParams(props), nil)
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
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DataSource, props.ResourceGroupName, props.WorkspaceName))
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

func (d *LogAnalyticsDataSourceWindowsEvent) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, workspaceName, sourceName, err := logAnalyticsDataSourceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, workspaceName, sourceName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DataSource, rgName, workspaceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogAnalyticsDataSourceWindowsEvent,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: it is the API's only write verb.
func (d *LogAnalyticsDataSourceWindowsEvent) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, workspaceName, sourceName, err := logAnalyticsDataSourceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := d.parseProps(request.DesiredProperties, sourceName)
	if err != nil {
		return nil, err
	}

	result, err := d.api.CreateOrUpdate(ctx, rgName, workspaceName, sourceName,
		logAnalyticsDataSourceWindowsEventParams(props), nil)
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

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DataSource, rgName, workspaceName))
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

func (d *LogAnalyticsDataSourceWindowsEvent) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, workspaceName, sourceName, err := logAnalyticsDataSourceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := d.api.Delete(ctx, rgName, workspaceName, sourceName, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status can only ever be asked about an operation that already finished: every
// write here is synchronous.
func (d *LogAnalyticsDataSourceWindowsEvent) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the workspace: data sources only
// exist inside one. The kind filter is mandatory — ARM rejects the request
// without `$filter`, and it is also what stops this type enumerating the other
// kinds that share the `dataSources` collection.
func (d *LogAnalyticsDataSourceWindowsEvent) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	workspaceName := request.AdditionalProperties["workspaceName"]
	if rgName == "" || workspaceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListByWorkspacePager(rgName, workspaceName,
		logAnalyticsDataSourceKindFilter(logAnalyticsDataSourceWindowsEventKind), nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list windows event data sources: %w", err)
		}
		for _, source := range page.Value {
			if source != nil && source.ID != nil {
				nativeIDs = append(nativeIDs, *source.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
