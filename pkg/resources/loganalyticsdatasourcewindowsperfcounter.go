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

const ResourceTypeLogAnalyticsDataSourceWindowsPerfCounter = "AZURE::OperationalInsights::DataSourceWindowsPerformanceCounter"

// logAnalyticsDataSourceWindowsPerfCounterKind is the ARM `kind` discriminator
// this provisioner owns. It is both the request-body field and the OData filter
// value that keeps List() from returning the other kinds' data sources.
const logAnalyticsDataSourceWindowsPerfCounterKind = armoperationalinsights.DataSourceKindWindowsPerformanceCounter

func init() {
	registry.Register(ResourceTypeLogAnalyticsDataSourceWindowsPerfCounter, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogAnalyticsDataSourceWindowsPerfCounter{api: c.LogAnalyticsDataSourcesClient, config: cfg}
	})
}

// LogAnalyticsDataSourceWindowsPerfCounter is the provisioner for a
// WindowsPerformanceCounter data source
// (`Microsoft.OperationalInsights/workspaces/<ws>/dataSources/<name>` with
// `kind: WindowsPerformanceCounter`). It is a child of
// AZURE::OperationalInsights::Workspace, and tells the legacy Log Analytics agent
// which perfmon counter to sample and how often.
type LogAnalyticsDataSourceWindowsPerfCounter struct {
	api    logAnalyticsDataSourcesAPI
	config *config.Config
}

// logAnalyticsDataSourceWindowsPerfCounterProps mirrors
// schema/pkl/operationalinsights/loganalyticsdatasourcewindowsperfcounter.pkl.
type logAnalyticsDataSourceWindowsPerfCounterProps struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	WorkspaceName     string `json:"workspaceName"`
	ObjectName        string `json:"objectName"`
	InstanceName      string `json:"instanceName"`
	CounterName       string `json:"counterName"`
	IntervalSeconds   int64  `json:"intervalSeconds"`
}

func (d *LogAnalyticsDataSourceWindowsPerfCounter) buildPropertiesFromResult(source *armoperationalinsights.DataSource, rgName, workspaceName string) map[string]any {
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
		if value, ok := logAnalyticsDataSourceString(blob, "objectName"); ok {
			props["objectName"] = value
		}
		if value, ok := logAnalyticsDataSourceString(blob, "instanceName"); ok {
			props["instanceName"] = value
		}
		if value, ok := logAnalyticsDataSourceString(blob, "counterName"); ok {
			props["counterName"] = value
		}
		if value, ok := logAnalyticsDataSourceInt(blob, "intervalSeconds"); ok {
			props["intervalSeconds"] = value
		}
	}

	// kind is fixed by the resource type, and etag is service state: neither is
	// modelled, so neither is surfaced.
	return props
}

// logAnalyticsDataSourceWindowsPerfCounterParams builds the request body shared
// by create and update. CreateOrUpdate is the API's only write verb.
func logAnalyticsDataSourceWindowsPerfCounterParams(props logAnalyticsDataSourceWindowsPerfCounterProps) armoperationalinsights.DataSource {
	return armoperationalinsights.DataSource{
		Kind: to.Ptr(logAnalyticsDataSourceWindowsPerfCounterKind),
		Properties: map[string]any{
			"objectName":      props.ObjectName,
			"instanceName":    props.InstanceName,
			"counterName":     props.CounterName,
			"intervalSeconds": props.IntervalSeconds,
		},
	}
}

func (d *LogAnalyticsDataSourceWindowsPerfCounter) parseProps(payload json.RawMessage, label string) (logAnalyticsDataSourceWindowsPerfCounterProps, string, error) {
	var props logAnalyticsDataSourceWindowsPerfCounterProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.WorkspaceName == "" {
		return props, "", fmt.Errorf("workspaceName is required")
	}
	if props.ObjectName == "" {
		return props, "", fmt.Errorf("objectName is required")
	}
	if props.InstanceName == "" {
		return props, "", fmt.Errorf("instanceName is required")
	}
	if props.CounterName == "" {
		return props, "", fmt.Errorf("counterName is required")
	}
	if props.IntervalSeconds <= 0 {
		return props, "", fmt.Errorf("intervalSeconds is required")
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

func (d *LogAnalyticsDataSourceWindowsPerfCounter) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := d.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := d.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.WorkspaceName, name,
		logAnalyticsDataSourceWindowsPerfCounterParams(props), nil)
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

func (d *LogAnalyticsDataSourceWindowsPerfCounter) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
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
		ResourceType: ResourceTypeLogAnalyticsDataSourceWindowsPerfCounter,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: it is the API's only write verb.
func (d *LogAnalyticsDataSourceWindowsPerfCounter) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, workspaceName, sourceName, err := logAnalyticsDataSourceIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := d.parseProps(request.DesiredProperties, sourceName)
	if err != nil {
		return nil, err
	}

	result, err := d.api.CreateOrUpdate(ctx, rgName, workspaceName, sourceName,
		logAnalyticsDataSourceWindowsPerfCounterParams(props), nil)
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

func (d *LogAnalyticsDataSourceWindowsPerfCounter) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
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
func (d *LogAnalyticsDataSourceWindowsPerfCounter) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
func (d *LogAnalyticsDataSourceWindowsPerfCounter) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	workspaceName := request.AdditionalProperties["workspaceName"]
	if rgName == "" || workspaceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListByWorkspacePager(rgName, workspaceName,
		logAnalyticsDataSourceKindFilter(logAnalyticsDataSourceWindowsPerfCounterKind), nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list windows performance counter data sources: %w", err)
		}
		for _, source := range page.Value {
			if source != nil && source.ID != nil {
				nativeIDs = append(nativeIDs, *source.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
