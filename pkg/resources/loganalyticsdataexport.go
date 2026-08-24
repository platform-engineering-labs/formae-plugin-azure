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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeLogAnalyticsDataExport = "AZURE::OperationalInsights::DataExport"

// logAnalyticsDataExportsAPI is the subset of *armoperationalinsights.DataExportsClient
// used here. Every operation is synchronous — no LRO, no poller — and CreateOrUpdate
// is also the update verb.
type logAnalyticsDataExportsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, workspaceName, dataExportName string, parameters armoperationalinsights.DataExport, options *armoperationalinsights.DataExportsClientCreateOrUpdateOptions) (armoperationalinsights.DataExportsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, workspaceName, dataExportName string, options *armoperationalinsights.DataExportsClientGetOptions) (armoperationalinsights.DataExportsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, workspaceName, dataExportName string, options *armoperationalinsights.DataExportsClientDeleteOptions) (armoperationalinsights.DataExportsClientDeleteResponse, error)
	NewListByWorkspacePager(resourceGroupName, workspaceName string, options *armoperationalinsights.DataExportsClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.DataExportsClientListByWorkspaceResponse]
}

func init() {
	registry.Register(ResourceTypeLogAnalyticsDataExport, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogAnalyticsDataExport{api: c.LogAnalyticsDataExportsClient, config: cfg}
	})
}

// LogAnalyticsDataExport is the provisioner for continuous export rules
// (`Microsoft.OperationalInsights/workspaces/<ws>/dataExports/<name>`). It is a
// child of AZURE::OperationalInsights::Workspace.
type LogAnalyticsDataExport struct {
	api    logAnalyticsDataExportsAPI
	config *config.Config
}

// logAnalyticsDataExportProps mirrors
// schema/pkl/operationalinsights/dataexport.pkl. ARM's nested destination block is
// flattened: its type is derived by the service from the resource ID.
type logAnalyticsDataExportProps struct {
	Name                  string   `json:"name"`
	ResourceGroupName     string   `json:"resourceGroupName"`
	WorkspaceName         string   `json:"workspaceName"`
	TableNames            []string `json:"tableNames"`
	DestinationResourceID string   `json:"destinationResourceId"`
	EventHubName          *string  `json:"eventHubName"`
	Enable                *bool    `json:"enable"`
}

func logAnalyticsDataExportIDParts(resourceID string) (rgName, workspaceName, exportName string, err error) {
	rgName, names, err := armIDParts(resourceID, "workspaces", "dataexports")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["workspaces"], names["dataexports"], nil
}

func (d *LogAnalyticsDataExport) buildPropertiesFromResult(export *armoperationalinsights.DataExport, rgName, workspaceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["workspaceName"] = workspaceName

	if export.ID != nil {
		props["id"] = *export.ID
	}
	if export.Name != nil {
		props["name"] = *export.Name
	}

	if p := export.Properties; p != nil {
		if tables := stringsFromPointers(p.TableNames); tables != nil {
			props["tableNames"] = tables
		}
		if p.Enable != nil {
			props["enable"] = *p.Enable
		}
		if dest := p.Destination; dest != nil {
			if dest.ResourceID != nil {
				props["destinationResourceId"] = *dest.ResourceID
			}
			if dest.MetaData != nil && dest.MetaData.EventHubName != nil && *dest.MetaData.EventHubName != "" {
				props["eventHubName"] = *dest.MetaData.EventHubName
			}
			// destination.type is derived from the resource ID by the service, and
			// the schema cannot express it, so it stays out of state.
		}
		// createdDate, lastModifiedDate and dataExportId are service state.
	}

	return props
}

// logAnalyticsDataExportParams builds the request body shared by create and update:
// CreateOrUpdate is the only write verb.
func logAnalyticsDataExportParams(props logAnalyticsDataExportProps) armoperationalinsights.DataExport {
	destination := &armoperationalinsights.Destination{
		ResourceID: to.Ptr(props.DestinationResourceID),
	}
	// Only an event hub destination takes this, and ARM rejects an empty metadata
	// block on a storage account.
	if props.EventHubName != nil && *props.EventHubName != "" {
		destination.MetaData = &armoperationalinsights.DestinationMetaData{
			EventHubName: props.EventHubName,
		}
	}

	return armoperationalinsights.DataExport{
		Properties: &armoperationalinsights.DataExportProperties{
			TableNames:  stringPointers(props.TableNames),
			Destination: destination,
			Enable:      props.Enable,
		},
	}
}

func (d *LogAnalyticsDataExport) parseProps(payload json.RawMessage, label string) (logAnalyticsDataExportProps, string, error) {
	var props logAnalyticsDataExportProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.WorkspaceName == "" {
		return props, "", fmt.Errorf("workspaceName is required")
	}
	if len(props.TableNames) == 0 {
		return props, "", fmt.Errorf("tableNames is required")
	}
	if props.DestinationResourceID == "" {
		return props, "", fmt.Errorf("destinationResourceId is required")
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

func (d *LogAnalyticsDataExport) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := d.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := d.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.WorkspaceName, name,
		logAnalyticsDataExportParams(props), nil)
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
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DataExport, props.ResourceGroupName, props.WorkspaceName))
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

func (d *LogAnalyticsDataExport) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, workspaceName, exportName, err := logAnalyticsDataExportIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, workspaceName, exportName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DataExport, rgName, workspaceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogAnalyticsDataExport,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: it is the API's only write verb.
func (d *LogAnalyticsDataExport) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, workspaceName, exportName, err := logAnalyticsDataExportIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := d.parseProps(request.DesiredProperties, exportName)
	if err != nil {
		return nil, err
	}

	result, err := d.api.CreateOrUpdate(ctx, rgName, workspaceName, exportName,
		logAnalyticsDataExportParams(props), nil)
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

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DataExport, rgName, workspaceName))
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

func (d *LogAnalyticsDataExport) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, workspaceName, exportName, err := logAnalyticsDataExportIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := d.api.Delete(ctx, rgName, workspaceName, exportName, nil); err != nil && !isDeleteSuccessError(err) {
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
func (d *LogAnalyticsDataExport) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the workspace: export rules only exist
// inside one.
func (d *LogAnalyticsDataExport) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	workspaceName := request.AdditionalProperties["workspaceName"]
	if rgName == "" || workspaceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := d.api.NewListByWorkspacePager(rgName, workspaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list data exports: %w", err)
		}
		for _, export := range page.Value {
			if export != nil && export.ID != nil {
				nativeIDs = append(nativeIDs, *export.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
