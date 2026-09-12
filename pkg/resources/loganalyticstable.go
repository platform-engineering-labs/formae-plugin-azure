// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeLogAnalyticsTable = "AZURE::OperationalInsights::Table"

// logAnalyticsTablesAPI is the whole of *armoperationalinsights.TablesClient at
// v1.2.0 (api-version 2020-08-01): a GET, a PATCH and a list.
//
// There is deliberately no create and no delete in this interface because the
// client HAS none. A workspace table is created by the workspace itself (every
// built-in table appears with the workspace) and cannot be removed, so this type
// adopts an existing table and owns only its retention. Create and Update are the
// same PATCH, and Delete resets retention to the workspace default rather than
// removing anything.
type logAnalyticsTablesAPI interface {
	Get(ctx context.Context, resourceGroupName, workspaceName, tableName string, options *armoperationalinsights.TablesClientGetOptions) (armoperationalinsights.TablesClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName, workspaceName, tableName string, parameters armoperationalinsights.Table, options *armoperationalinsights.TablesClientUpdateOptions) (armoperationalinsights.TablesClientUpdateResponse, error)
	NewListByWorkspacePager(resourceGroupName, workspaceName string, options *armoperationalinsights.TablesClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.TablesClientListByWorkspaceResponse]
}

func init() {
	registry.Register(ResourceTypeLogAnalyticsTable, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogAnalyticsTable{api: c.LogAnalyticsTablesClient, config: cfg}
	})
}

// LogAnalyticsTable is the provisioner for per-table retention on a Log Analytics
// workspace (`Microsoft.OperationalInsights/workspaces/<ws>/tables/<name>`). It is
// a child of AZURE::OperationalInsights::Workspace.
//
// The API is fully synchronous — the single PATCH returns a final answer.
type LogAnalyticsTable struct {
	api    logAnalyticsTablesAPI
	config *config.Config
}

// logAnalyticsTableProps mirrors
// schema/pkl/operationalinsights/loganalyticstable.pkl.
type logAnalyticsTableProps struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	WorkspaceName     string `json:"workspaceName"`
	RetentionInDays   int32  `json:"retentionInDays"`
}

func logAnalyticsTableIDParts(resourceID string) (rgName, workspaceName, tableName string, err error) {
	rgName, names, err := armIDParts(resourceID, "workspaces", "tables")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["workspaces"], names["tables"], nil
}

func (t *LogAnalyticsTable) buildPropertiesFromResult(table *armoperationalinsights.Table, rgName, workspaceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["workspaceName"] = workspaceName

	if table.ID != nil {
		props["id"] = *table.ID
	}
	if table.Name != nil {
		props["name"] = *table.Name
	}
	if p := table.Properties; p != nil && p.RetentionInDays != nil {
		props["retentionInDays"] = *p.RetentionInDays
	}

	return props
}

func (t *LogAnalyticsTable) parseProps(payload json.RawMessage, label string) (logAnalyticsTableProps, string, error) {
	var props logAnalyticsTableProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.WorkspaceName == "" {
		return props, "", fmt.Errorf("workspaceName is required")
	}
	if props.RetentionInDays == 0 {
		return props, "", fmt.Errorf("retentionInDays is required")
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

// logAnalyticsTableParams builds the PATCH body. It is the only write verb, so
// create and update share it.
func logAnalyticsTableParams(retentionInDays int32) armoperationalinsights.Table {
	return armoperationalinsights.Table{
		Properties: &armoperationalinsights.TableProperties{
			RetentionInDays: to.Ptr(retentionInDays),
		},
	}
}

// Create adopts an existing workspace table and sets its retention: the API has no
// PUT, and a table that the workspace has not created cannot be brought into
// existence from here.
func (t *LogAnalyticsTable) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := t.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Update(ctx, props.ResourceGroupName, props.WorkspaceName, name,
		logAnalyticsTableParams(props.RetentionInDays), nil)
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
	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.Table, props.ResourceGroupName, props.WorkspaceName))
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

func (t *LogAnalyticsTable) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, workspaceName, tableName, err := logAnalyticsTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Get(ctx, rgName, workspaceName, tableName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.Table, rgName, workspaceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogAnalyticsTable,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues the PATCH: retention is the only field this API version exposes.
func (t *LogAnalyticsTable) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, workspaceName, tableName, err := logAnalyticsTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := t.parseProps(request.DesiredProperties, tableName)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Update(ctx, rgName, workspaceName, tableName,
		logAnalyticsTableParams(props.RetentionInDays), nil)
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

	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.Table, rgName, workspaceName))
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

// Delete releases the table back to the workspace's own retention. The table
// itself survives — ARM offers no DELETE on a workspace table at this API version
// — so this is a relinquish, not a removal, and the resource will still be
// readable afterwards.
//
// azcore.NullValue is what sends an explicit JSON `null`: a nil *int32 is dropped
// from the PATCH body by the SDK's marshaller, which would leave the retention
// exactly as it was.
func (t *LogAnalyticsTable) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, workspaceName, tableName, err := logAnalyticsTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	reset := armoperationalinsights.Table{
		Properties: &armoperationalinsights.TableProperties{
			RetentionInDays: azcore.NullValue[*int32](),
		},
	}
	if _, err := t.api.Update(ctx, rgName, workspaceName, tableName, reset, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status can only ever be asked about an operation that already finished: the
// single write verb is synchronous.
func (t *LogAnalyticsTable) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the workspace: tables only exist
// inside one. Note that this enumerates every table the workspace has, built-in
// ones included — ARM offers no filter, and a workspace's built-in tables are
// real, addressable resources.
func (t *LogAnalyticsTable) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	workspaceName := request.AdditionalProperties["workspaceName"]
	if rgName == "" || workspaceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := t.api.NewListByWorkspacePager(rgName, workspaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list workspace tables: %w", err)
		}
		for _, table := range page.Value {
			if table != nil && table.ID != nil {
				nativeIDs = append(nativeIDs, *table.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
