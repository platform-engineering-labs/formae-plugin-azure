// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeLogAnalyticsLinkedStorageAccount = "AZURE::OperationalInsights::LinkedStorageAccount"

// logAnalyticsLinkedStorageAccountsAPI is the subset of
// *armoperationalinsights.LinkedStorageAccountsClient used here. Every operation is
// synchronous, CreateOrUpdate is also the update verb, and the data source type is
// passed as the resource's path segment rather than in the body.
type logAnalyticsLinkedStorageAccountsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, workspaceName string, dataSourceType armoperationalinsights.DataSourceType, parameters armoperationalinsights.LinkedStorageAccountsResource, options *armoperationalinsights.LinkedStorageAccountsClientCreateOrUpdateOptions) (armoperationalinsights.LinkedStorageAccountsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, workspaceName string, dataSourceType armoperationalinsights.DataSourceType, options *armoperationalinsights.LinkedStorageAccountsClientGetOptions) (armoperationalinsights.LinkedStorageAccountsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, workspaceName string, dataSourceType armoperationalinsights.DataSourceType, options *armoperationalinsights.LinkedStorageAccountsClientDeleteOptions) (armoperationalinsights.LinkedStorageAccountsClientDeleteResponse, error)
	NewListByWorkspacePager(resourceGroupName, workspaceName string, options *armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.LinkedStorageAccountsClientListByWorkspaceResponse]
}

func init() {
	registry.Register(ResourceTypeLogAnalyticsLinkedStorageAccount, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogAnalyticsLinkedStorageAccount{api: c.LogAnalyticsLinkedStorageAccountsClient, config: cfg}
	})
}

// LogAnalyticsLinkedStorageAccount is the provisioner for storage links
// (`Microsoft.OperationalInsights/workspaces/<ws>/linkedStorageAccounts/<type>`). It
// is a child of AZURE::OperationalInsights::Workspace.
type LogAnalyticsLinkedStorageAccount struct {
	api    logAnalyticsLinkedStorageAccountsAPI
	config *config.Config
}

// logAnalyticsLinkedStorageAccountProps mirrors
// schema/pkl/operationalinsights/linkedstorageaccount.pkl.
type logAnalyticsLinkedStorageAccountProps struct {
	Name              string   `json:"name"`
	ResourceGroupName string   `json:"resourceGroupName"`
	WorkspaceName     string   `json:"workspaceName"`
	StorageAccountIDs []string `json:"storageAccountIds"`
}

// logAnalyticsLinkedStorageAccountDataSourceTypes is the set ARM accepts as the
// resource's path segment.
var logAnalyticsLinkedStorageAccountDataSourceTypes = []string{"Alerts", "AzureWatson", "CustomLogs", "Query"}

func logAnalyticsLinkedStorageAccountIDParts(resourceID string) (rgName, workspaceName, dataSourceType string, err error) {
	rgName, names, err := armIDParts(resourceID, "workspaces", "linkedstorageaccounts")
	if err != nil {
		return "", "", "", err
	}
	// ARM answers with the type lower-cased in both the ID and the name; desired
	// state carries the enum's own casing, so canonicalize or every sync drifts.
	return rgName, names["workspaces"], canonicalizeEnum(names["linkedstorageaccounts"], logAnalyticsLinkedStorageAccountDataSourceTypes...), nil
}

func (l *LogAnalyticsLinkedStorageAccount) buildPropertiesFromResult(link *armoperationalinsights.LinkedStorageAccountsResource, rgName, workspaceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["workspaceName"] = workspaceName

	if link.ID != nil {
		props["id"] = *link.ID
	}

	if p := link.Properties; p != nil {
		if ids := stringsFromPointers(p.StorageAccountIDs); ids != nil {
			props["storageAccountIds"] = ids
		}
		// dataSourceType and the resource name are the same value; the property comes
		// from whichever ARM populated.
		if p.DataSourceType != nil {
			props["name"] = canonicalizeEnum(string(*p.DataSourceType), logAnalyticsLinkedStorageAccountDataSourceTypes...)
		}
	}
	if _, ok := props["name"]; !ok && link.Name != nil {
		props["name"] = canonicalizeEnum(*link.Name, logAnalyticsLinkedStorageAccountDataSourceTypes...)
	}

	return props
}

func (l *LogAnalyticsLinkedStorageAccount) parseProps(payload json.RawMessage, label string) (logAnalyticsLinkedStorageAccountProps, string, error) {
	var props logAnalyticsLinkedStorageAccountProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.WorkspaceName == "" {
		return props, "", fmt.Errorf("workspaceName is required")
	}
	if len(props.StorageAccountIDs) == 0 {
		return props, "", fmt.Errorf("storageAccountIds is required")
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

func (l *LogAnalyticsLinkedStorageAccount) write(ctx context.Context, rgName, workspaceName, dataSourceType string, ids []string) (armoperationalinsights.LinkedStorageAccountsClientCreateOrUpdateResponse, error) {
	// The body carries only the account IDs: the data source type travels in the URL.
	params := armoperationalinsights.LinkedStorageAccountsResource{
		Properties: &armoperationalinsights.LinkedStorageAccountsProperties{
			StorageAccountIDs: stringPointers(ids),
		},
	}
	return l.api.CreateOrUpdate(ctx, rgName, workspaceName,
		armoperationalinsights.DataSourceType(dataSourceType), params, nil)
}

func (l *LogAnalyticsLinkedStorageAccount) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := l.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := l.write(ctx, props.ResourceGroupName, props.WorkspaceName, name, props.StorageAccountIDs)
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
	propsJSON, err := json.Marshal(l.buildPropertiesFromResult(&result.LinkedStorageAccountsResource, props.ResourceGroupName, props.WorkspaceName))
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

func (l *LogAnalyticsLinkedStorageAccount) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, workspaceName, dataSourceType, err := logAnalyticsLinkedStorageAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := l.api.Get(ctx, rgName, workspaceName, armoperationalinsights.DataSourceType(dataSourceType), nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(l.buildPropertiesFromResult(&result.LinkedStorageAccountsResource, rgName, workspaceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogAnalyticsLinkedStorageAccount,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: it is the API's only write verb. Only the account
// list can change — the data source type is the resource's own address.
func (l *LogAnalyticsLinkedStorageAccount) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, workspaceName, dataSourceType, err := logAnalyticsLinkedStorageAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := l.parseProps(request.DesiredProperties, dataSourceType)
	if err != nil {
		return nil, err
	}

	result, err := l.write(ctx, rgName, workspaceName, dataSourceType, props.StorageAccountIDs)
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

	propsJSON, err := json.Marshal(l.buildPropertiesFromResult(&result.LinkedStorageAccountsResource, rgName, workspaceName))
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

func (l *LogAnalyticsLinkedStorageAccount) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, workspaceName, dataSourceType, err := logAnalyticsLinkedStorageAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := l.api.Delete(ctx, rgName, workspaceName, armoperationalinsights.DataSourceType(dataSourceType), nil); err != nil && !isDeleteSuccessError(err) {
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
func (l *LogAnalyticsLinkedStorageAccount) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the workspace: links only exist inside
// one.
func (l *LogAnalyticsLinkedStorageAccount) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	workspaceName := request.AdditionalProperties["workspaceName"]
	if rgName == "" || workspaceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := l.api.NewListByWorkspacePager(rgName, workspaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list linked storage accounts: %w", err)
		}
		for _, link := range page.Value {
			if link != nil && link.ID != nil {
				nativeIDs = append(nativeIDs, *link.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
