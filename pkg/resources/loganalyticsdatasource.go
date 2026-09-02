// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
)

// logAnalyticsDataSourcesAPI is the subset of
// *armoperationalinsights.DataSourcesClient shared by every
// AZURE::OperationalInsights::DataSource* type.
//
// One ARM resource type (`workspaces/<ws>/dataSources/<name>`) backs all of them:
// the `kind` discriminator picks the shape of the untyped `properties` blob, and
// there is one Go type per kind because each kind's blob is a different schema.
// Every operation is synchronous — no LRO, no poller — and CreateOrUpdate is also
// the update verb.
//
// NewListByWorkspacePager takes the OData filter POSITIONALLY, not through the
// options struct: the ARM endpoint rejects a request without `$filter`, so a kind
// filter is mandatory rather than an optimisation. It is also what keeps the two
// kinds from enumerating each other's resources during discovery.
type logAnalyticsDataSourcesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, workspaceName, dataSourceName string, parameters armoperationalinsights.DataSource, options *armoperationalinsights.DataSourcesClientCreateOrUpdateOptions) (armoperationalinsights.DataSourcesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, workspaceName, dataSourceName string, options *armoperationalinsights.DataSourcesClientGetOptions) (armoperationalinsights.DataSourcesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, workspaceName, dataSourceName string, options *armoperationalinsights.DataSourcesClientDeleteOptions) (armoperationalinsights.DataSourcesClientDeleteResponse, error)
	NewListByWorkspacePager(resourceGroupName, workspaceName, filter string, options *armoperationalinsights.DataSourcesClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.DataSourcesClientListByWorkspaceResponse]
}

// logAnalyticsDataSourceIDParts splits a data source ARM ID into the resource
// group, the workspace name and the data source name.
func logAnalyticsDataSourceIDParts(resourceID string) (rgName, workspaceName, dataSourceName string, err error) {
	rgName, names, err := armIDParts(resourceID, "workspaces", "datasources")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["workspaces"], names["datasources"], nil
}

// logAnalyticsDataSourceKindFilter is the OData filter that narrows
// ListByWorkspace to a single kind. The SDK's own example uses this exact form
// (`kind='WindowsEvent'`), not the `kind eq '...'` spelling.
func logAnalyticsDataSourceKindFilter(kind armoperationalinsights.DataSourceKind) string {
	return fmt.Sprintf("kind='%s'", string(kind))
}

// logAnalyticsDataSourceBlob coerces the SDK's untyped `Properties any` into a
// map. ARM always answers with a JSON object here, but a nil or differently
// shaped body must not panic the read.
func logAnalyticsDataSourceBlob(properties any) map[string]any {
	blob, ok := properties.(map[string]any)
	if !ok {
		return nil
	}
	return blob
}

// logAnalyticsDataSourceString reads a string out of the properties blob,
// reporting whether it was present and non-empty.
func logAnalyticsDataSourceString(blob map[string]any, key string) (string, bool) {
	value, ok := blob[key].(string)
	if !ok || value == "" {
		return "", false
	}
	return value, true
}

// logAnalyticsDataSourceInt reads an integer out of the properties blob. ARM's
// numbers arrive as float64 through encoding/json, but a recorded fixture may
// hand back a Go int, so both are accepted.
func logAnalyticsDataSourceInt(blob map[string]any, key string) (int64, bool) {
	switch n := blob[key].(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int32:
		return int64(n), true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}
