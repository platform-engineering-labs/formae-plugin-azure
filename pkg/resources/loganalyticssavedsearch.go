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

const ResourceTypeLogAnalyticsSavedSearch = "AZURE::OperationalInsights::SavedSearch"

// logAnalyticsSavedSearchesAPI is the subset of *armoperationalinsights.SavedSearchesClient
// used here. Every operation is synchronous — there is no LRO and no poller — and
// CreateOrUpdate doubles as the update verb. ListByWorkspace returns one response
// rather than a pager.
type logAnalyticsSavedSearchesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, workspaceName, savedSearchID string, parameters armoperationalinsights.SavedSearch, options *armoperationalinsights.SavedSearchesClientCreateOrUpdateOptions) (armoperationalinsights.SavedSearchesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, workspaceName, savedSearchID string, options *armoperationalinsights.SavedSearchesClientGetOptions) (armoperationalinsights.SavedSearchesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, workspaceName, savedSearchID string, options *armoperationalinsights.SavedSearchesClientDeleteOptions) (armoperationalinsights.SavedSearchesClientDeleteResponse, error)
	ListByWorkspace(ctx context.Context, resourceGroupName, workspaceName string, options *armoperationalinsights.SavedSearchesClientListByWorkspaceOptions) (armoperationalinsights.SavedSearchesClientListByWorkspaceResponse, error)
}

func init() {
	registry.Register(ResourceTypeLogAnalyticsSavedSearch, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogAnalyticsSavedSearch{api: c.LogAnalyticsSavedSearchesClient, config: cfg}
	})
}

// LogAnalyticsSavedSearch is the provisioner for stored KQL queries
// (`Microsoft.OperationalInsights/workspaces/<ws>/savedSearches/<id>`). It is a
// child of AZURE::OperationalInsights::Workspace.
type LogAnalyticsSavedSearch struct {
	api    logAnalyticsSavedSearchesAPI
	config *config.Config
}

// logAnalyticsSavedSearchProps mirrors
// schema/pkl/operationalinsights/savedsearch.pkl.
type logAnalyticsSavedSearchProps struct {
	Name               string  `json:"name"`
	ResourceGroupName  string  `json:"resourceGroupName"`
	WorkspaceName      string  `json:"workspaceName"`
	Category           string  `json:"category"`
	DisplayName        string  `json:"displayName"`
	Query              string  `json:"query"`
	FunctionAlias      *string `json:"functionAlias"`
	FunctionParameters *string `json:"functionParameters"`
	Version            *int64  `json:"version"`
}

func logAnalyticsSavedSearchIDParts(resourceID string) (rgName, workspaceName, searchID string, err error) {
	rgName, names, err := armIDParts(resourceID, "workspaces", "savedsearches")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["workspaces"], names["savedsearches"], nil
}

func (s *LogAnalyticsSavedSearch) buildPropertiesFromResult(search *armoperationalinsights.SavedSearch, rgName, workspaceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["workspaceName"] = workspaceName

	if search.ID != nil {
		props["id"] = *search.ID
	}
	if search.Name != nil {
		props["name"] = *search.Name
	}

	if p := search.Properties; p != nil {
		if p.Category != nil {
			props["category"] = *p.Category
		}
		if p.DisplayName != nil {
			props["displayName"] = *p.DisplayName
		}
		if p.Query != nil {
			props["query"] = *p.Query
		}
		// ARM echoes these as empty strings for a plain saved search; an empty value
		// read back as set would drift against a fixture that never declared them.
		if p.FunctionAlias != nil && *p.FunctionAlias != "" {
			props["functionAlias"] = *p.FunctionAlias
		}
		if p.FunctionParameters != nil && *p.FunctionParameters != "" {
			props["functionParameters"] = *p.FunctionParameters
		}
		if p.Version != nil {
			props["version"] = *p.Version
		}
		// Properties.Tags is a saved-search-specific name/value list, not ARM resource
		// tags, and is not modelled.
	}

	return props
}

// logAnalyticsSavedSearchParams builds the request body shared by create and update:
// CreateOrUpdate is the only write verb.
func logAnalyticsSavedSearchParams(props logAnalyticsSavedSearchProps) armoperationalinsights.SavedSearch {
	return armoperationalinsights.SavedSearch{
		Properties: &armoperationalinsights.SavedSearchProperties{
			Category:           to.Ptr(props.Category),
			DisplayName:        to.Ptr(props.DisplayName),
			Query:              to.Ptr(props.Query),
			FunctionAlias:      props.FunctionAlias,
			FunctionParameters: props.FunctionParameters,
			Version:            props.Version,
		},
	}
}

func (s *LogAnalyticsSavedSearch) parseProps(payload json.RawMessage, label string) (logAnalyticsSavedSearchProps, string, error) {
	var props logAnalyticsSavedSearchProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.WorkspaceName == "" {
		return props, "", fmt.Errorf("workspaceName is required")
	}
	if props.Category == "" {
		return props, "", fmt.Errorf("category is required")
	}
	if props.DisplayName == "" {
		return props, "", fmt.Errorf("displayName is required")
	}
	if props.Query == "" {
		return props, "", fmt.Errorf("query is required")
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

func (s *LogAnalyticsSavedSearch) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := s.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := s.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.WorkspaceName, name,
		logAnalyticsSavedSearchParams(props), nil)
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
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.SavedSearch, props.ResourceGroupName, props.WorkspaceName))
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

func (s *LogAnalyticsSavedSearch) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, workspaceName, searchID, err := logAnalyticsSavedSearchIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, workspaceName, searchID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.SavedSearch, rgName, workspaceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogAnalyticsSavedSearch,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: it is the API's only write verb.
func (s *LogAnalyticsSavedSearch) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, workspaceName, searchID, err := logAnalyticsSavedSearchIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := s.parseProps(request.DesiredProperties, searchID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.CreateOrUpdate(ctx, rgName, workspaceName, searchID,
		logAnalyticsSavedSearchParams(props), nil)
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

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.SavedSearch, rgName, workspaceName))
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

func (s *LogAnalyticsSavedSearch) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, workspaceName, searchID, err := logAnalyticsSavedSearchIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := s.api.Delete(ctx, rgName, workspaceName, searchID, nil); err != nil && !isDeleteSuccessError(err) {
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
func (s *LogAnalyticsSavedSearch) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the workspace: saved searches only
// exist inside one.
func (s *LogAnalyticsSavedSearch) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	workspaceName := request.AdditionalProperties["workspaceName"]
	if rgName == "" || workspaceName == "" {
		return &resource.ListResult{}, nil
	}

	// One response, not a pager: the API returns every saved search at once.
	result, err := s.api.ListByWorkspace(ctx, rgName, workspaceName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list saved searches: %w", err)
	}

	var nativeIDs []string
	for _, search := range result.Value {
		if search != nil && search.ID != nil {
			nativeIDs = append(nativeIDs, *search.ID)
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
