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

const ResourceTypeLogAnalyticsStorageInsightConfig = "AZURE::OperationalInsights::StorageInsightConfig"

// logAnalyticsStorageInsightConfigsAPI is the subset of
// *armoperationalinsights.StorageInsightConfigsClient used here. Every operation
// is synchronous — no LRO, no poller — and CreateOrUpdate is also the update verb.
type logAnalyticsStorageInsightConfigsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, workspaceName, storageInsightName string, parameters armoperationalinsights.StorageInsight, options *armoperationalinsights.StorageInsightConfigsClientCreateOrUpdateOptions) (armoperationalinsights.StorageInsightConfigsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, workspaceName, storageInsightName string, options *armoperationalinsights.StorageInsightConfigsClientGetOptions) (armoperationalinsights.StorageInsightConfigsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, workspaceName, storageInsightName string, options *armoperationalinsights.StorageInsightConfigsClientDeleteOptions) (armoperationalinsights.StorageInsightConfigsClientDeleteResponse, error)
	NewListByWorkspacePager(resourceGroupName, workspaceName string, options *armoperationalinsights.StorageInsightConfigsClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.StorageInsightConfigsClientListByWorkspaceResponse]
}

func init() {
	registry.Register(ResourceTypeLogAnalyticsStorageInsightConfig, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogAnalyticsStorageInsightConfig{api: c.LogAnalyticsStorageInsightConfigsClient, config: cfg}
	})
}

// LogAnalyticsStorageInsightConfig is the provisioner for storage insight configs
// (`Microsoft.OperationalInsights/workspaces/<ws>/storageInsightConfigs/<name>`).
// It is a child of AZURE::OperationalInsights::Workspace and pulls agent data the
// workspace never received directly out of a storage account the agents wrote to.
//
// storageAccountKey is write-only: ARM accepts it on every write and never
// returns it from Get, so it is never serialized into resource state and drift in
// it cannot be detected.
type LogAnalyticsStorageInsightConfig struct {
	api    logAnalyticsStorageInsightConfigsAPI
	config *config.Config
}

// logAnalyticsStorageInsightConfigProps mirrors
// schema/pkl/operationalinsights/loganalyticsstorageinsightconfig.pkl. ARM's
// nested storageAccount block is flattened into its two fields.
// storageInsightAccountKey unwraps storageAccountKey, which may arrive either as a
// bare string or as the object form produced by `formae.value(...).opaque`.
func storageInsightAccountKey(props logAnalyticsStorageInsightConfigProps) string {
	key, _ := opaqueString(props.StorageAccountKey)
	return key
}

type logAnalyticsStorageInsightConfigProps struct {
	Name              string `json:"name"`
	ResourceGroupName string `json:"resourceGroupName"`
	WorkspaceName     string `json:"workspaceName"`
	StorageAccountID  string `json:"storageAccountId"`
	// Typed `any`, not `string`, and read through opaqueString below.
	//
	// A write-only secret is declared in a forma as
	// `formae.value("...").opaque`, which renders as an OBJECT, not a string. A
	// `string` field here therefore fails before any ARM call with
	//
	//   failed to parse resource properties: json: cannot unmarshal object into
	//   Go struct field logAnalyticsStorageInsightConfigProps.storageAccountKey
	//   of type string
	//
	// which is what the live run hit. `app-service-certificate` already had the
	// answer for its pfx blob and password: keep the raw value and unwrap it with
	// opaqueString, which accepts either a bare string or the opaque wrapper.
	StorageAccountKey any      `json:"storageAccountKey"`
	Containers        []string `json:"containers"`
	Tables            []string `json:"tables"`
}

func logAnalyticsStorageInsightConfigIDParts(resourceID string) (rgName, workspaceName, insightName string, err error) {
	rgName, names, err := armIDParts(resourceID, "workspaces", "storageinsightconfigs")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["workspaces"], names["storageinsightconfigs"], nil
}

func (s *LogAnalyticsStorageInsightConfig) buildPropertiesFromResult(insight *armoperationalinsights.StorageInsight, rgName, workspaceName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["workspaceName"] = workspaceName

	if insight.ID != nil {
		props["id"] = *insight.ID
	}
	if insight.Name != nil {
		props["name"] = *insight.Name
	}

	if p := insight.Properties; p != nil {
		if account := p.StorageAccount; account != nil && account.ID != nil {
			props["storageAccountId"] = *account.ID
		}
		// storageAccount.key is never returned by ARM — it is write-only, like
		// every other secret in this plugin — so there is nothing to drop.
		if containers := stringsFromPointers(p.Containers); len(containers) > 0 {
			props["containers"] = containers
		}
		if tables := stringsFromPointers(p.Tables); len(tables) > 0 {
			props["tables"] = tables
		}
		// status is the service's own health verdict on the connection, and eTag
		// is service state: neither is modelled.
	}

	return props
}

// logAnalyticsStorageInsightConfigParams builds the request body shared by create
// and update: CreateOrUpdate is the only write verb.
func logAnalyticsStorageInsightConfigParams(props logAnalyticsStorageInsightConfigProps) armoperationalinsights.StorageInsight {
	insightProps := &armoperationalinsights.StorageInsightProperties{
		StorageAccount: &armoperationalinsights.StorageAccount{
			ID:  to.Ptr(props.StorageAccountID),
			Key: to.Ptr(storageInsightAccountKey(props)),
		},
	}
	if containers := stringPointers(props.Containers); containers != nil {
		insightProps.Containers = containers
	}
	if tables := stringPointers(props.Tables); tables != nil {
		insightProps.Tables = tables
	}

	return armoperationalinsights.StorageInsight{Properties: insightProps}
}

func (s *LogAnalyticsStorageInsightConfig) parseProps(payload json.RawMessage, label string) (logAnalyticsStorageInsightConfigProps, string, error) {
	var props logAnalyticsStorageInsightConfigProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.WorkspaceName == "" {
		return props, "", fmt.Errorf("workspaceName is required")
	}
	if props.StorageAccountID == "" {
		return props, "", fmt.Errorf("storageAccountId is required")
	}
	if storageInsightAccountKey(props) == "" {
		return props, "", fmt.Errorf("storageAccountKey is required")
	}
	if len(props.Containers) == 0 && len(props.Tables) == 0 {
		return props, "", fmt.Errorf("at least one of containers or tables is required")
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

func (s *LogAnalyticsStorageInsightConfig) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := s.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := s.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.WorkspaceName, name,
		logAnalyticsStorageInsightConfigParams(props), nil)
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
	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.StorageInsight, props.ResourceGroupName, props.WorkspaceName))
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

func (s *LogAnalyticsStorageInsightConfig) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, workspaceName, insightName, err := logAnalyticsStorageInsightConfigIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.Get(ctx, rgName, workspaceName, insightName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.StorageInsight, rgName, workspaceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogAnalyticsStorageInsightConfig,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: it is the API's only write verb. The account key
// rides along on every update because ARM rejects a body without it.
func (s *LogAnalyticsStorageInsightConfig) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, workspaceName, insightName, err := logAnalyticsStorageInsightConfigIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := s.parseProps(request.DesiredProperties, insightName)
	if err != nil {
		return nil, err
	}

	result, err := s.api.CreateOrUpdate(ctx, rgName, workspaceName, insightName,
		logAnalyticsStorageInsightConfigParams(props), nil)
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

	propsJSON, err := json.Marshal(s.buildPropertiesFromResult(&result.StorageInsight, rgName, workspaceName))
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

func (s *LogAnalyticsStorageInsightConfig) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, workspaceName, insightName, err := logAnalyticsStorageInsightConfigIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := s.api.Delete(ctx, rgName, workspaceName, insightName, nil); err != nil && !isDeleteSuccessError(err) {
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
func (s *LogAnalyticsStorageInsightConfig) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List requires both the resource group and the workspace: storage insight
// configs only exist inside one.
func (s *LogAnalyticsStorageInsightConfig) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	workspaceName := request.AdditionalProperties["workspaceName"]
	if rgName == "" || workspaceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := s.api.NewListByWorkspacePager(rgName, workspaceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list storage insight configs: %w", err)
		}
		for _, insight := range page.Value {
			if insight != nil && insight.ID != nil {
				nativeIDs = append(nativeIDs, *insight.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
