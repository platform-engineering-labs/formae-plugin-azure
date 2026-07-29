// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeStorageTable = "AZURE::Storage::Table"

// storageTablesAPI is the subset of *armstorage.TableClient used here. Table
// operations are synchronous (no LRO/poller). Note that Create/Update take the
// body inside the *options* struct rather than as a positional parameter.
type storageTablesAPI interface {
	Create(ctx context.Context, resourceGroupName, accountName, tableName string, options *armstorage.TableClientCreateOptions) (armstorage.TableClientCreateResponse, error)
	Get(ctx context.Context, resourceGroupName, accountName, tableName string, options *armstorage.TableClientGetOptions) (armstorage.TableClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName, accountName, tableName string, options *armstorage.TableClientUpdateOptions) (armstorage.TableClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName, accountName, tableName string, options *armstorage.TableClientDeleteOptions) (armstorage.TableClientDeleteResponse, error)
	NewListPager(resourceGroupName, accountName string, options *armstorage.TableClientListOptions) *runtime.Pager[armstorage.TableClientListResponse]
}

func init() {
	registry.Register(ResourceTypeStorageTable, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &StorageTable{api: c.StorageTablesClient, config: cfg}
	})
}

// StorageTable is the provisioner for storage tables
// (`Microsoft.Storage/storageAccounts/<acct>/tableServices/default/tables/<name>`).
// It is a child of AZURE::Storage::StorageAccount. All operations are synchronous.
type StorageTable struct {
	api    storageTablesAPI
	config *config.Config
}

func storageTableIDParts(resourceID string) (rgName, accountName, tableName string, err error) {
	rgName, names, err := armIDParts(resourceID, "storageaccounts", "tables")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["storageaccounts"], names["tables"], nil
}

func serializeStorageTableProperties(result armstorage.Table, rgName, accountName, tableName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["storageAccountName"] = accountName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = tableName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if result.TableProperties != nil && len(result.TableProperties.SignedIdentifiers) > 0 {
		ids := make([]map[string]any, 0, len(result.TableProperties.SignedIdentifiers))
		for _, si := range result.TableProperties.SignedIdentifiers {
			if si == nil || si.ID == nil {
				continue
			}
			entry := map[string]any{"id": *si.ID}
			if ap := si.AccessPolicy; ap != nil {
				policy := map[string]any{}
				if ap.Permission != nil {
					policy["permission"] = *ap.Permission
				}
				if ap.StartTime != nil {
					policy["startTime"] = ap.StartTime.UTC().Format(time.RFC3339)
				}
				if ap.ExpiryTime != nil {
					policy["expiryTime"] = ap.ExpiryTime.UTC().Format(time.RFC3339)
				}
				if len(policy) > 0 {
					entry["accessPolicy"] = policy
				}
			}
			ids = append(ids, entry)
		}
		// ARM does not promise to echo stored access policies in submitted order.
		sort.Slice(ids, func(i, j int) bool { return ids[i]["id"].(string) < ids[j]["id"].(string) })
		if len(ids) > 0 {
			props["signedIdentifiers"] = ids
		}
	}

	return json.Marshal(props)
}

func storageTableParamsFromProperties(props map[string]any) (*armstorage.Table, error) {
	table := &armstorage.Table{TableProperties: &armstorage.TableProperties{}}

	raw, ok := props["signedIdentifiers"].([]any)
	if !ok || len(raw) == 0 {
		return table, nil
	}

	identifiers := make([]*armstorage.TableSignedIdentifier, 0, len(raw))
	for i, entry := range raw {
		m, ok := entry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("signedIdentifiers[%d] must be an object", i)
		}
		id, _ := m["id"].(string)
		if id == "" {
			return nil, fmt.Errorf("signedIdentifiers[%d].id is required", i)
		}
		si := &armstorage.TableSignedIdentifier{ID: stringPtr(id)}

		if apMap, ok := m["accessPolicy"].(map[string]any); ok {
			ap := &armstorage.TableAccessPolicy{}
			permission, _ := apMap["permission"].(string)
			if permission == "" {
				return nil, fmt.Errorf("signedIdentifiers[%d].accessPolicy.permission is required", i)
			}
			ap.Permission = stringPtr(permission)
			if v, ok := apMap["startTime"].(string); ok && v != "" {
				t, err := parseTime(v)
				if err != nil {
					return nil, fmt.Errorf("signedIdentifiers[%d].accessPolicy.startTime: %w", i, err)
				}
				ap.StartTime = &t
			}
			if v, ok := apMap["expiryTime"].(string); ok && v != "" {
				t, err := parseTime(v)
				if err != nil {
					return nil, fmt.Errorf("signedIdentifiers[%d].accessPolicy.expiryTime: %w", i, err)
				}
				ap.ExpiryTime = &t
			}
			si.AccessPolicy = ap
		}

		identifiers = append(identifiers, si)
	}
	sort.Slice(identifiers, func(i, j int) bool { return *identifiers[i].ID < *identifiers[j].ID })
	table.TableProperties.SignedIdentifiers = identifiers

	return table, nil
}

func (t *StorageTable) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	accountName, _ := props["storageAccountName"].(string)
	if accountName == "" {
		return nil, fmt.Errorf("storageAccountName is required")
	}
	tableName, _ := props["name"].(string)
	if tableName == "" {
		tableName = request.Label
	}
	if tableName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := storageTableParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Create(ctx, rgName, accountName, tableName,
		&armstorage.TableClientCreateOptions{Parameters: params})
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeStorageTableProperties(result.Table, rgName, accountName, tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Table properties: %w", err)
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
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

func (t *StorageTable) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, tableName, err := storageTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Get(ctx, rgName, accountName, tableName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeStorageTableProperties(result.Table, rgName, accountName, tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Table properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeStorageTable,
		Properties:   string(propsJSON),
	}, nil
}

func (t *StorageTable) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, tableName, err := storageTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}

	params, err := storageTableParamsFromProperties(props)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Update(ctx, rgName, accountName, tableName,
		&armstorage.TableClientUpdateOptions{Parameters: params})
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

	propsJSON, err := serializeStorageTableProperties(result.Table, rgName, accountName, tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Table properties: %w", err)
	}

	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (t *StorageTable) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, tableName, err := storageTableIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete. NotFound means the goal is already achieved.
	if _, err := t.api.Delete(ctx, rgName, accountName, tableName, nil); err != nil {
		if isDeleteSuccessError(err) {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
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

// Status is a no-op success passthrough: table operations are synchronous, so
// Create/Update/Delete never return InProgress. It exists only to satisfy the
// Provisioner interface.
func (t *StorageTable) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (t *StorageTable) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["storageAccountName"]

	var nativeIDs []string
	pager := t.api.NewListPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list tables in storage account %s: %w", accountName, err)
		}
		for _, table := range page.Value {
			if table.ID != nil {
				nativeIDs = append(nativeIDs, *table.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
