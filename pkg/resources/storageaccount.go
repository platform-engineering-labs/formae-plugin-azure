// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeStorageAccount = "Azure::Storage::StorageAccount"

type storageAccountsAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, accountName string, parameters armstorage.AccountCreateParameters, options *armstorage.AccountsClientBeginCreateOptions) (*runtime.Poller[armstorage.AccountsClientCreateResponse], error)
	GetProperties(ctx context.Context, resourceGroupName string, accountName string, options *armstorage.AccountsClientGetPropertiesOptions) (armstorage.AccountsClientGetPropertiesResponse, error)
	Update(ctx context.Context, resourceGroupName string, accountName string, parameters armstorage.AccountUpdateParameters, options *armstorage.AccountsClientUpdateOptions) (armstorage.AccountsClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, accountName string, options *armstorage.AccountsClientDeleteOptions) (armstorage.AccountsClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armstorage.AccountsClientListByResourceGroupOptions) *runtime.Pager[armstorage.AccountsClientListByResourceGroupResponse]
	NewListPager(options *armstorage.AccountsClientListOptions) *runtime.Pager[armstorage.AccountsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeStorageAccount, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &StorageAccount{
			api:      c.StorageAccountsClient,
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// StorageAccount is the provisioner for Azure Storage Accounts.
type StorageAccount struct {
	api      storageAccountsAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func storageAccountIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "storageaccounts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["storageaccounts"], nil
}

// serializeStorageAccountProperties converts an Azure StorageAccount to Formae property format
func serializeStorageAccountProperties(result armstorage.Account, rgName, accountName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = accountName
	}

	if result.Location != nil {
		props["location"] = *result.Location
	}

	// SKU
	if result.SKU != nil {
		sku := make(map[string]any)
		if result.SKU.Name != nil {
			sku["name"] = string(*result.SKU.Name)
		}
		props["sku"] = sku
	}

	// Kind
	if result.Kind != nil {
		props["kind"] = string(*result.Kind)
	}

	// Properties
	if result.Properties != nil {
		if result.Properties.AccessTier != nil {
			props["accessTier"] = string(*result.Properties.AccessTier)
		}
		if result.Properties.EnableHTTPSTrafficOnly != nil {
			props["enableHttpsTrafficOnly"] = *result.Properties.EnableHTTPSTrafficOnly
		}
		if result.Properties.MinimumTLSVersion != nil {
			props["minimumTlsVersion"] = string(*result.Properties.MinimumTLSVersion)
		}
		if result.Properties.AllowBlobPublicAccess != nil {
			props["allowBlobPublicAccess"] = *result.Properties.AllowBlobPublicAccess
		}
		if result.Properties.PrimaryEndpoints != nil {
			endpoints := make(map[string]any)
			if result.Properties.PrimaryEndpoints.Blob != nil {
				endpoints["blob"] = *result.Properties.PrimaryEndpoints.Blob
				props["primaryBlobEndpoint"] = *result.Properties.PrimaryEndpoints.Blob
			}
			if result.Properties.PrimaryEndpoints.Queue != nil {
				endpoints["queue"] = *result.Properties.PrimaryEndpoints.Queue
				props["primaryQueueEndpoint"] = *result.Properties.PrimaryEndpoints.Queue
			}
			if result.Properties.PrimaryEndpoints.Table != nil {
				endpoints["table"] = *result.Properties.PrimaryEndpoints.Table
				props["primaryTableEndpoint"] = *result.Properties.PrimaryEndpoints.Table
			}
			if result.Properties.PrimaryEndpoints.File != nil {
				endpoints["file"] = *result.Properties.PrimaryEndpoints.File
				props["primaryFileEndpoint"] = *result.Properties.PrimaryEndpoints.File
			}
			if result.Properties.PrimaryEndpoints.Web != nil {
				endpoints["web"] = *result.Properties.PrimaryEndpoints.Web
			}
			if result.Properties.PrimaryEndpoints.Dfs != nil {
				endpoints["dfs"] = *result.Properties.PrimaryEndpoints.Dfs
			}
			props["primaryEndpoints"] = endpoints
		}
	}

	// Add tags
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	// Include id for resolvable references
	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func (s *StorageAccount) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	accountName, ok := props["name"].(string)
	if !ok || accountName == "" {
		accountName = request.Label
	}

	// Parse SKU
	var sku *armstorage.SKU
	if skuRaw, ok := props["sku"].(map[string]any); ok {
		sku = &armstorage.SKU{}
		if name, ok := skuRaw["name"].(string); ok {
			skuName := armstorage.SKUName(name)
			sku.Name = &skuName
		}
	}
	if sku == nil || sku.Name == nil {
		return nil, fmt.Errorf("sku.name is required")
	}

	// Parse Kind
	var kind *armstorage.Kind
	if kindRaw, ok := props["kind"].(string); ok {
		k := armstorage.Kind(kindRaw)
		kind = &k
	}
	if kind == nil {
		return nil, fmt.Errorf("kind is required")
	}

	params := armstorage.AccountCreateParameters{
		Location:   stringPtr(location),
		SKU:        sku,
		Kind:       kind,
		Properties: &armstorage.AccountPropertiesCreateParameters{},
	}

	// Parse access tier
	if accessTier, ok := props["accessTier"].(string); ok {
		tier := armstorage.AccessTier(accessTier)
		params.Properties.AccessTier = &tier
	}

	// Parse enableHttpsTrafficOnly
	if httpsOnly, ok := props["enableHttpsTrafficOnly"].(bool); ok {
		params.Properties.EnableHTTPSTrafficOnly = &httpsOnly
	}

	// Parse minimumTlsVersion
	if tlsVersion, ok := props["minimumTlsVersion"].(string); ok {
		version := armstorage.MinimumTLSVersion(tlsVersion)
		params.Properties.MinimumTLSVersion = &version
	}

	// Parse allowBlobPublicAccess
	if allowPublicAccess, ok := props["allowBlobPublicAccess"].(bool); ok {
		params.Properties.AllowBlobPublicAccess = &allowPublicAccess
	}

	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	// Storage account creation is async (LRO)
	poller, err := s.api.BeginCreate(ctx, rgName, accountName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,

				ErrorCode: operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s",
		s.config.SubscriptionId, rgName, accountName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,

					ErrorCode: operationErrorCode(err),
				},
			}, nil
		}

		propsJSON, err := serializeStorageAccountProperties(result.Account, rgName, accountName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize StorageAccount properties: %w", err)
		}

		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        *result.ID,

				ResourceProperties: propsJSON,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	requestID, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       requestID,
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (s *StorageAccount) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, err := storageAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := s.api.GetProperties(ctx, rgName, accountName, nil)
	if err != nil {
		return &resource.ReadResult{

			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeStorageAccountProperties(result.Account, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize StorageAccount properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeStorageAccount,
		Properties:   string(propsJSON),
	}, nil
}

func (s *StorageAccount) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, err := storageAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armstorage.AccountUpdateParameters{
		Properties: &armstorage.AccountPropertiesUpdateParameters{},
	}

	// Parse access tier (updatable)
	if accessTier, ok := props["accessTier"].(string); ok {
		tier := armstorage.AccessTier(accessTier)
		params.Properties.AccessTier = &tier
	}

	// Parse enableHttpsTrafficOnly (updatable)
	if httpsOnly, ok := props["enableHttpsTrafficOnly"].(bool); ok {
		params.Properties.EnableHTTPSTrafficOnly = &httpsOnly
	}

	// Parse minimumTlsVersion (updatable)
	if tlsVersion, ok := props["minimumTlsVersion"].(string); ok {
		version := armstorage.MinimumTLSVersion(tlsVersion)
		params.Properties.MinimumTLSVersion = &version
	}

	// Parse allowBlobPublicAccess (updatable)
	if allowPublicAccess, ok := props["allowBlobPublicAccess"].(bool); ok {
		params.Properties.AllowBlobPublicAccess = &allowPublicAccess
	}

	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	// Storage account update is synchronous
	result, err := s.api.Update(ctx, rgName, accountName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,

				ErrorCode: operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeStorageAccountProperties(result.Account, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize StorageAccount properties: %w", err)
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        *result.ID,

			ResourceProperties: propsJSON,
		},
	}, nil
}

func (s *StorageAccount) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, err := storageAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Storage account deletion is synchronous
	_, err = s.api.Delete(ctx, rgName, accountName, nil)
	if err != nil {
		// If the resource is already gone (NotFound), treat as success
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
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

				ErrorCode: operationErrorCode(err),
			},
		}, fmt.Errorf("failed to delete StorageAccount: %w", err)
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (s *StorageAccount) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return s.statusCreate(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unexpected async operation type for storage account: %s", reqID.OperationType)
	}
}

func (s *StorageAccount) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationCreate,
		func(token string) (*runtime.Poller[armstorage.AccountsClientCreateResponse], error) {
			return resumePoller[armstorage.AccountsClientCreateResponse](s.pipeline, token)
		},
		func(_ context.Context, result armstorage.AccountsClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, accountName, err := storageAccountIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeStorageAccountProperties(result.Account, rgName, accountName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize StorageAccount properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (s *StorageAccount) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if resourceGroupName != "" {
		pager := s.api.NewListByResourceGroupPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list storage accounts: %w", err)
			}
			for _, account := range page.Value {
				if account.ID != nil {
					nativeIDs = append(nativeIDs, *account.ID)
				}
			}
		}
	} else {
		pager := s.api.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list storage accounts: %w", err)
			}
			for _, account := range page.Value {
				if account.ID != nil {
					nativeIDs = append(nativeIDs, *account.ID)
				}
			}
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
