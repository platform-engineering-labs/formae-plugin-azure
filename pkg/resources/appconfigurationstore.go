// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appconfiguration/armappconfiguration"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeAppConfigurationStore = "AZURE::AppConfiguration::ConfigurationStore"

type appConfigurationStoresAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, configStoreName string, parameters armappconfiguration.ConfigurationStore, options *armappconfiguration.ConfigurationStoresClientBeginCreateOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, configStoreName string, options *armappconfiguration.ConfigurationStoresClientGetOptions) (armappconfiguration.ConfigurationStoresClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, configStoreName string, parameters armappconfiguration.ConfigurationStoreUpdateParameters, options *armappconfiguration.ConfigurationStoresClientBeginUpdateOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, configStoreName string, options *armappconfiguration.ConfigurationStoresClientBeginDeleteOptions) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientDeleteResponse], error)
	NewListPager(options *armappconfiguration.ConfigurationStoresClientListOptions) *runtime.Pager[armappconfiguration.ConfigurationStoresClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armappconfiguration.ConfigurationStoresClientListByResourceGroupOptions) *runtime.Pager[armappconfiguration.ConfigurationStoresClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeAppConfigurationStore, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AppConfigurationStore{
			api:      c.AppConfigurationStoresClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// AppConfigurationStore is the provisioner for App Configuration stores
// (Microsoft.AppConfiguration/configurationStores).
//
// Access keys and connection strings are deliberately never serialized: ARM
// returns them only from a separate ListKeys call, so putting them in resource
// state would persist live credentials.
type AppConfigurationStore struct {
	api      appConfigurationStoresAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func appConfigurationStoreIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "configurationstores")
	if err != nil {
		return "", "", err
	}
	return rgName, names["configurationstores"], nil
}

func (a *AppConfigurationStore) buildPropertiesFromResult(store *armappconfiguration.ConfigurationStore, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if store.ID != nil {
		props["id"] = *store.ID
	}
	if store.Name != nil {
		props["name"] = *store.Name
	}
	if store.Location != nil {
		props["location"] = strings.ToLower(strings.ReplaceAll(*store.Location, " ", ""))
	}
	if store.SKU != nil && store.SKU.Name != nil {
		props["sku"] = map[string]any{"name": *store.SKU.Name}
	}

	if store.Properties != nil {
		if store.Properties.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = string(*store.Properties.PublicNetworkAccess)
		}
		if store.Properties.DisableLocalAuth != nil {
			props["disableLocalAuth"] = *store.Properties.DisableLocalAuth
		}
		if store.Properties.SoftDeleteRetentionInDays != nil {
			props["softDeleteRetentionInDays"] = *store.Properties.SoftDeleteRetentionInDays
		}
		if store.Properties.EnablePurgeProtection != nil {
			props["enablePurgeProtection"] = *store.Properties.EnablePurgeProtection
		}
		if store.Properties.Endpoint != nil {
			props["endpoint"] = *store.Properties.Endpoint
		}
	}

	if tags := azureTagsToFormaeTags(store.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func buildConfigurationStoreParams(props map[string]any, location string) armappconfiguration.ConfigurationStore {
	storeProps := &armappconfiguration.ConfigurationStoreProperties{}
	if v, ok := props["publicNetworkAccess"].(string); ok && v != "" {
		storeProps.PublicNetworkAccess = to.Ptr(armappconfiguration.PublicNetworkAccess(v))
	}
	if v, ok := props["disableLocalAuth"].(bool); ok {
		storeProps.DisableLocalAuth = to.Ptr(v)
	}
	if v, ok := capacity(props["softDeleteRetentionInDays"]); ok {
		storeProps.SoftDeleteRetentionInDays = to.Ptr(v)
	}
	if v, ok := props["enablePurgeProtection"].(bool); ok {
		storeProps.EnablePurgeProtection = to.Ptr(v)
	}

	params := armappconfiguration.ConfigurationStore{
		Location:   to.Ptr(location),
		Properties: storeProps,
	}
	if raw, ok := props["sku"].(map[string]any); ok {
		if name, ok := raw["name"].(string); ok && name != "" {
			params.SKU = &armappconfiguration.SKU{Name: to.Ptr(name)}
		}
	}
	return params
}

func (a *AppConfigurationStore) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	storeName, ok := props["name"].(string)
	if !ok || storeName == "" {
		storeName = request.Label
	}
	if storeName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := buildConfigurationStoreParams(props, location)
	if params.SKU == nil {
		return nil, fmt.Errorf("sku is required")
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := a.api.BeginCreate(ctx, rgName, storeName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.AppConfiguration/configurationStores/%s",
		a.config.SubscriptionId, rgName, storeName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.ConfigurationStore, rgName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (a *AppConfigurationStore) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, storeName, err := appConfigurationStoreIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, storeName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.ConfigurationStore, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAppConfigurationStore,
		Properties:   string(propsJSON),
	}, nil
}

// Update patches the mutable subset. sku, publicNetworkAccess, disableLocalAuth
// and enablePurgeProtection are in-place; location and softDeleteRetentionInDays
// are createOnly in the schema because ARM rejects changing them.
func (a *AppConfigurationStore) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, storeName, err := appConfigurationStoreIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armappconfiguration.ConfigurationStorePropertiesUpdateParameters{}
	if v, ok := props["publicNetworkAccess"].(string); ok && v != "" {
		updateProps.PublicNetworkAccess = to.Ptr(armappconfiguration.PublicNetworkAccess(v))
	}
	if v, ok := props["disableLocalAuth"].(bool); ok {
		updateProps.DisableLocalAuth = to.Ptr(v)
	}
	if v, ok := props["enablePurgeProtection"].(bool); ok {
		updateProps.EnablePurgeProtection = to.Ptr(v)
	}

	params := armappconfiguration.ConfigurationStoreUpdateParameters{Properties: updateProps}
	if raw, ok := props["sku"].(map[string]any); ok {
		if name, ok := raw["name"].(string); ok && name != "" {
			params.SKU = &armappconfiguration.SKU{Name: to.Ptr(name)}
		}
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := a.api.BeginUpdate(ctx, rgName, storeName, params, nil)
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

	if poller.Done() {
		result, err := poller.Result(ctx)
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
		propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.ConfigurationStore, rgName))
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Delete soft-deletes the store: the name stays reserved for
// softDeleteRetentionInDays unless purged. Purging is not done here — it is
// irreversible and would destroy a recoverable store the user may still want.
func (a *AppConfigurationStore) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, storeName, err := appConfigurationStoreIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginDelete(ctx, rgName, storeName, nil)
	if err != nil {
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

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (a *AppConfigurationStore) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientCreateResponse], error) {
				return resumePoller[armappconfiguration.ConfigurationStoresClientCreateResponse](a.pipeline, token)
			},
			func(_ context.Context, result armappconfiguration.ConfigurationStoresClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return a.completeFromStore(&result.ConfigurationStore)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientUpdateResponse], error) {
				return resumePoller[armappconfiguration.ConfigurationStoresClientUpdateResponse](a.pipeline, token)
			},
			func(_ context.Context, result armappconfiguration.ConfigurationStoresClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return a.completeFromStore(&result.ConfigurationStore)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armappconfiguration.ConfigurationStoresClientDeleteResponse], error) {
				return resumePoller[armappconfiguration.ConfigurationStoresClientDeleteResponse](a.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (a *AppConfigurationStore) completeFromStore(store *armappconfiguration.ConfigurationStore) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if store.ID != nil {
		nativeID = *store.ID
		if rg, _, err := appConfigurationStoreIDParts(*store.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(store, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (a *AppConfigurationStore) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := a.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list app configuration stores: %w", err)
			}
			for _, store := range page.Value {
				if store.ID != nil {
					nativeIDs = append(nativeIDs, *store.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := a.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list app configuration stores: %w", err)
		}
		for _, store := range page.Value {
			if store.ID != nil {
				nativeIDs = append(nativeIDs, *store.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
