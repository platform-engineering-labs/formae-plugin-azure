// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeCognitiveAccount = "AZURE::CognitiveServices::Account"

type cognitiveAccountsAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, accountName string, account armcognitiveservices.Account, options *armcognitiveservices.AccountsClientBeginCreateOptions) (*runtime.Poller[armcognitiveservices.AccountsClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, accountName string, options *armcognitiveservices.AccountsClientGetOptions) (armcognitiveservices.AccountsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, accountName string, account armcognitiveservices.Account, options *armcognitiveservices.AccountsClientBeginUpdateOptions) (*runtime.Poller[armcognitiveservices.AccountsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, accountName string, options *armcognitiveservices.AccountsClientBeginDeleteOptions) (*runtime.Poller[armcognitiveservices.AccountsClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armcognitiveservices.AccountsClientListByResourceGroupOptions) *runtime.Pager[armcognitiveservices.AccountsClientListByResourceGroupResponse]
	NewListPager(options *armcognitiveservices.AccountsClientListOptions) *runtime.Pager[armcognitiveservices.AccountsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeCognitiveAccount, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CognitiveAccount{
			api:      c.CognitiveAccountsClient,
			config:   cfg,
			pipeline: c.Pipeline(),
		}
	})
}

// CognitiveAccount is the provisioner for Azure Cognitive Services accounts.
type CognitiveAccount struct {
	api      cognitiveAccountsAPI
	config   *config.Config
	pipeline runtime.Pipeline
}

func cognitiveAccountIDParts(resourceID string) (rgName, accountName string, err error) {
	rgName, names, err := armIDParts(resourceID, "accounts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["accounts"], nil
}

func serializeCognitiveAccountProperties(result armcognitiveservices.Account, rgName, accountName string) (json.RawMessage, error) {
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
	if result.Kind != nil {
		props["kind"] = *result.Kind
	}

	if result.SKU != nil && result.SKU.Name != nil {
		props["sku"] = map[string]any{"name": *result.SKU.Name}
	}

	if result.Properties != nil {
		if result.Properties.CustomSubDomainName != nil {
			props["customSubDomainName"] = *result.Properties.CustomSubDomainName
		}
		if result.Properties.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = string(*result.Properties.PublicNetworkAccess)
		}
		if result.Properties.Endpoint != nil {
			props["endpoint"] = *result.Properties.Endpoint
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	if result.ID != nil {
		props["id"] = *result.ID
	}

	return json.Marshal(props)
}

func (a *CognitiveAccount) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	kind, ok := props["kind"].(string)
	if !ok || kind == "" {
		return nil, fmt.Errorf("kind is required")
	}

	accountName, ok := props["name"].(string)
	if !ok || accountName == "" {
		accountName = request.Label
	}

	params := armcognitiveservices.Account{
		Location:   stringPtr(location),
		Kind:       stringPtr(kind),
		Properties: &armcognitiveservices.AccountProperties{},
	}

	if skuRaw, ok := props["sku"].(map[string]any); ok {
		if name, ok := skuRaw["name"].(string); ok && name != "" {
			params.SKU = &armcognitiveservices.SKU{Name: stringPtr(name)}
		}
	}
	if params.SKU == nil || params.SKU.Name == nil {
		return nil, fmt.Errorf("sku.name is required")
	}

	if customSubDomain, ok := props["customSubDomainName"].(string); ok && customSubDomain != "" {
		params.Properties.CustomSubDomainName = stringPtr(customSubDomain)
	}
	if publicAccess, ok := props["publicNetworkAccess"].(string); ok && publicAccess != "" {
		access := armcognitiveservices.PublicNetworkAccess(publicAccess)
		params.Properties.PublicNetworkAccess = &access
	}

	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := a.api.BeginCreate(ctx, rgName, accountName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.CognitiveServices/accounts/%s",
		a.config.SubscriptionId, rgName, accountName)

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

		propsJSON, err := serializeCognitiveAccountProperties(result.Account, rgName, accountName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Cognitive Account properties: %w", err)
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

func (a *CognitiveAccount) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, err := cognitiveAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, accountName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: operationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeCognitiveAccountProperties(result.Account, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Cognitive Account properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeCognitiveAccount,
		Properties:   string(propsJSON),
	}, nil
}

func (a *CognitiveAccount) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, err := cognitiveAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armcognitiveservices.Account{
		Properties: &armcognitiveservices.AccountProperties{},
	}

	if skuRaw, ok := props["sku"].(map[string]any); ok {
		if name, ok := skuRaw["name"].(string); ok && name != "" {
			params.SKU = &armcognitiveservices.SKU{Name: stringPtr(name)}
		}
	}
	if publicAccess, ok := props["publicNetworkAccess"].(string); ok && publicAccess != "" {
		access := armcognitiveservices.PublicNetworkAccess(publicAccess)
		params.Properties.PublicNetworkAccess = &access
	}

	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := a.api.BeginUpdate(ctx, rgName, accountName, params, nil)
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

		propsJSON, err := serializeCognitiveAccountProperties(result.Account, rgName, accountName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Cognitive Account properties: %w", err)
		}

		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
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

func (a *CognitiveAccount) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, err := cognitiveAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginDelete(ctx, rgName, accountName, nil)
	if err != nil {
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
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to start Cognitive Account deletion: %w", err)
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
			}, fmt.Errorf("failed to get Cognitive Account delete result: %w", err)
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

func (a *CognitiveAccount) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return a.statusCreate(ctx, request, &reqID)
	case lroOpUpdate:
		return a.statusUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return a.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unexpected operation type: %s", reqID.OperationType)
	}
}

func (a *CognitiveAccount) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationCreate,
		func(token string) (*runtime.Poller[armcognitiveservices.AccountsClientCreateResponse], error) {
			return resumePoller[armcognitiveservices.AccountsClientCreateResponse](a.pipeline, token)
		},
		func(_ context.Context, result armcognitiveservices.AccountsClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, accountName, err := cognitiveAccountIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeCognitiveAccountProperties(result.Account, rgName, accountName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Cognitive Account properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (a *CognitiveAccount) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusLRO(ctx, request, reqID, resource.OperationUpdate,
		func(token string) (*runtime.Poller[armcognitiveservices.AccountsClientUpdateResponse], error) {
			return resumePoller[armcognitiveservices.AccountsClientUpdateResponse](a.pipeline, token)
		},
		func(_ context.Context, result armcognitiveservices.AccountsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, accountName, err := cognitiveAccountIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeCognitiveAccountProperties(result.Account, rgName, accountName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize Cognitive Account properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (a *CognitiveAccount) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armcognitiveservices.AccountsClientDeleteResponse], error) {
			return resumePoller[armcognitiveservices.AccountsClientDeleteResponse](a.pipeline, token)
		}, nil)
}

func (a *CognitiveAccount) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := a.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Cognitive Accounts: %w", err)
			}
			for _, account := range page.Value {
				if account.ID != nil {
					nativeIDs = append(nativeIDs, *account.ID)
				}
			}
		}
	} else {
		pager := a.api.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list Cognitive Accounts: %w", err)
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
