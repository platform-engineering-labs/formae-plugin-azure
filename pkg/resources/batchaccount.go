// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/batch/armbatch/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeBatchAccount = "AZURE::Batch::Account"

// batchAccountAPI is the armbatch surface used here. Create and Delete are LROs,
// Update is a synchronous PATCH. Note that create and update take *different*
// parameter types (AccountCreateParameters vs AccountUpdateParameters) with
// different property blocks, so the two bodies cannot share a builder.
type batchAccountAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, accountName string, parameters armbatch.AccountCreateParameters, options *armbatch.AccountClientBeginCreateOptions) (*runtime.Poller[armbatch.AccountClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, accountName string, options *armbatch.AccountClientGetOptions) (armbatch.AccountClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, accountName string, parameters armbatch.AccountUpdateParameters, options *armbatch.AccountClientUpdateOptions) (armbatch.AccountClientUpdateResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, accountName string, options *armbatch.AccountClientBeginDeleteOptions) (*runtime.Poller[armbatch.AccountClientDeleteResponse], error)
	NewListPager(options *armbatch.AccountClientListOptions) *runtime.Pager[armbatch.AccountClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armbatch.AccountClientListByResourceGroupOptions) *runtime.Pager[armbatch.AccountClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeBatchAccount, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &BatchAccount{
			api:      c.BatchAccountClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// BatchAccount is the provisioner for Azure Batch accounts
// (Microsoft.Batch/batchAccounts).
//
// The shared account keys are never serialized: ARM returns them only from a
// separate GetKeys call, so putting them in resource state would persist live
// credentials.
type BatchAccount struct {
	api      batchAccountAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// batchAccountProps mirrors schema/pkl/batch/batchaccount.pkl.
type batchAccountProps struct {
	Name                       string                 `json:"name"`
	Location                   string                 `json:"location"`
	ResourceGroupName          string                 `json:"resourceGroupName"`
	PoolAllocationMode         string                 `json:"poolAllocationMode"`
	AllowedAuthenticationModes []string               `json:"allowedAuthenticationModes"`
	AutoStorage                *batchAutoStorageProps `json:"autoStorage"`
	PublicNetworkAccess        string                 `json:"publicNetworkAccess"`
}

type batchAutoStorageProps struct {
	StorageAccountID   string `json:"storageAccountId"`
	AuthenticationMode string `json:"authenticationMode"`
}

func batchAccountIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "batchaccounts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["batchaccounts"], nil
}

func (b *BatchAccount) buildPropertiesFromResult(acct *armbatch.Account, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if acct.ID != nil {
		props["id"] = *acct.ID
	}
	if acct.Name != nil {
		props["name"] = *acct.Name
	}
	if acct.Location != nil {
		props["location"] = normalizeAzureLocation(*acct.Location)
	}

	if p := acct.Properties; p != nil {
		if p.PoolAllocationMode != nil {
			props["poolAllocationMode"] = canonicalizeEnum(string(*p.PoolAllocationMode),
				"BatchService", "UserSubscription")
		}
		if len(p.AllowedAuthenticationModes) > 0 {
			modes := make([]string, 0, len(p.AllowedAuthenticationModes))
			for _, m := range p.AllowedAuthenticationModes {
				if m == nil {
					continue
				}
				modes = append(modes, canonicalizeEnum(string(*m),
					"AAD", "SharedKey", "TaskAuthenticationToken"))
			}
			// ARM does not preserve the order the modes were sent in — sending
			// ["AAD","SharedKey"] reads back as ["SharedKey","AAD"] — so sort to a
			// stable form rather than letting the order flap between syncs.
			sort.Strings(modes)
			props["allowedAuthenticationModes"] = modes
		}
		// LastKeySync is deliberately dropped: it is a timestamp the service
		// bumps on its own and would show up as permanent drift.
		if as := p.AutoStorage; as != nil && as.StorageAccountID != nil {
			autoStorage := map[string]any{"storageAccountId": *as.StorageAccountID}
			if as.AuthenticationMode != nil {
				autoStorage["authenticationMode"] = canonicalizeEnum(string(*as.AuthenticationMode),
					"StorageKeys", "BatchAccountManagedIdentity")
			}
			props["autoStorage"] = autoStorage
		}
		if p.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = canonicalizeEnum(string(*p.PublicNetworkAccess),
				"Enabled", "Disabled", "SecuredByPerimeter")
		}
		if p.AccountEndpoint != nil {
			props["accountEndpoint"] = *p.AccountEndpoint
		}
	}

	if tags := azureTagsToFormaeTags(acct.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func batchAuthModes(modes []string) []*armbatch.AuthenticationMode {
	if len(modes) == 0 {
		return nil
	}
	out := make([]*armbatch.AuthenticationMode, 0, len(modes))
	for _, m := range modes {
		out = append(out, to.Ptr(armbatch.AuthenticationMode(m)))
	}
	return out
}

func batchAutoStorage(props *batchAutoStorageProps) *armbatch.AutoStorageBaseProperties {
	if props == nil || props.StorageAccountID == "" {
		return nil
	}
	autoStorage := &armbatch.AutoStorageBaseProperties{
		StorageAccountID: to.Ptr(props.StorageAccountID),
	}
	if props.AuthenticationMode != "" {
		autoStorage.AuthenticationMode = to.Ptr(armbatch.AutoStorageAuthenticationMode(props.AuthenticationMode))
	}
	return autoStorage
}

func (b *BatchAccount) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props batchAccountProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	createProps := &armbatch.AccountCreateProperties{
		AllowedAuthenticationModes: batchAuthModes(props.AllowedAuthenticationModes),
		AutoStorage:                batchAutoStorage(props.AutoStorage),
	}
	if props.PoolAllocationMode != "" {
		createProps.PoolAllocationMode = to.Ptr(armbatch.PoolAllocationMode(props.PoolAllocationMode))
	}
	if props.PublicNetworkAccess != "" {
		createProps.PublicNetworkAccess = to.Ptr(armbatch.PublicNetworkAccessType(props.PublicNetworkAccess))
	}

	params := armbatch.AccountCreateParameters{
		Location:   to.Ptr(props.Location),
		Properties: createProps,
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := b.api.BeginCreate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Batch/batchAccounts/%s",
		b.config.SubscriptionId, props.ResourceGroupName, name)

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
		nativeID, propsJSON, err := b.completeFromAccount(&result.Account)
		if err != nil {
			return nil, err
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

func (b *BatchAccount) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := batchAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := b.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&result.Account, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeBatchAccount,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH. poolAllocationMode is createOnly in the schema:
// AccountUpdateProperties has no field for it, so ARM cannot change it in place.
func (b *BatchAccount) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := batchAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props batchAccountProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armbatch.AccountUpdateProperties{
		AllowedAuthenticationModes: batchAuthModes(props.AllowedAuthenticationModes),
		AutoStorage:                batchAutoStorage(props.AutoStorage),
	}
	if props.PublicNetworkAccess != "" {
		updateProps.PublicNetworkAccess = to.Ptr(armbatch.PublicNetworkAccessType(props.PublicNetworkAccess))
	}

	params := armbatch.AccountUpdateParameters{Properties: updateProps}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := b.api.Update(ctx, rgName, name, params, nil)
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

	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(&result.Account, rgName))
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

func (b *BatchAccount) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := batchAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := b.api.BeginDelete(ctx, rgName, name, nil)
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

// Status handles create and delete; Update is synchronous and never reaches here.
func (b *BatchAccount) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armbatch.AccountClientCreateResponse], error) {
				return resumePoller[armbatch.AccountClientCreateResponse](b.pipeline, token)
			},
			func(_ context.Context, result armbatch.AccountClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return b.completeFromAccount(&result.Account)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armbatch.AccountClientDeleteResponse], error) {
				return resumePoller[armbatch.AccountClientDeleteResponse](b.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (b *BatchAccount) completeFromAccount(acct *armbatch.Account) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if acct.ID != nil {
		nativeID = *acct.ID
		if rg, _, err := batchAccountIDParts(*acct.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(b.buildPropertiesFromResult(acct, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (b *BatchAccount) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := b.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list batch accounts: %w", err)
			}
			for _, acct := range page.Value {
				if acct.ID != nil {
					nativeIDs = append(nativeIDs, *acct.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := b.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list batch accounts: %w", err)
		}
		for _, acct := range page.Value {
			if acct.ID != nil {
				nativeIDs = append(nativeIDs, *acct.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
