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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/netapp/armnetapp/v7"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeNetAppAccount = "AZURE::NetApp::Account"

// netAppAccountsAPI is the armnetapp surface used here. All three mutating
// calls are LROs. Note that armnetapp.AccountPatch carries tags and nothing else:
// every other property is createOnly in the schema because ARM has no way to
// change it in place.
type netAppAccountsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, accountName string, body armnetapp.Account, options *armnetapp.AccountsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetapp.AccountsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, accountName string, options *armnetapp.AccountsClientGetOptions) (armnetapp.AccountsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, accountName string, body armnetapp.AccountPatch, options *armnetapp.AccountsClientBeginUpdateOptions) (*runtime.Poller[armnetapp.AccountsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, accountName string, options *armnetapp.AccountsClientBeginDeleteOptions) (*runtime.Poller[armnetapp.AccountsClientDeleteResponse], error)
	NewListBySubscriptionPager(options *armnetapp.AccountsClientListBySubscriptionOptions) *runtime.Pager[armnetapp.AccountsClientListBySubscriptionResponse]
	NewListPager(resourceGroupName string, options *armnetapp.AccountsClientListOptions) *runtime.Pager[armnetapp.AccountsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeNetAppAccount, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &NetAppAccount{
			api:      c.NetAppAccountsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// DNSResolver is the provisioner for Azure DNS Private Resolvers
// (Microsoft.NetApp/netAppAccounts).
type NetAppAccount struct {
	api      netAppAccountsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// netAppAccountProps mirrors schema/pkl/netapp/netappaccount.pkl.
type netAppAccountProps struct {
	Name              string  `json:"name"`
	Location          string  `json:"location"`
	ResourceGroupName string  `json:"resourceGroupName"`
	NfsV4IDDomain     *string `json:"nfsV4IdDomain"`
}

func netAppAccountIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "netappaccounts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["netappaccounts"], nil
}

func (a *NetAppAccount) buildPropertiesFromResult(acct *armnetapp.Account, rgName string) map[string]any {
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
		if p.NfsV4IDDomain != nil {
			props["nfsV4IdDomain"] = *p.NfsV4IDDomain
		}
		// activeDirectories is deliberately dropped: it carries a domain-join
		// username and password. encryption, disableShowmount, multiAdStatus and
		// provisioningState are dropped as service state rather than desired state.
		// resourceGuid and provisioningState are deliberately dropped: neither is
		// desired state and both would only ever read back as noise.
	}

	if tags := azureTagsToFormaeTags(acct.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (a *NetAppAccount) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props netAppAccountProps
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

	params := armnetapp.Account{
		Location:   to.Ptr(props.Location),
		Properties: &armnetapp.AccountProperties{NfsV4IDDomain: props.NfsV4IDDomain},
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := a.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.NetApp/netAppAccounts/%s",
		a.config.SubscriptionId, props.ResourceGroupName, name)

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
		nativeID, propsJSON, err := a.completeFromAccount(&result.Account)
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

func (a *NetAppAccount) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := netAppAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.Account, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeNetAppAccount,
		Properties:   string(propsJSON),
	}, nil
}

// Update can only ever change tags: armnetapp.AccountPatch has no other field, and
// the schema marks everything else createOnly to match.
func (a *NetAppAccount) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := netAppAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props netAppAccountProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armnetapp.AccountPatch{
		Tags:       formaeTagsToAzureTags(request.DesiredProperties),
		Properties: &armnetapp.AccountProperties{NfsV4IDDomain: props.NfsV4IDDomain},
	}

	poller, err := a.api.BeginUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.Account, rgName))
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

func (a *NetAppAccount) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := netAppAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginDelete(ctx, rgName, name, nil)
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

func (a *NetAppAccount) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armnetapp.AccountsClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetapp.AccountsClientCreateOrUpdateResponse](a.pipeline, token)
			},
			func(_ context.Context, result armnetapp.AccountsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return a.completeFromAccount(&result.Account)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armnetapp.AccountsClientUpdateResponse], error) {
				return resumePoller[armnetapp.AccountsClientUpdateResponse](a.pipeline, token)
			},
			func(_ context.Context, result armnetapp.AccountsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return a.completeFromAccount(&result.Account)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetapp.AccountsClientDeleteResponse], error) {
				return resumePoller[armnetapp.AccountsClientDeleteResponse](a.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (a *NetAppAccount) completeFromAccount(acct *armnetapp.Account) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if acct.ID != nil {
		nativeID = *acct.ID
		if rg, _, err := netAppAccountIDParts(*acct.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(acct, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (a *NetAppAccount) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := a.api.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list netapp accounts: %w", err)
			}
			for _, acct := range page.Value {
				if acct.ID != nil {
					nativeIDs = append(nativeIDs, *acct.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := a.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list netapp accounts: %w", err)
		}
		for _, acct := range page.Value {
			if acct.ID != nil {
				nativeIDs = append(nativeIDs, *acct.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
