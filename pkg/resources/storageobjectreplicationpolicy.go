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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeStorageObjectReplicationPolicy = "AZURE::Storage::ObjectReplicationPolicy"

// objectReplicationPolicyDefaultName is the name ARM requires when the policy is
// first written to the DESTINATION account. ARM answers with a minted GUID, and
// that GUID is the name every later write — to either account — must use.
const objectReplicationPolicyDefaultName = "default"

// storageObjectReplicationPoliciesAPI is the armstorage surface used here; every
// verb is synchronous.
type storageObjectReplicationPoliciesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, accountName, objectReplicationPolicyID string, properties armstorage.ObjectReplicationPolicy, options *armstorage.ObjectReplicationPoliciesClientCreateOrUpdateOptions) (armstorage.ObjectReplicationPoliciesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, accountName, objectReplicationPolicyID string, options *armstorage.ObjectReplicationPoliciesClientGetOptions) (armstorage.ObjectReplicationPoliciesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, accountName, objectReplicationPolicyID string, options *armstorage.ObjectReplicationPoliciesClientDeleteOptions) (armstorage.ObjectReplicationPoliciesClientDeleteResponse, error)
	NewListPager(resourceGroupName, accountName string, options *armstorage.ObjectReplicationPoliciesClientListOptions) *runtime.Pager[armstorage.ObjectReplicationPoliciesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeStorageObjectReplicationPolicy, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &StorageObjectReplicationPolicy{api: c.StorageObjectReplicationPoliciesClient, config: cfg}
	})
}

// StorageObjectReplicationPolicy provisions object replication between two
// storage accounts.
//
// ARM splits one logical policy across two resources that must agree. The
// destination copy is created first, under the name `default`, and ARM answers
// with a policy id plus a rule id for every rule; the source copy must then be
// written under that policy id, carrying those rule ids. Neither half replicates
// anything on its own, so this provisioner performs both writes on create and
// update, and both deletes on delete. The identifier is the destination copy's ARM
// ID, which is the half that mints the ids.
type StorageObjectReplicationPolicy struct {
	api    storageObjectReplicationPoliciesAPI
	config *config.Config
}

// storageObjectReplicationPolicyProps mirrors
// schema/pkl/storage/storageobjectreplicationpolicy.pkl.
type storageObjectReplicationPolicyProps struct {
	ResourceGroupName      string                        `json:"resourceGroupName"`
	StorageAccountName     string                        `json:"storageAccountName"`
	SourceStorageAccountID string                        `json:"sourceStorageAccountId"`
	MetricsEnabled         *bool                         `json:"metricsEnabled"`
	Rules                  []objectReplicationPolicyRule `json:"rules"`
}

type objectReplicationPolicyRule struct {
	SourceContainer      string                          `json:"sourceContainer"`
	DestinationContainer string                          `json:"destinationContainer"`
	Filters              *objectReplicationPolicyFilters `json:"filters"`
}

type objectReplicationPolicyFilters struct {
	PrefixMatch     []string `json:"prefixMatch"`
	MinCreationTime string   `json:"minCreationTime"`
}

func storageObjectReplicationPolicyIDParts(resourceID string) (rgName, accountName, policyID string, err error) {
	rgName, names, err := armIDParts(resourceID, "storageaccounts", "objectreplicationpolicies")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["storageaccounts"], names["objectreplicationpolicies"], nil
}

// storageAccountARMID builds the full resource ID ARM wants for
// sourceAccount/destinationAccount whenever cross-tenant replication is
// disallowed, which is the default on accounts created today.
func storageAccountARMID(subscriptionID, rgName, accountName string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s",
		subscriptionID, rgName, accountName)
}

func objectReplicationPolicyFromProps(props storageObjectReplicationPolicyProps, destinationAccountID string) armstorage.ObjectReplicationPolicy {
	rules := make([]*armstorage.ObjectReplicationPolicyRule, 0, len(props.Rules))
	for _, r := range props.Rules {
		rule := &armstorage.ObjectReplicationPolicyRule{
			SourceContainer:      to.Ptr(r.SourceContainer),
			DestinationContainer: to.Ptr(r.DestinationContainer),
		}
		if f := r.Filters; f != nil {
			filters := &armstorage.ObjectReplicationPolicyFilter{
				PrefixMatch: stringPointers(f.PrefixMatch),
			}
			if f.MinCreationTime != "" {
				filters.MinCreationTime = to.Ptr(f.MinCreationTime)
			}
			rule.Filters = filters
		}
		rules = append(rules, rule)
	}

	return armstorage.ObjectReplicationPolicy{
		Properties: &armstorage.ObjectReplicationPolicyProperties{
			SourceAccount:      to.Ptr(props.SourceStorageAccountID),
			DestinationAccount: to.Ptr(destinationAccountID),
			Metrics: &armstorage.ObjectReplicationPolicyPropertiesMetrics{
				Enabled: to.Ptr(props.MetricsEnabled != nil && *props.MetricsEnabled),
			},
			Rules: rules,
		},
	}
}

func serializeStorageObjectReplicationPolicyProperties(result armstorage.ObjectReplicationPolicy, rgName, accountName, sourcePolicyID string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName":  rgName,
		"storageAccountName": accountName,
		"metricsEnabled":     false,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if sourcePolicyID != "" {
		props["sourcePolicyId"] = sourcePolicyID
	}

	rules := make([]map[string]any, 0)
	if p := result.Properties; p != nil {
		if p.SourceAccount != nil {
			props["sourceStorageAccountId"] = *p.SourceAccount
		}
		if p.PolicyID != nil {
			props["policyId"] = *p.PolicyID
		}
		if p.Metrics != nil && p.Metrics.Enabled != nil {
			props["metricsEnabled"] = *p.Metrics.Enabled
		}
		for _, r := range p.Rules {
			if r == nil {
				continue
			}
			rule := map[string]any{}
			if r.SourceContainer != nil {
				rule["sourceContainer"] = *r.SourceContainer
			}
			if r.DestinationContainer != nil {
				rule["destinationContainer"] = *r.DestinationContainer
			}
			// ruleId is service-minted and threaded through internally; surfacing it
			// would be a property no caller can declare.
			if r.Filters != nil {
				filters := map[string]any{}
				if v := stringsFromPointers(r.Filters.PrefixMatch); len(v) > 0 {
					filters["prefixMatch"] = v
				}
				if r.Filters.MinCreationTime != nil && *r.Filters.MinCreationTime != "" {
					filters["minCreationTime"] = *r.Filters.MinCreationTime
				}
				if len(filters) > 0 {
					rule["filters"] = filters
				}
			}
			rules = append(rules, rule)
		}
	}
	props["rules"] = rules

	return json.Marshal(props)
}

// upsert performs the two-sided write.
//
// policyName is `default` on a create, and the already-minted policy id on an
// update. The destination response is echoed straight back to the source account
// so the service-minted rule ids travel with it: ARM rejects a source-side write
// whose rules carry no rule id.
func (o *StorageObjectReplicationPolicy) upsert(ctx context.Context, payload json.RawMessage, policyName string) (armstorage.ObjectReplicationPolicy, string, storageObjectReplicationPolicyProps, error) {
	var props storageObjectReplicationPolicyProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armstorage.ObjectReplicationPolicy{}, "", props, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return armstorage.ObjectReplicationPolicy{}, "", props, fmt.Errorf("resourceGroupName is required")
	}
	if props.StorageAccountName == "" {
		return armstorage.ObjectReplicationPolicy{}, "", props, fmt.Errorf("storageAccountName is required")
	}
	if props.SourceStorageAccountID == "" {
		return armstorage.ObjectReplicationPolicy{}, "", props, fmt.Errorf("sourceStorageAccountId is required")
	}
	if len(props.Rules) == 0 {
		return armstorage.ObjectReplicationPolicy{}, "", props, fmt.Errorf("at least one rule is required")
	}
	sourceRG, sourceAccount, err := storageAccountIDParts(props.SourceStorageAccountID)
	if err != nil {
		return armstorage.ObjectReplicationPolicy{}, "", props, fmt.Errorf("sourceStorageAccountId is not a storage account ARM ID: %w", err)
	}

	destinationAccountID := storageAccountARMID(o.config.SubscriptionId, props.ResourceGroupName, props.StorageAccountName)
	body := objectReplicationPolicyFromProps(props, destinationAccountID)

	destination, err := o.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.StorageAccountName, policyName, body, nil)
	if err != nil {
		return armstorage.ObjectReplicationPolicy{}, "", props, fmt.Errorf("failed to write the destination copy of the policy on %s: %w", props.StorageAccountName, err)
	}

	mintedID := policyName
	if destination.Name != nil && *destination.Name != "" {
		mintedID = *destination.Name
	}
	if mintedID == objectReplicationPolicyDefaultName {
		return armstorage.ObjectReplicationPolicy{}, "", props,
			fmt.Errorf("ARM did not mint a policy id for the destination copy on %s", props.StorageAccountName)
	}

	// Echo the destination document — rule ids included — onto the source account.
	source, err := o.api.CreateOrUpdate(ctx, sourceRG, sourceAccount, mintedID,
		armstorage.ObjectReplicationPolicy{Properties: destination.Properties}, nil)
	if err != nil {
		return armstorage.ObjectReplicationPolicy{}, "", props, fmt.Errorf("failed to write the source copy of the policy on %s: %w", sourceAccount, err)
	}

	sourcePolicyID := ""
	if source.ID != nil {
		sourcePolicyID = *source.ID
	}
	return destination.ObjectReplicationPolicy, sourcePolicyID, props, nil
}

func (o *StorageObjectReplicationPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	policy, sourcePolicyID, props, err := o.upsert(ctx, request.Properties, objectReplicationPolicyDefaultName)
	if err != nil {
		if props.ResourceGroupName == "" || props.StorageAccountName == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := serializeStorageObjectReplicationPolicyProperties(policy, props.ResourceGroupName, props.StorageAccountName, sourcePolicyID)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ObjectReplicationPolicy properties: %w", err)
	}

	nativeID := ""
	if policy.ID != nil {
		nativeID = *policy.ID
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

func (o *StorageObjectReplicationPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, policyID, err := storageObjectReplicationPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := o.api.Get(ctx, rgName, accountName, policyID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeStorageObjectReplicationPolicyProperties(result.ObjectReplicationPolicy, rgName, accountName, o.sourcePolicyID(result.ObjectReplicationPolicy, policyID))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ObjectReplicationPolicy properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeStorageObjectReplicationPolicy,
		Properties:   string(propsJSON),
	}, nil
}

// sourcePolicyID derives the ARM ID of the source-account copy from the policy's
// own sourceAccount field, so a discovered policy reports it too.
func (o *StorageObjectReplicationPolicy) sourcePolicyID(policy armstorage.ObjectReplicationPolicy, policyID string) string {
	if policy.Properties == nil || policy.Properties.SourceAccount == nil {
		return ""
	}
	sourceRG, sourceAccount, err := storageAccountIDParts(*policy.Properties.SourceAccount)
	if err != nil {
		// A policy written elsewhere may carry a bare account name; there is then no
		// resource group to build an ID from, and reporting a guess would be worse
		// than reporting nothing.
		return ""
	}
	return fmt.Sprintf("%s/objectReplicationPolicies/%s",
		storageAccountARMID(o.config.SubscriptionId, sourceRG, sourceAccount), policyID)
}

func (o *StorageObjectReplicationPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	_, _, policyID, err := storageObjectReplicationPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	policy, sourcePolicyID, props, err := o.upsert(ctx, request.DesiredProperties, policyID)
	if err != nil {
		if props.ResourceGroupName == "" || props.StorageAccountName == "" {
			return nil, err
		}
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

	propsJSON, err := serializeStorageObjectReplicationPolicyProperties(policy, props.ResourceGroupName, props.StorageAccountName, sourcePolicyID)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ObjectReplicationPolicy properties after update: %w", err)
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

// Delete removes both copies. The source copy goes first: while it exists the
// source account keeps trying to replicate, and ARM leaves it behind if only the
// destination copy is deleted.
func (o *StorageObjectReplicationPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, policyID, err := storageObjectReplicationPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// The source account is only discoverable from the policy body, so read it
	// before deleting. A policy that is already gone needs no further work.
	existing, err := o.api.Get(ctx, rgName, accountName, policyID, nil)
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
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	if existing.Properties != nil && existing.Properties.SourceAccount != nil {
		if sourceRG, sourceAccount, parseErr := storageAccountIDParts(*existing.Properties.SourceAccount); parseErr == nil {
			if _, delErr := o.api.Delete(ctx, sourceRG, sourceAccount, policyID, nil); delErr != nil && !isDeleteSuccessError(delErr) {
				return &resource.DeleteResult{
					ProgressResult: &resource.ProgressResult{
						Operation:       resource.OperationDelete,
						OperationStatus: resource.OperationStatusFailure,
						NativeID:        request.NativeID,
						ErrorCode:       operationErrorCode(delErr),
						StatusMessage:   fmt.Sprintf("failed to delete the source copy of the policy on %s: %v", sourceAccount, delErr),
					},
				}, nil
			}
		}
	}

	if _, err := o.api.Delete(ctx, rgName, accountName, policyID, nil); err != nil && !isDeleteSuccessError(err) {
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

// Object-replication writes are synchronous, so Status just re-reads.
func (o *StorageObjectReplicationPolicy) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, accountName, policyID, err := storageObjectReplicationPolicyIDParts(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   err.Error(),
			},
		}, err
	}

	result, err := o.api.Get(ctx, rgName, accountName, policyID, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, fmt.Errorf("failed to get ObjectReplicationPolicy status: %w", err)
	}

	propsJSON, err := serializeStorageObjectReplicationPolicyProperties(result.ObjectReplicationPolicy, rgName, accountName, o.sourcePolicyID(result.ObjectReplicationPolicy, policyID))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ObjectReplicationPolicy properties: %w", err)
	}
	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

// List enumerates the policies on one account. Both copies of a policy list on
// their own account, so a source account also reports the mirror this provisioner
// wrote; discovery of the mirror reads back the same document, which is the
// honest answer — ARM really does hold two resources.
func (o *StorageObjectReplicationPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["storageAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := o.api.NewListPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list ObjectReplicationPolicies in storage account %s: %w", accountName, err)
		}
		for _, item := range page.Value {
			if item != nil && item.ID != nil {
				nativeIDs = append(nativeIDs, *item.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
