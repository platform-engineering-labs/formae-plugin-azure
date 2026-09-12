// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testORPPolicyID     = "2a20bb73-5717-4635-985a-5d4cf777438f"
	testORPRuleID       = "d5d18a48-8801-4554-aeaa-74faf65f5ef9"
	testORPSourceAcctID = "/subscriptions/sub-1/resourceGroups/rg-src/providers/Microsoft.Storage/storageAccounts/srcacct"
	testORPDestAcctID   = "/subscriptions/sub-1/resourceGroups/rg-dst/providers/Microsoft.Storage/storageAccounts/dstacct"
	testORPNativeID     = testORPDestAcctID + "/objectReplicationPolicies/" + testORPPolicyID
	testORPSourceID     = testORPSourceAcctID + "/objectReplicationPolicies/" + testORPPolicyID
)

func orpDesired(prefix string, metrics bool) json.RawMessage {
	props, _ := json.Marshal(map[string]any{
		"resourceGroupName":      "rg-dst",
		"storageAccountName":     "dstacct",
		"sourceStorageAccountId": testORPSourceAcctID,
		"metricsEnabled":         metrics,
		"rules": []map[string]any{{
			"sourceContainer":      "scont",
			"destinationContainer": "dcont",
			"filters": map[string]any{
				"prefixMatch": []string{prefix},
			},
		}},
	})
	return props
}

// orpCall records one CreateOrUpdate the provisioner made, so the two-sided flow
// can be asserted in order.
type orpCall struct {
	rgName      string
	accountName string
	policyName  string
	body        armstorage.ObjectReplicationPolicy
}

// echoORP answers the way ARM does on the destination side: it mints a policy id
// and a rule id per rule.
func echoORP(accountID string, sent armstorage.ObjectReplicationPolicy) armstorage.ObjectReplicationPolicy {
	out := armstorage.ObjectReplicationPolicy{
		ID:   to.Ptr(accountID + "/objectReplicationPolicies/" + testORPPolicyID),
		Name: to.Ptr(testORPPolicyID),
		Properties: &armstorage.ObjectReplicationPolicyProperties{
			PolicyID: to.Ptr(testORPPolicyID),
		},
	}
	if sent.Properties != nil {
		out.Properties.SourceAccount = sent.Properties.SourceAccount
		out.Properties.DestinationAccount = sent.Properties.DestinationAccount
		out.Properties.Metrics = sent.Properties.Metrics
		for _, r := range sent.Properties.Rules {
			copied := *r
			if copied.RuleID == nil {
				copied.RuleID = to.Ptr(testORPRuleID)
			}
			out.Properties.Rules = append(out.Properties.Rules, &copied)
		}
	}
	return out
}

func newORPFake(calls *[]orpCall) *fakeObjectReplicationPoliciesAPI {
	var current armstorage.ObjectReplicationPolicy
	fake := &fakeObjectReplicationPoliciesAPI{}
	fake.createOrUpdateFn = func(_ context.Context, rgName, accountName, policyName string, body armstorage.ObjectReplicationPolicy, _ *armstorage.ObjectReplicationPoliciesClientCreateOrUpdateOptions) (armstorage.ObjectReplicationPoliciesClientCreateOrUpdateResponse, error) {
		*calls = append(*calls, orpCall{rgName: rgName, accountName: accountName, policyName: policyName, body: body})
		accountID := testORPDestAcctID
		if accountName == "srcacct" {
			accountID = testORPSourceAcctID
		} else {
			current = echoORP(accountID, body)
		}
		return armstorage.ObjectReplicationPoliciesClientCreateOrUpdateResponse{ObjectReplicationPolicy: echoORP(accountID, body)}, nil
	}
	fake.getFn = func(_ context.Context, _, _, _ string, _ *armstorage.ObjectReplicationPoliciesClientGetOptions) (armstorage.ObjectReplicationPoliciesClientGetResponse, error) {
		return armstorage.ObjectReplicationPoliciesClientGetResponse{ObjectReplicationPolicy: current}, nil
	}
	fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armstorage.ObjectReplicationPoliciesClientDeleteOptions) (armstorage.ObjectReplicationPoliciesClientDeleteResponse, error) {
		return armstorage.ObjectReplicationPoliciesClientDeleteResponse{}, nil
	}
	fake.newListPagerFn = func(_, _ string, _ *armstorage.ObjectReplicationPoliciesClientListOptions) *runtime.Pager[armstorage.ObjectReplicationPoliciesClientListResponse] {
		return runtime.NewPager(runtime.PagingHandler[armstorage.ObjectReplicationPoliciesClientListResponse]{
			More: func(_ armstorage.ObjectReplicationPoliciesClientListResponse) bool { return false },
			Fetcher: func(_ context.Context, _ *armstorage.ObjectReplicationPoliciesClientListResponse) (armstorage.ObjectReplicationPoliciesClientListResponse, error) {
				return armstorage.ObjectReplicationPoliciesClientListResponse{
					ObjectReplicationPolicies: armstorage.ObjectReplicationPolicies{
						Value: []*armstorage.ObjectReplicationPolicy{{ID: to.Ptr(testORPNativeID)}},
					},
				}, nil
			},
		})
	}
	return fake
}

func TestStorageObjectReplicationPolicy_CRUD(t *testing.T) {
	var calls []orpCall
	fake := newORPFake(&calls)
	prov := newTestStorageObjectReplicationPolicy(fake)

	t.Run("Create_writes_the_destination_then_the_source", func(t *testing.T) {
		calls = nil
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: orpDesired("blobA", true)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testORPNativeID, got.ProgressResult.NativeID)

		require.Len(t, calls, 2, "one write per side of the policy")

		// Destination first, under the fixed name ARM requires on a create.
		require.Equal(t, "rg-dst", calls[0].rgName)
		require.Equal(t, "dstacct", calls[0].accountName)
		require.Equal(t, "default", calls[0].policyName)
		require.Equal(t, testORPSourceAcctID, *calls[0].body.Properties.SourceAccount)
		require.Equal(t, testORPDestAcctID, *calls[0].body.Properties.DestinationAccount)
		require.True(t, *calls[0].body.Properties.Metrics.Enabled)
		// A create must not invent rule ids; ARM mints them.
		require.Nil(t, calls[0].body.Properties.Rules[0].RuleID)

		// Source second, under the minted policy id and carrying the minted rule id.
		require.Equal(t, "rg-src", calls[1].rgName)
		require.Equal(t, "srcacct", calls[1].accountName)
		require.Equal(t, testORPPolicyID, calls[1].policyName)
		require.Equal(t, testORPRuleID, *calls[1].body.Properties.Rules[0].RuleID)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "rg-dst", serialized["resourceGroupName"])
		require.Equal(t, "dstacct", serialized["storageAccountName"])
		require.Equal(t, testORPSourceAcctID, serialized["sourceStorageAccountId"])
		require.Equal(t, testORPPolicyID, serialized["policyId"])
		require.Equal(t, testORPSourceID, serialized["sourcePolicyId"])
		require.Equal(t, true, serialized["metricsEnabled"])
		rules := serialized["rules"].([]any)
		require.Len(t, rules, 1)
		rule := rules[0].(map[string]any)
		require.Equal(t, "scont", rule["sourceContainer"])
		require.Equal(t, "dcont", rule["destinationContainer"])
		// The service-minted rule id is never surfaced: no caller can declare it.
		require.NotContains(t, rule, "ruleId")
		require.Equal(t, []any{"blobA"}, rule["filters"].(map[string]any)["prefixMatch"])
	})

	t.Run("Create_requires_sourceStorageAccountId", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":  "rg-dst",
			"storageAccountName": "dstacct",
			"rules":              []any{},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "sourceStorageAccountId is required")
	})

	t.Run("Create_rejects_a_source_that_is_not_a_storage_account_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName":      "rg-dst",
			"storageAccountName":     "dstacct",
			"sourceStorageAccountId": "srcacct",
			"rules": []map[string]any{{
				"sourceContainer": "scont", "destinationContainer": "dcont",
			}},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "not a storage account ARM ID")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testORPNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeStorageObjectReplicationPolicy, got.ResourceType)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &serialized))
		// A discovered policy reports the mirror it is paired with.
		require.Equal(t, testORPSourceID, serialized["sourcePolicyId"])
	})

	t.Run("Update_reuses_the_minted_policy_id_on_both_sides", func(t *testing.T) {
		calls = nil
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testORPNativeID,
			DesiredProperties: orpDesired("blobB", false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testORPNativeID, got.ProgressResult.NativeID)

		require.Len(t, calls, 2)
		require.Equal(t, testORPPolicyID, calls[0].policyName, "an update must not fall back to `default`")
		require.Equal(t, "dstacct", calls[0].accountName)
		require.Equal(t, testORPPolicyID, calls[1].policyName)
		require.Equal(t, "srcacct", calls[1].accountName)
		require.False(t, *calls[0].body.Properties.Metrics.Enabled)
		require.Equal(t, "blobB", *calls[0].body.Properties.Rules[0].Filters.PrefixMatch[0])
	})

	t.Run("Delete_removes_the_source_copy_first", func(t *testing.T) {
		var deletes []orpCall
		fake.deleteFn = func(_ context.Context, rgName, accountName, policyName string, _ *armstorage.ObjectReplicationPoliciesClientDeleteOptions) (armstorage.ObjectReplicationPoliciesClientDeleteResponse, error) {
			deletes = append(deletes, orpCall{rgName: rgName, accountName: accountName, policyName: policyName})
			return armstorage.ObjectReplicationPoliciesClientDeleteResponse{}, nil
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testORPNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		require.Len(t, deletes, 2)
		require.Equal(t, "srcacct", deletes[0].accountName)
		require.Equal(t, "rg-src", deletes[0].rgName)
		require.Equal(t, testORPPolicyID, deletes[0].policyName)
		require.Equal(t, "dstacct", deletes[1].accountName)
		require.Equal(t, testORPPolicyID, deletes[1].policyName)
	})

	t.Run("Status_rereads", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{
			RequestID: "req-1",
			NativeID:  testORPNativeID,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testORPNativeID, got.ProgressResult.NativeID)
	})

	t.Run("List_by_account", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-dst", "storageAccountName": "dstacct"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testORPNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parent_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})
}

func TestStorageObjectReplicationPolicy_Failures(t *testing.T) {
	t.Run("a_destination_write_that_mints_no_id_fails_rather_than_writing_the_source", func(t *testing.T) {
		var calls []orpCall
		fake := newORPFake(&calls)
		fake.createOrUpdateFn = func(_ context.Context, rgName, accountName, policyName string, body armstorage.ObjectReplicationPolicy, _ *armstorage.ObjectReplicationPoliciesClientCreateOrUpdateOptions) (armstorage.ObjectReplicationPoliciesClientCreateOrUpdateResponse, error) {
			calls = append(calls, orpCall{rgName: rgName, accountName: accountName, policyName: policyName, body: body})
			return armstorage.ObjectReplicationPoliciesClientCreateOrUpdateResponse{
				ObjectReplicationPolicy: armstorage.ObjectReplicationPolicy{Name: to.Ptr("default")},
			}, nil
		}
		prov := newTestStorageObjectReplicationPolicy(fake)

		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: orpDesired("blobA", false)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "did not mint a policy id")
		require.Len(t, calls, 1, "the source copy must not be written without a policy id")
	})

	t.Run("a_source_write_failure_is_reported_with_the_provider_error", func(t *testing.T) {
		var calls []orpCall
		fake := newORPFake(&calls)
		inner := fake.createOrUpdateFn
		fake.createOrUpdateFn = func(ctx context.Context, rgName, accountName, policyName string, body armstorage.ObjectReplicationPolicy, opts *armstorage.ObjectReplicationPoliciesClientCreateOrUpdateOptions) (armstorage.ObjectReplicationPoliciesClientCreateOrUpdateResponse, error) {
			if accountName == "srcacct" {
				return armstorage.ObjectReplicationPoliciesClientCreateOrUpdateResponse{},
					&azcore.ResponseError{StatusCode: 400, ErrorCode: "ChangeFeedNotEnabled"}
			}
			return inner(ctx, rgName, accountName, policyName, body, opts)
		}
		prov := newTestStorageObjectReplicationPolicy(fake)

		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: orpDesired("blobA", false)})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "source copy")
		require.Contains(t, got.ProgressResult.StatusMessage, "ChangeFeedNotEnabled")
	})

	t.Run("Read_maps_404", func(t *testing.T) {
		var calls []orpCall
		fake := newORPFake(&calls)
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armstorage.ObjectReplicationPoliciesClientGetOptions) (armstorage.ObjectReplicationPoliciesClientGetResponse, error) {
			return armstorage.ObjectReplicationPoliciesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		prov := newTestStorageObjectReplicationPolicy(fake)

		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testORPNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Delete_of_an_absent_policy_is_success", func(t *testing.T) {
		var calls []orpCall
		fake := newORPFake(&calls)
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armstorage.ObjectReplicationPoliciesClientGetOptions) (armstorage.ObjectReplicationPoliciesClientGetResponse, error) {
			return armstorage.ObjectReplicationPoliciesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		prov := newTestStorageObjectReplicationPolicy(fake)

		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testORPNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})
}

func TestStorageObjectReplicationPolicyIDParts(t *testing.T) {
	rg, acct, policyID, err := storageObjectReplicationPolicyIDParts(testORPNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-dst", rg)
	require.Equal(t, "dstacct", acct)
	require.Equal(t, testORPPolicyID, policyID)

	_, _, _, err = storageObjectReplicationPolicyIDParts(testORPDestAcctID)
	require.Error(t, err)
}

func TestStorageAccountARMID(t *testing.T) {
	require.Equal(t, testORPSourceAcctID, storageAccountARMID("sub-1", "rg-src", "srcacct"))
}

// --- Test helpers ---

func newTestStorageObjectReplicationPolicy(api storageObjectReplicationPoliciesAPI) *StorageObjectReplicationPolicy {
	return &StorageObjectReplicationPolicy{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeObjectReplicationPoliciesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, accountName, policyID string, properties armstorage.ObjectReplicationPolicy, opts *armstorage.ObjectReplicationPoliciesClientCreateOrUpdateOptions) (armstorage.ObjectReplicationPoliciesClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, accountName, policyID string, opts *armstorage.ObjectReplicationPoliciesClientGetOptions) (armstorage.ObjectReplicationPoliciesClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, accountName, policyID string, opts *armstorage.ObjectReplicationPoliciesClientDeleteOptions) (armstorage.ObjectReplicationPoliciesClientDeleteResponse, error)
	newListPagerFn   func(rgName, accountName string, opts *armstorage.ObjectReplicationPoliciesClientListOptions) *runtime.Pager[armstorage.ObjectReplicationPoliciesClientListResponse]
}

func (f *fakeObjectReplicationPoliciesAPI) CreateOrUpdate(ctx context.Context, rgName, accountName, policyID string, properties armstorage.ObjectReplicationPolicy, opts *armstorage.ObjectReplicationPoliciesClientCreateOrUpdateOptions) (armstorage.ObjectReplicationPoliciesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, accountName, policyID, properties, opts)
}

func (f *fakeObjectReplicationPoliciesAPI) Get(ctx context.Context, rgName, accountName, policyID string, opts *armstorage.ObjectReplicationPoliciesClientGetOptions) (armstorage.ObjectReplicationPoliciesClientGetResponse, error) {
	return f.getFn(ctx, rgName, accountName, policyID, opts)
}

func (f *fakeObjectReplicationPoliciesAPI) Delete(ctx context.Context, rgName, accountName, policyID string, opts *armstorage.ObjectReplicationPoliciesClientDeleteOptions) (armstorage.ObjectReplicationPoliciesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, accountName, policyID, opts)
}

func (f *fakeObjectReplicationPoliciesAPI) NewListPager(rgName, accountName string, opts *armstorage.ObjectReplicationPoliciesClientListOptions) *runtime.Pager[armstorage.ObjectReplicationPoliciesClientListResponse] {
	return f.newListPagerFn(rgName, accountName, opts)
}
