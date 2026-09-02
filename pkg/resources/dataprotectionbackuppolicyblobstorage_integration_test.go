// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// This file carries the fake BackupPoliciesClient and the shared fixtures used by
// all four backup-policy test files, because all four formae types are the same
// ARM resource behind dataprotectionpolicy.go.

func dpPolicyNativeID(vault, name string) string {
	return fmt.Sprintf("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DataProtection/backupVaults/%s/backupPolicies/%s", vault, name)
}

// --- fake client ---

type fakeDPBackupPoliciesAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, vaultName, policyName string, params armdataprotection.BaseBackupPolicyResource, opts *armdataprotection.BackupPoliciesClientCreateOrUpdateOptions) (armdataprotection.BackupPoliciesClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, vaultName, policyName string, opts *armdataprotection.BackupPoliciesClientGetOptions) (armdataprotection.BackupPoliciesClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, vaultName, policyName string, opts *armdataprotection.BackupPoliciesClientDeleteOptions) (armdataprotection.BackupPoliciesClientDeleteResponse, error)
	newListPagerFn   func(rgName, vaultName string, opts *armdataprotection.BackupPoliciesClientListOptions) *runtime.Pager[armdataprotection.BackupPoliciesClientListResponse]
}

func (f *fakeDPBackupPoliciesAPI) CreateOrUpdate(ctx context.Context, rgName, vaultName, policyName string, params armdataprotection.BaseBackupPolicyResource, opts *armdataprotection.BackupPoliciesClientCreateOrUpdateOptions) (armdataprotection.BackupPoliciesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, vaultName, policyName, params, opts)
}

func (f *fakeDPBackupPoliciesAPI) Get(ctx context.Context, rgName, vaultName, policyName string, opts *armdataprotection.BackupPoliciesClientGetOptions) (armdataprotection.BackupPoliciesClientGetResponse, error) {
	return f.getFn(ctx, rgName, vaultName, policyName, opts)
}

func (f *fakeDPBackupPoliciesAPI) Delete(ctx context.Context, rgName, vaultName, policyName string, opts *armdataprotection.BackupPoliciesClientDeleteOptions) (armdataprotection.BackupPoliciesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, vaultName, policyName, opts)
}

func (f *fakeDPBackupPoliciesAPI) NewListPager(rgName, vaultName string, opts *armdataprotection.BackupPoliciesClientListOptions) *runtime.Pager[armdataprotection.BackupPoliciesClientListResponse] {
	return f.newListPagerFn(rgName, vaultName, opts)
}

// dpPolicyEcho wires a fake that echoes the policy body it was sent back as the
// stored resource, so a test asserting on the read path is asserting on what the
// write path actually produced.
func dpPolicyEcho(t *testing.T, nativeID, name string, sent *armdataprotection.BaseBackupPolicyResource) *fakeDPBackupPoliciesAPI {
	t.Helper()
	fake := &fakeDPBackupPoliciesAPI{}
	fake.createOrUpdateFn = func(_ context.Context, _, _, policyName string, params armdataprotection.BaseBackupPolicyResource, _ *armdataprotection.BackupPoliciesClientCreateOrUpdateOptions) (armdataprotection.BackupPoliciesClientCreateOrUpdateResponse, error) {
		require.Equal(t, name, policyName)
		*sent = params
		stored := params
		stored.ID = to.Ptr(nativeID)
		stored.Name = to.Ptr(policyName)
		return armdataprotection.BackupPoliciesClientCreateOrUpdateResponse{BaseBackupPolicyResource: stored}, nil
	}
	fake.getFn = func(_ context.Context, _, _, _ string, _ *armdataprotection.BackupPoliciesClientGetOptions) (armdataprotection.BackupPoliciesClientGetResponse, error) {
		stored := *sent
		stored.ID = to.Ptr(nativeID)
		stored.Name = to.Ptr(name)
		return armdataprotection.BackupPoliciesClientGetResponse{BaseBackupPolicyResource: stored}, nil
	}
	fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdataprotection.BackupPoliciesClientDeleteOptions) (armdataprotection.BackupPoliciesClientDeleteResponse, error) {
		return armdataprotection.BackupPoliciesClientDeleteResponse{}, nil
	}
	fake.newListPagerFn = func(_, _ string, _ *armdataprotection.BackupPoliciesClientListOptions) *runtime.Pager[armdataprotection.BackupPoliciesClientListResponse] {
		stored := *sent
		stored.ID = to.Ptr(nativeID)
		stored.Name = to.Ptr(name)
		return runtime.NewPager(runtime.PagingHandler[armdataprotection.BackupPoliciesClientListResponse]{
			More: func(_ armdataprotection.BackupPoliciesClientListResponse) bool { return false },
			Fetcher: func(_ context.Context, _ *armdataprotection.BackupPoliciesClientListResponse) (armdataprotection.BackupPoliciesClientListResponse, error) {
				return armdataprotection.BackupPoliciesClientListResponse{
					BaseBackupPolicyResourceList: armdataprotection.BaseBackupPolicyResourceList{
						Value: []*armdataprotection.BaseBackupPolicyResource{
							&stored,
							// A policy for a different datasource in the same vault:
							// every flavour must ignore the other three.
							{
								ID: to.Ptr(dpPolicyNativeID("bv-1", "someone-elses")),
								Properties: &armdataprotection.BackupPolicy{
									ObjectType:      to.Ptr("BackupPolicy"),
									DatasourceTypes: []*string{to.Ptr("Microsoft.Something/else")},
								},
							},
						},
					},
				}, nil
			},
		})
	}
	return fake
}

// dpPolicyProvisioner builds the shared provisioner body directly. Each of the
// four registered types embeds exactly this and adds nothing, so a test that
// drives it drives all four code paths; the per-type files assert the bindings.
func dpPolicyProvisioner(api dataProtectionBackupPoliciesAPI, resourceType, datasourceType string) *dataProtectionBackupPolicy {
	return &dataProtectionBackupPolicy{
		api:            api,
		config:         &config.Config{SubscriptionId: "sub-1"},
		resourceType:   resourceType,
		datasourceType: datasourceType,
	}
}

// dpRetentionOnlyProps is the operational-tier blob shape: one retention rule and
// no schedule at all.
func dpRetentionOnlyProps(name, duration string) json.RawMessage {
	out, _ := json.Marshal(map[string]any{
		"name":              name,
		"resourceGroupName": "rg-1",
		"vaultName":         "bv-1",
		"retentionRules": []map[string]any{{
			"name":      "Default",
			"isDefault": true,
			"lifecycles": []map[string]any{{
				"sourceDatastoreType": "OperationalStore",
				"deleteAfterDuration": duration,
			}},
		}},
	})
	return out
}

// dpScheduledProps is the shape every other datasource uses: one backup rule with
// a schedule and one default retention rule.
func dpScheduledProps(name, backupType, datastoreType, interval, timeZone, duration string) json.RawMessage {
	rule := map[string]any{
		"name":                   "BackupRule",
		"backupType":             backupType,
		"datastoreType":          datastoreType,
		"repeatingTimeIntervals": []string{interval},
		"taggingCriteria": []map[string]any{{
			"tagName":         "Default",
			"isDefault":       true,
			"taggingPriority": 99,
		}},
	}
	if timeZone != "" {
		rule["timeZone"] = timeZone
	}
	out, _ := json.Marshal(map[string]any{
		"name":              name,
		"resourceGroupName": "rg-1",
		"vaultName":         "bv-1",
		"backupRules":       []map[string]any{rule},
		"retentionRules": []map[string]any{{
			"name":      "Default",
			"isDefault": true,
			"lifecycles": []map[string]any{{
				"sourceDatastoreType": datastoreType,
				"deleteAfterDuration": duration,
			}},
		}},
	})
	return out
}

// --- AZURE::DataProtection::BackupPolicyBlobStorage ---

func TestDataProtectionBackupPolicyBlobStorage_CRUD(t *testing.T) {
	const name = "bp-blob-1"
	nativeID := dpPolicyNativeID("bv-1", name)

	var sent armdataprotection.BaseBackupPolicyResource
	fake := dpPolicyEcho(t, nativeID, name, &sent)
	prov := dpPolicyProvisioner(fake,
		ResourceTypeDataProtectionBackupPolicyBlobStorage,
		datasourceDataProtectionBackupPolicyBlobStorage)

	t.Run("Create sends the blob datasource and an operational retention rule", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      name,
			Properties: dpRetentionOnlyProps(name, "P30D"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, nativeID, got.ProgressResult.NativeID)

		policy, ok := sent.Properties.(*armdataprotection.BackupPolicy)
		require.True(t, ok)
		require.Equal(t, "BackupPolicy", *policy.ObjectType)
		require.Len(t, policy.DatasourceTypes, 1)
		require.Equal(t, "Microsoft.Storage/storageAccounts/blobServices", *policy.DatasourceTypes[0])

		// Retention-only: exactly one rule, and it is the retention rule.
		require.Len(t, policy.PolicyRules, 1)
		retention, ok := policy.PolicyRules[0].(*armdataprotection.AzureRetentionRule)
		require.True(t, ok)
		require.Equal(t, "Default", *retention.Name)
		require.True(t, *retention.IsDefault)
		require.Len(t, retention.Lifecycles, 1)
		require.Equal(t, armdataprotection.DataStoreTypesOperationalStore, *retention.Lifecycles[0].SourceDataStore.DataStoreType)
		del, ok := retention.Lifecycles[0].DeleteAfter.(*armdataprotection.AbsoluteDeleteOption)
		require.True(t, ok)
		require.Equal(t, "P30D", *del.Duration)
	})

	t.Run("Read round-trips the rule tree", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: nativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeDataProtectionBackupPolicyBlobStorage, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "bv-1", props["vaultName"])
		require.Equal(t, name, props["name"])
		// An operational-tier policy has no schedules, so backupRules must be
		// absent rather than an empty list.
		require.NotContains(t, props, "backupRules")

		rules := props["retentionRules"].([]any)
		require.Len(t, rules, 1)
		rule := rules[0].(map[string]any)
		require.Equal(t, "Default", rule["name"])
		require.Equal(t, true, rule["isDefault"])
		lifecycles := rule["lifecycles"].([]any)
		require.Len(t, lifecycles, 1)
		require.Equal(t, "OperationalStore", lifecycles[0].(map[string]any)["sourceDatastoreType"])
		require.Equal(t, "P30D", lifecycles[0].(map[string]any)["deleteAfterDuration"])
		// ARM echoes an empty targetDataStoreCopySettings on some datasources; an
		// unset list must not read back as a declared empty one.
		require.NotContains(t, lifecycles[0].(map[string]any), "targetCopySettings")
	})

	t.Run("Update re-PUTs the whole rule tree", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          nativeID,
			DesiredProperties: dpRetentionOnlyProps(name, "P60D"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		policy := sent.Properties.(*armdataprotection.BackupPolicy)
		retention := policy.PolicyRules[0].(*armdataprotection.AzureRetentionRule)
		del := retention.Lifecycles[0].DeleteAfter.(*armdataprotection.AbsoluteDeleteOption)
		require.Equal(t, "P60D", *del.Duration)
	})

	t.Run("List returns only this datasource's policies", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "vaultName": "bv-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{nativeID}, got.NativeIDs)
	})

	t.Run("List without a vault scope enumerates nothing", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Delete of a missing policy is success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armdataprotection.BackupPoliciesClientDeleteOptions) (armdataprotection.BackupPoliciesClientDeleteResponse, error) {
			return armdataprotection.BackupPoliciesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: nativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("A rejected create reports the provider error", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdataprotection.BaseBackupPolicyResource, _ *armdataprotection.BackupPoliciesClientCreateOrUpdateOptions) (armdataprotection.BackupPoliciesClientCreateOrUpdateResponse, error) {
			return armdataprotection.BackupPoliciesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "UserErrorInvalidPolicyInput"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      name,
			Properties: dpRetentionOnlyProps(name, "P30D"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.NotEmpty(t, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "UserErrorInvalidPolicyInput")
	})
}

func TestDataProtectionBackupPolicyBlobStorage_Registration(t *testing.T) {
	require.Equal(t, "AZURE::DataProtection::BackupPolicyBlobStorage", ResourceTypeDataProtectionBackupPolicyBlobStorage)
	require.Equal(t, "Microsoft.Storage/storageAccounts/blobServices", datasourceDataProtectionBackupPolicyBlobStorage)

	prov := &DataProtectionBackupPolicyBlobStorage{
		dataProtectionBackupPolicy: *dpPolicyProvisioner(nil,
			ResourceTypeDataProtectionBackupPolicyBlobStorage,
			datasourceDataProtectionBackupPolicyBlobStorage),
	}
	require.Equal(t, ResourceTypeDataProtectionBackupPolicyBlobStorage, prov.resourceType)
}

// A policy needs at least one retention rule; ARM's error for an empty rule tree is
// opaque, so the handler refuses before the call.
func TestDataProtectionBackupPolicy_RejectsAnEmptyRuleTree(t *testing.T) {
	prov := dpPolicyProvisioner(&fakeDPBackupPoliciesAPI{},
		ResourceTypeDataProtectionBackupPolicyBlobStorage,
		datasourceDataProtectionBackupPolicyBlobStorage)

	props, _ := json.Marshal(map[string]any{
		"name":              "bp-empty",
		"resourceGroupName": "rg-1",
		"vaultName":         "bv-1",
	})
	_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
	require.ErrorContains(t, err, "at least one retentionRule")
}

// The scope keys List() reads must be the ones the PKL listParam supplies, or
// discovery calls List() with them empty forever.
func TestDataProtectionBackupPolicy_MissingScopeIsNotAnError(t *testing.T) {
	prov := dpPolicyProvisioner(&fakeDPBackupPoliciesAPI{},
		ResourceTypeDataProtectionBackupPolicyDisk,
		datasourceDataProtectionBackupPolicyDisk)

	got, err := prov.List(context.Background(), &resource.ListRequest{})
	require.NoError(t, err)
	require.Empty(t, got.NativeIDs)
}
