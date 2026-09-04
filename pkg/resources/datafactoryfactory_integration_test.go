// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testDataFactoryNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DataFactory/factories/adf-1"

const testUserAssignedIdentityID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uai-1"

func newTestDataFactoryFactory(api dataFactoryFactoriesAPI) *DataFactoryFactory {
	return &DataFactoryFactory{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func dataFactoryDesired(overrides map[string]any) []byte {
	props := map[string]any{
		"name":                "adf-1",
		"location":            "eastus",
		"resourceGroupName":   "rg-1",
		"publicNetworkAccess": "Enabled",
		"Tags": []map[string]string{
			{"Key": "env", "Value": "conformance"},
		},
	}
	for k, v := range overrides {
		if v == nil {
			delete(props, k)
			continue
		}
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

func TestDataFactoryFactory_CRUD(t *testing.T) {
	factoryResult := armdatafactory.Factory{
		ID:       to.Ptr(testDataFactoryNativeID),
		Name:     to.Ptr("adf-1"),
		Location: to.Ptr("East US"),
		Identity: &armdatafactory.FactoryIdentity{
			Type:        to.Ptr(armdatafactory.FactoryIdentityTypeSystemAssigned),
			PrincipalID: to.Ptr("11111111-1111-1111-1111-111111111111"),
			TenantID:    to.Ptr("22222222-2222-2222-2222-222222222222"),
		},
		Properties: &armdatafactory.FactoryProperties{
			PublicNetworkAccess: to.Ptr(armdatafactory.PublicNetworkAccessEnabled),
			ProvisioningState:   to.Ptr("Succeeded"),
			Version:             to.Ptr("2018-06-01"),
			CreateTime:          to.Ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		},
		Tags: map[string]*string{"env": to.Ptr("conformance")},
	}

	var sent armdatafactory.Factory
	var sawRG, sawName string
	createCalls := 0
	deleteCalls := 0
	fake := &fakeDataFactoryFactoriesAPI{
		createOrUpdateFn: func(_ context.Context, rgName, name string, params armdatafactory.Factory, _ *armdatafactory.FactoriesClientCreateOrUpdateOptions) (armdatafactory.FactoriesClientCreateOrUpdateResponse, error) {
			sawRG, sawName, sent = rgName, name, params
			createCalls++
			return armdatafactory.FactoriesClientCreateOrUpdateResponse{Factory: factoryResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armdatafactory.FactoriesClientGetOptions) (armdatafactory.FactoriesClientGetResponse, error) {
			return armdatafactory.FactoriesClientGetResponse{Factory: factoryResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armdatafactory.FactoriesClientDeleteOptions) (armdatafactory.FactoriesClientDeleteResponse, error) {
			deleteCalls++
			return armdatafactory.FactoriesClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_ *armdatafactory.FactoriesClientListOptions) *runtime.Pager[armdatafactory.FactoriesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdatafactory.FactoriesClientListResponse]{
				More: func(_ armdatafactory.FactoriesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdatafactory.FactoriesClientListResponse) (armdatafactory.FactoriesClientListResponse, error) {
					return armdatafactory.FactoriesClientListResponse{
						FactoryListResponse: armdatafactory.FactoryListResponse{
							Value: []*armdatafactory.Factory{{ID: to.Ptr(testDataFactoryNativeID)}, {}},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armdatafactory.FactoriesClientListByResourceGroupOptions) *runtime.Pager[armdatafactory.FactoriesClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdatafactory.FactoriesClientListByResourceGroupResponse]{
				More: func(_ armdatafactory.FactoriesClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdatafactory.FactoriesClientListByResourceGroupResponse) (armdatafactory.FactoriesClientListByResourceGroupResponse, error) {
					return armdatafactory.FactoriesClientListByResourceGroupResponse{
						FactoryListResponse: armdatafactory.FactoryListResponse{
							Value: []*armdatafactory.Factory{{ID: to.Ptr(testDataFactoryNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDataFactoryFactory(fake)

	// Every FactoriesClient verb is synchronous, so a create reports success
	// directly and never hands back a resume token.
	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "adf-1",
			Properties: dataFactoryDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDataFactoryNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)

		require.Equal(t, "rg-1", sawRG)
		require.Equal(t, "adf-1", sawName)
		require.Equal(t, "eastus", *sent.Location)
		require.Equal(t, armdatafactory.PublicNetworkAccessEnabled, *sent.Properties.PublicNetworkAccess)
		require.Equal(t, "conformance", *sent.Tags["env"])
	})

	t.Run("Create_requires_resource_group", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: dataFactoryDesired(map[string]any{"resourceGroupName": nil}),
		})
		require.ErrorContains(t, err, "resourceGroupName is required")
	})

	t.Run("Create_requires_location", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: dataFactoryDesired(map[string]any{"location": nil}),
		})
		require.ErrorContains(t, err, "location is required")
	})

	// An undeclared identity must be left out of the body entirely: the service
	// then applies its own default of a system-assigned identity, which is what
	// the schema's provider default records.
	t.Run("Create_without_identity_sends_none", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: dataFactoryDesired(nil)})
		require.NoError(t, err)
		require.Nil(t, sent.Identity)
		require.Nil(t, sent.Properties.RepoConfiguration)
		require.Nil(t, sent.Properties.PurviewConfiguration)
	})

	t.Run("Create_with_user_assigned_identity", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: dataFactoryDesired(map[string]any{
				"identity": map[string]any{
					"type":                    "SystemAssigned,UserAssigned",
					"userAssignedIdentityIds": []string{testUserAssignedIdentityID},
				},
			}),
		})
		require.NoError(t, err)
		require.NotNil(t, sent.Identity)
		require.Equal(t, armdatafactory.FactoryIdentityTypeSystemAssignedUserAssigned, *sent.Identity.Type)
		require.Contains(t, sent.Identity.UserAssignedIdentities, testUserAssignedIdentityID)
	})

	t.Run("Create_with_github_repo_configuration", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: dataFactoryDesired(map[string]any{
				"repoConfiguration": map[string]any{
					"kind":                "FactoryGitHubConfiguration",
					"accountName":         "acme",
					"repositoryName":      "data-platform",
					"collaborationBranch": "main",
					"rootFolder":          "/adf",
					"hostName":            "https://github.acme.example",
				},
				"purviewResourceId": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Purview/accounts/pv-1",
			}),
		})
		require.NoError(t, err)
		github, ok := sent.Properties.RepoConfiguration.(*armdatafactory.FactoryGitHubConfiguration)
		require.True(t, ok)
		require.Equal(t, "acme", *github.AccountName)
		require.Equal(t, "main", *github.CollaborationBranch)
		require.Equal(t, "https://github.acme.example", *github.HostName)
		// lastCommitId is service state and must never be written back.
		require.Nil(t, github.LastCommitID)
		require.NotNil(t, sent.Properties.PurviewConfiguration)
	})

	t.Run("Create_with_vsts_repo_configuration", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: dataFactoryDesired(map[string]any{
				"repoConfiguration": map[string]any{
					"kind":                "FactoryVSTSConfiguration",
					"accountName":         "acme",
					"repositoryName":      "data-platform",
					"collaborationBranch": "main",
					"rootFolder":          "/",
					"projectName":         "Platform",
				},
			}),
		})
		require.NoError(t, err)
		vsts, ok := sent.Properties.RepoConfiguration.(*armdatafactory.FactoryVSTSConfiguration)
		require.True(t, ok)
		require.Equal(t, "Platform", *vsts.ProjectName)
	})

	t.Run("Create_rejects_vsts_without_project", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: dataFactoryDesired(map[string]any{
				"repoConfiguration": map[string]any{
					"kind":                "FactoryVSTSConfiguration",
					"accountName":         "acme",
					"repositoryName":      "data-platform",
					"collaborationBranch": "main",
					"rootFolder":          "/",
				},
			}),
		})
		require.ErrorContains(t, err, "projectName")
	})

	t.Run("Create_rejects_unknown_repo_kind", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: dataFactoryDesired(map[string]any{
				"repoConfiguration": map[string]any{
					"kind":                "FactoryGitLabConfiguration",
					"accountName":         "acme",
					"repositoryName":      "data-platform",
					"collaborationBranch": "main",
					"rootFolder":          "/",
				},
			}),
		})
		require.ErrorContains(t, err, "FactoryGitHubConfiguration")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataFactoryNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "adf-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM hands back "East US"; desired state writes the compact form.
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Enabled", props["publicNetworkAccess"])
		require.Equal(t, map[string]any{"type": "SystemAssigned"}, props["identity"])
		// principalId and tenantId are lifted out of the nested identity block
		// so they can be resolvables — a formae.Resolvable addresses a top-level
		// property by name and cannot reach one nested a level down.
		require.Equal(t, "11111111-1111-1111-1111-111111111111", props["identityPrincipalId"])
		require.Equal(t, "22222222-2222-2222-2222-222222222222", props["identityTenantId"])
	})

	// createTime, version and provisioningState are service state: none is desired
	// state and the first two move on their own.
	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataFactoryNativeID})
		require.NoError(t, err)
		for _, key := range []string{"createTime", "version", "provisioningState", "eTag"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("Read_reports_user_assigned_identity_ids_sorted", func(t *testing.T) {
		second := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aaa-0"
		withUAI := factoryResult
		withUAI.Identity = &armdatafactory.FactoryIdentity{
			Type: to.Ptr(armdatafactory.FactoryIdentityTypeUserAssigned),
			UserAssignedIdentities: map[string]any{
				testUserAssignedIdentityID: map[string]any{},
				second:                     map[string]any{},
			},
		}
		fake.getFn = func(_ context.Context, _, _ string, _ *armdatafactory.FactoriesClientGetOptions) (armdatafactory.FactoriesClientGetResponse, error) {
			return armdatafactory.FactoriesClientGetResponse{Factory: withUAI}, nil
		}
		defer func() {
			fake.getFn = func(_ context.Context, _, _ string, _ *armdatafactory.FactoriesClientGetOptions) (armdatafactory.FactoriesClientGetResponse, error) {
				return armdatafactory.FactoriesClientGetResponse{Factory: factoryResult}, nil
			}
		}()

		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDataFactoryNativeID})
		require.NoError(t, err)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		identity, ok := props["identity"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, []any{second, testUserAssignedIdentityID}, identity["userAssignedIdentityIds"])
	})

	// The narrow PATCH verb only accepts identity, tags and publicNetworkAccess,
	// so an update has to reissue CreateOrUpdate for repoConfiguration and
	// purviewResourceId to reconcile at all.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testDataFactoryNativeID,
			DesiredProperties: dataFactoryDesired(map[string]any{
				"publicNetworkAccess": "Disabled",
			}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, createCalls)
		require.Equal(t, armdatafactory.PublicNetworkAccessDisabled, *sent.Properties.PublicNetworkAccess)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataFactoryNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armdatafactory.FactoriesClientDeleteOptions) (armdatafactory.FactoriesClientDeleteResponse, error) {
			return armdatafactory.FactoriesClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDataFactoryNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDataFactoryNativeID}, got.NativeIDs)
	})

	// Discovery may have no resource group to scope by, in which case the whole
	// subscription is paged; entries with no ID are skipped rather than panicking.
	t.Run("List_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testDataFactoryNativeID}, got.NativeIDs)
	})

	// A failed create must carry the provider's own reason, not just a transition
	// to Failed with no cause.
	t.Run("Azure_error_maps_to_failure_with_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armdatafactory.Factory, _ *armdatafactory.FactoriesClientCreateOrUpdateOptions) (armdatafactory.FactoriesClientCreateOrUpdateResponse, error) {
			return armdatafactory.FactoriesClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 409, ErrorCode: "NameAlreadyInUse"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "adf-1", Properties: dataFactoryDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeResourceConflict, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "NameAlreadyInUse")
	})
}

func TestDataFactoryFactory_ReadNotFound(t *testing.T) {
	fake := &fakeDataFactoryFactoriesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armdatafactory.FactoriesClientGetOptions) (armdatafactory.FactoriesClientGetResponse, error) {
			return armdatafactory.FactoriesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestDataFactoryFactory(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testDataFactoryNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestDataFactoryFactory_StatusIsAlwaysDone(t *testing.T) {
	got, err := newTestDataFactoryFactory(&fakeDataFactoryFactoriesAPI{}).
		Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
}

func TestDataFactoryChildIDParts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		nativeID  string
		childType string
		wantChild string
		wantErr   bool
	}{
		{
			name:      "linked service",
			nativeID:  testDataFactoryNativeID + "/linkedservices/ls-1",
			childType: "linkedservices",
			wantChild: "ls-1",
		},
		{
			// ARM mixes casing in the type segment; matching must be
			// case-insensitive or every read of a real ID fails.
			name:      "integration runtime with ARM casing",
			nativeID:  testDataFactoryNativeID + "/integrationRuntimes/ir-1",
			childType: "integrationruntimes",
			wantChild: "ir-1",
		},
		{
			name:      "wrong child type",
			nativeID:  testDataFactoryNativeID + "/pipelines/p-1",
			childType: "linkedservices",
			wantErr:   true,
		},
		{
			name:      "not a factory child at all",
			nativeID:  "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Relay/namespaces/ns-1",
			childType: "pipelines",
			wantErr:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rgName, factoryName, child, err := dataFactoryChildIDParts(tc.nativeID, tc.childType)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "adf-1", factoryName)
			require.Equal(t, tc.wantChild, child)
		})
	}
}

func TestDataFactoryCanonicalJSON(t *testing.T) {
	// Key order must not survive: Go's map encoding sorts keys, so a body that
	// differed from the service's formatting only in ordering would otherwise look
	// like a change on every apply.
	parsed, err := dataFactoryCanonicalJSON("activities", `[{"type":"Wait","name":"w"}]`)
	require.NoError(t, err)
	encoded, err := json.Marshal(parsed)
	require.NoError(t, err)
	require.JSONEq(t, `[{"name":"w","type":"Wait"}]`, string(encoded))
	require.Equal(t, `[{"name":"w","type":"Wait"}]`, string(encoded))

	_, err = dataFactoryCanonicalJSON("activities", `{not json`)
	require.ErrorContains(t, err, "activities is not valid JSON")
}

// --- Test helpers ---

type fakeDataFactoryFactoriesAPI struct {
	createOrUpdateFn              func(ctx context.Context, rgName, name string, params armdatafactory.Factory, options *armdatafactory.FactoriesClientCreateOrUpdateOptions) (armdatafactory.FactoriesClientCreateOrUpdateResponse, error)
	getFn                         func(ctx context.Context, rgName, name string, options *armdatafactory.FactoriesClientGetOptions) (armdatafactory.FactoriesClientGetResponse, error)
	deleteFn                      func(ctx context.Context, rgName, name string, options *armdatafactory.FactoriesClientDeleteOptions) (armdatafactory.FactoriesClientDeleteResponse, error)
	newListPagerFn                func(options *armdatafactory.FactoriesClientListOptions) *runtime.Pager[armdatafactory.FactoriesClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armdatafactory.FactoriesClientListByResourceGroupOptions) *runtime.Pager[armdatafactory.FactoriesClientListByResourceGroupResponse]
}

func (f *fakeDataFactoryFactoriesAPI) CreateOrUpdate(ctx context.Context, rgName, name string, params armdatafactory.Factory, options *armdatafactory.FactoriesClientCreateOrUpdateOptions) (armdatafactory.FactoriesClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeDataFactoryFactoriesAPI) Get(ctx context.Context, rgName, name string, options *armdatafactory.FactoriesClientGetOptions) (armdatafactory.FactoriesClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeDataFactoryFactoriesAPI) Delete(ctx context.Context, rgName, name string, options *armdatafactory.FactoriesClientDeleteOptions) (armdatafactory.FactoriesClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, name, options)
}

func (f *fakeDataFactoryFactoriesAPI) NewListPager(options *armdatafactory.FactoriesClientListOptions) *runtime.Pager[armdatafactory.FactoriesClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeDataFactoryFactoriesAPI) NewListByResourceGroupPager(rgName string, options *armdatafactory.FactoriesClientListByResourceGroupOptions) *runtime.Pager[armdatafactory.FactoriesClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
