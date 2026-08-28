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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testStaticSiteNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/staticSites/swa-1"

func newTestStaticSite(api staticSitesAPI) *StaticSite {
	return &StaticSite{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func staticSiteDesired(stagingPolicy string, allowConfigFileUpdates bool) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "swa-1",
		"resourceGroupName": "rg-1",
		"location":          "eastus2",
		"sku": map[string]any{
			"name": "Free",
			"tier": "Free",
		},
		"repositoryUrl":            "https://github.com/example/site",
		"branch":                   "main",
		"repositoryToken":          map[string]any{"$value": "ghp_token"},
		"stagingEnvironmentPolicy": stagingPolicy,
		"allowConfigFileUpdates":   allowConfigFileUpdates,
		"buildProperties": map[string]any{
			"appLocation":                        "/",
			"apiLocation":                        "api",
			"outputLocation":                     "dist",
			"appBuildCommand":                    "npm run build",
			"skipGithubActionWorkflowGeneration": true,
		},
		"Tags": []any{map[string]any{"Key": "env", "Value": "test"}},
	})
	return out
}

func staticSiteResult() armappservice.StaticSiteARMResource {
	return armappservice.StaticSiteARMResource{
		ID:       to.Ptr(testStaticSiteNativeID),
		Name:     to.Ptr("swa-1"),
		Location: to.Ptr("East US 2"),
		SKU: &armappservice.SKUDescription{
			Name: to.Ptr("free"),
			Tier: to.Ptr("Free"),
		},
		Properties: &armappservice.StaticSite{
			RepositoryURL:            to.Ptr("https://github.com/example/site"),
			Branch:                   to.Ptr("main"),
			StagingEnvironmentPolicy: to.Ptr(armappservice.StagingEnvironmentPolicyEnabled),
			AllowConfigFileUpdates:   to.Ptr(true),
			PublicNetworkAccess:      to.Ptr("Enabled"),
			DefaultHostname:          to.Ptr("polite-rock-123.azurestaticapps.net"),
			// ARM never returns these; assert the plugin would not leak them even if
			// a response carried them.
			RepositoryToken: to.Ptr("ghp_token"),
			BuildProperties: &armappservice.StaticSiteBuildProperties{AppLocation: to.Ptr("/")},
		},
		Tags: map[string]*string{"env": to.Ptr("test")},
	}
}

func TestStaticSite_CRUD(t *testing.T) {
	result := staticSiteResult()
	doneResponse := armappservice.StaticSitesClientCreateOrUpdateStaticSiteResponse{StaticSiteARMResource: result}

	var sent armappservice.StaticSiteARMResource
	fake := &fakeStaticSitesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, name string, params armappservice.StaticSiteARMResource, _ *armappservice.StaticSitesClientBeginCreateOrUpdateStaticSiteOptions) (*runtime.Poller[armappservice.StaticSitesClientCreateOrUpdateStaticSiteResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "swa-1", name)
			sent = params
			return newDonePoller(doneResponse), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armappservice.StaticSitesClientGetStaticSiteOptions) (armappservice.StaticSitesClientGetStaticSiteResponse, error) {
			return armappservice.StaticSitesClientGetStaticSiteResponse{StaticSiteARMResource: result}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armappservice.StaticSitesClientBeginDeleteStaticSiteOptions) (*runtime.Poller[armappservice.StaticSitesClientDeleteStaticSiteResponse], error) {
			return newDonePoller(armappservice.StaticSitesClientDeleteStaticSiteResponse{}), nil
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armappservice.StaticSitesClientGetStaticSitesByResourceGroupOptions) *runtime.Pager[armappservice.StaticSitesClientGetStaticSitesByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappservice.StaticSitesClientGetStaticSitesByResourceGroupResponse]{
				More: func(_ armappservice.StaticSitesClientGetStaticSitesByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappservice.StaticSitesClientGetStaticSitesByResourceGroupResponse) (armappservice.StaticSitesClientGetStaticSitesByResourceGroupResponse, error) {
					return armappservice.StaticSitesClientGetStaticSitesByResourceGroupResponse{
						StaticSiteCollection: armappservice.StaticSiteCollection{
							Value: []*armappservice.StaticSiteARMResource{{ID: to.Ptr(testStaticSiteNativeID)}},
						},
					}, nil
				},
			})
		},
		newListPagerFn: func(_ *armappservice.StaticSitesClientListOptions) *runtime.Pager[armappservice.StaticSitesClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappservice.StaticSitesClientListResponse]{
				More: func(_ armappservice.StaticSitesClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappservice.StaticSitesClientListResponse) (armappservice.StaticSitesClientListResponse, error) {
					return armappservice.StaticSitesClientListResponse{
						StaticSiteCollection: armappservice.StaticSiteCollection{
							Value: []*armappservice.StaticSiteARMResource{
								{ID: to.Ptr(testStaticSiteNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Web/staticSites/swa-2")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestStaticSite(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "swa-1",
			Properties: staticSiteDesired("Enabled", true),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testStaticSiteNativeID, got.ProgressResult.NativeID)

		require.Equal(t, "eastus2", *sent.Location)
		require.Equal(t, "Free", *sent.SKU.Name)
		require.Equal(t, "https://github.com/example/site", *sent.Properties.RepositoryURL)
		require.Equal(t, "main", *sent.Properties.Branch)
		require.Equal(t, "ghp_token", *sent.Properties.RepositoryToken)
		require.Equal(t, armappservice.StagingEnvironmentPolicyEnabled, *sent.Properties.StagingEnvironmentPolicy)
		require.True(t, *sent.Properties.AllowConfigFileUpdates)
		require.Equal(t, "/", *sent.Properties.BuildProperties.AppLocation)
		require.Equal(t, "api", *sent.Properties.BuildProperties.APILocation)
		require.Equal(t, "dist", *sent.Properties.BuildProperties.OutputLocation)
		require.Equal(t, "npm run build", *sent.Properties.BuildProperties.AppBuildCommand)
		require.True(t, *sent.Properties.BuildProperties.SkipGithubActionWorkflowGeneration)
		require.Equal(t, "test", *sent.Tags["env"])
	})

	// A detached site — no repository — is the shape the conformance fixture uses.
	t.Run("Create_without_repository", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "swa-1", "resourceGroupName": "rg-1", "location": "eastus2",
			"sku": map[string]any{"name": "Free", "tier": "Free"},
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Nil(t, sent.Properties.RepositoryURL)
		require.Nil(t, sent.Properties.BuildProperties)
	})

	t.Run("Read_never_returns_write_only_fields", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testStaticSiteNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "swa-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		// ARM hands back "East US 2".
		require.Equal(t, "eastus2", props["location"])
		sku := props["sku"].(map[string]any)
		// ARM handed back "free"; desired state and the PKL union use "Free".
		require.Equal(t, "Free", sku["name"])
		require.Equal(t, "Free", sku["tier"])
		require.Equal(t, "https://github.com/example/site", props["repositoryUrl"])
		require.Equal(t, "main", props["branch"])
		require.Equal(t, "Enabled", props["stagingEnvironmentPolicy"])
		require.Equal(t, true, props["allowConfigFileUpdates"])
		require.Equal(t, "Enabled", props["publicNetworkAccess"])
		require.Equal(t, "polite-rock-123.azurestaticapps.net", props["defaultHostname"])
		require.NotContains(t, props, "repositoryToken")
		require.NotContains(t, props, "buildProperties")
	})

	t.Run("Update_keeps_native_id", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testStaticSiteNativeID,
			DesiredProperties: staticSiteDesired("Disabled", false),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testStaticSiteNativeID, got.ProgressResult.NativeID)
		require.Equal(t, armappservice.StagingEnvironmentPolicyDisabled, *sent.Properties.StagingEnvironmentPolicy)
		require.False(t, *sent.Properties.AllowConfigFileUpdates)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStaticSiteNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_in_progress_returns_poller", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armappservice.StaticSitesClientBeginDeleteStaticSiteOptions) (*runtime.Poller[armappservice.StaticSitesClientDeleteStaticSiteResponse], error) {
			return newInProgressPoller[armappservice.StaticSitesClientDeleteStaticSiteResponse](), nil
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStaticSiteNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, testStaticSiteNativeID, got.ProgressResult.NativeID)
		require.NotEmpty(t, got.ProgressResult.RequestID)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armappservice.StaticSitesClientBeginDeleteStaticSiteOptions) (*runtime.Poller[armappservice.StaticSitesClientDeleteStaticSiteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testStaticSiteNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testStaticSiteNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armappservice.StaticSiteARMResource, _ *armappservice.StaticSitesClientBeginCreateOrUpdateStaticSiteOptions) (*runtime.Poller[armappservice.StaticSitesClientCreateOrUpdateStaticSiteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 409}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "swa-1",
			Properties: staticSiteDesired("Enabled", true),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestStaticSite_CreateInProgressPinsNativeID(t *testing.T) {
	fake := &fakeStaticSitesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armappservice.StaticSiteARMResource, _ *armappservice.StaticSitesClientBeginCreateOrUpdateStaticSiteOptions) (*runtime.Poller[armappservice.StaticSitesClientCreateOrUpdateStaticSiteResponse], error) {
			return newInProgressPoller[armappservice.StaticSitesClientCreateOrUpdateStaticSiteResponse](), nil
		},
	}
	got, err := newTestStaticSite(fake).Create(context.Background(), &resource.CreateRequest{
		Label:      "swa-1",
		Properties: staticSiteDesired("Enabled", true),
	})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	require.Equal(t, testStaticSiteNativeID, got.ProgressResult.NativeID)
	require.NotEmpty(t, got.ProgressResult.RequestID)
}

func TestStaticSite_ReadNotFound(t *testing.T) {
	fake := &fakeStaticSitesAPI{
		getFn: func(_ context.Context, _, _ string, _ *armappservice.StaticSitesClientGetStaticSiteOptions) (armappservice.StaticSitesClientGetStaticSiteResponse, error) {
			return armappservice.StaticSitesClientGetStaticSiteResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestStaticSite(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testStaticSiteNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestStaticSite_IDParts(t *testing.T) {
	rgName, siteName, err := staticSiteIDParts(testStaticSiteNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rgName)
	require.Equal(t, "swa-1", siteName)

	_, _, err = staticSiteIDParts(testWebAppNativeID)
	require.Error(t, err)
}

// --- Test helpers ---

type fakeStaticSitesAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, params armappservice.StaticSiteARMResource, options *armappservice.StaticSitesClientBeginCreateOrUpdateStaticSiteOptions) (*runtime.Poller[armappservice.StaticSitesClientCreateOrUpdateStaticSiteResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armappservice.StaticSitesClientGetStaticSiteOptions) (armappservice.StaticSitesClientGetStaticSiteResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armappservice.StaticSitesClientBeginDeleteStaticSiteOptions) (*runtime.Poller[armappservice.StaticSitesClientDeleteStaticSiteResponse], error)
	newListByResourceGroupPagerFn func(rgName string, options *armappservice.StaticSitesClientGetStaticSitesByResourceGroupOptions) *runtime.Pager[armappservice.StaticSitesClientGetStaticSitesByResourceGroupResponse]
	newListPagerFn                func(options *armappservice.StaticSitesClientListOptions) *runtime.Pager[armappservice.StaticSitesClientListResponse]
}

func (f *fakeStaticSitesAPI) BeginCreateOrUpdateStaticSite(ctx context.Context, rgName string, name string, params armappservice.StaticSiteARMResource, options *armappservice.StaticSitesClientBeginCreateOrUpdateStaticSiteOptions) (*runtime.Poller[armappservice.StaticSitesClientCreateOrUpdateStaticSiteResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, params, options)
}

func (f *fakeStaticSitesAPI) GetStaticSite(ctx context.Context, rgName string, name string, options *armappservice.StaticSitesClientGetStaticSiteOptions) (armappservice.StaticSitesClientGetStaticSiteResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeStaticSitesAPI) BeginDeleteStaticSite(ctx context.Context, rgName string, name string, options *armappservice.StaticSitesClientBeginDeleteStaticSiteOptions) (*runtime.Poller[armappservice.StaticSitesClientDeleteStaticSiteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeStaticSitesAPI) NewGetStaticSitesByResourceGroupPager(rgName string, options *armappservice.StaticSitesClientGetStaticSitesByResourceGroupOptions) *runtime.Pager[armappservice.StaticSitesClientGetStaticSitesByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}

func (f *fakeStaticSitesAPI) NewListPager(options *armappservice.StaticSitesClientListOptions) *runtime.Pager[armappservice.StaticSitesClientListResponse] {
	return f.newListPagerFn(options)
}
