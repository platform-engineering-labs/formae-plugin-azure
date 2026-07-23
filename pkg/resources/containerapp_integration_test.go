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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testCANativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.App/containerApps/app-1"
const testCAEnvID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.App/managedEnvironments/env-1"

// fullCAProps exercises containers/env/scale/ingress AND a write-only secret so
// the round-trip test can prove the secret value never surfaces on serialize.
func fullCAProps() map[string]any {
	return map[string]any{
		"resourceGroupName":    "rg-1",
		"name":                 "app-1",
		"location":             "eastus",
		"managedEnvironmentId": testCAEnvID,
		"configuration": map[string]any{
			"ingress": map[string]any{
				"external":      true,
				"targetPort":    80,
				"transport":     "auto",
				"allowInsecure": false,
			},
			"secrets": []map[string]any{
				{"name": "api-key", "value": "super-secret-value"},
			},
		},
		"template": map[string]any{
			"containers": []map[string]any{
				{
					"name":  "main",
					"image": "mcr.microsoft.com/k8se/quickstart:latest",
					"resources": map[string]any{
						"cpu":    0.5,
						"memory": "1Gi",
					},
					"env": []map[string]any{
						{"name": "GREETING", "value": "hello"},
						{"name": "API_KEY", "secretRef": "api-key"},
					},
				},
			},
			"scale": map[string]any{
				"minReplicas": 0,
				"maxReplicas": 1,
			},
		},
	}
}

// noSecretCAProps matches the default conformance fixture: a plain container with
// an env var, external ingress, NO secrets.
func noSecretCAProps() map[string]any {
	return map[string]any{
		"resourceGroupName":    "rg-1",
		"name":                 "app-1",
		"location":             "eastus",
		"managedEnvironmentId": testCAEnvID,
		"configuration": map[string]any{
			"ingress": map[string]any{
				"external":   true,
				"targetPort": 80,
			},
		},
		"template": map[string]any{
			"containers": []map[string]any{
				{
					"name":  "main",
					"image": "mcr.microsoft.com/k8se/quickstart:latest",
					"resources": map[string]any{
						"cpu":    0.5,
						"memory": "1Gi",
					},
					"env": []map[string]any{
						{"name": "GREETING", "value": "hello"},
					},
				},
			},
			"scale": map[string]any{
				"minReplicas": 0,
				"maxReplicas": 1,
			},
		},
	}
}

func createCAProps() json.RawMessage {
	props, _ := json.Marshal(noSecretCAProps())
	return props
}

// TestContainerApp_MarshallerRoundTrip proves containers/env/scale/ingress
// round-trip clean AND the secret value never surfaces on serialize (Azure never
// returns it -> false drift if serialized).
func TestContainerApp_MarshallerRoundTrip(t *testing.T) {
	app := newTestContainerApp(nil)

	var props map[string]any
	require.NoError(t, json.Unmarshal(mustJSON(t, fullCAProps()), &props))

	params, err := app.buildContainerAppParams(props, "eastus")
	require.NoError(t, err)
	params.ID = to.Ptr(testCANativeID)
	// Simulate the read-only ingress FQDN Azure fills in.
	params.Properties.Configuration.Ingress.Fqdn = to.Ptr("app-1.happy-abc.eastus.azurecontainerapps.io")

	raw, err := serializeContainerAppProperties(params, "rg-1", "app-1")
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))

	require.Equal(t, "app-1", got["name"])
	require.Equal(t, "eastus", got["location"])
	require.Equal(t, testCANativeID, got["id"])
	require.Equal(t, testCAEnvID, got["managedEnvironmentId"], "environment ref must round-trip as a full ARM ID")
	require.Equal(t, "app-1.happy-abc.eastus.azurecontainerapps.io", got["fqdn"], "ingress FQDN must surface as top-level fqdn output")

	cfg := got["configuration"].(map[string]any)
	ingress := cfg["ingress"].(map[string]any)
	require.Equal(t, true, ingress["external"])
	require.EqualValues(t, 80, ingress["targetPort"])
	require.Equal(t, "auto", ingress["transport"])
	require.Equal(t, false, ingress["allowInsecure"])

	// Secret NAME round-trips; VALUE is write-only and must never be read back.
	secrets := cfg["secrets"].([]any)
	require.Len(t, secrets, 1)
	require.Equal(t, "api-key", secrets[0].(map[string]any)["name"])
	require.Nil(t, secrets[0].(map[string]any)["value"], "secret value must not surface in serialized state")

	tmpl := got["template"].(map[string]any)
	containers := tmpl["containers"].([]any)
	require.Len(t, containers, 1)
	c := containers[0].(map[string]any)
	require.Equal(t, "main", c["name"])
	require.Equal(t, "mcr.microsoft.com/k8se/quickstart:latest", c["image"])
	res := c["resources"].(map[string]any)
	require.EqualValues(t, 0.5, res["cpu"])
	require.Equal(t, "1Gi", res["memory"])
	env := c["env"].([]any)
	require.Len(t, env, 2)
	require.Equal(t, "GREETING", env[0].(map[string]any)["name"])
	require.Equal(t, "hello", env[0].(map[string]any)["value"])
	require.Equal(t, "API_KEY", env[1].(map[string]any)["name"])
	require.Equal(t, "api-key", env[1].(map[string]any)["secretRef"])

	scale := tmpl["scale"].(map[string]any)
	require.EqualValues(t, 0, scale["minReplicas"])
	require.EqualValues(t, 1, scale["maxReplicas"])
}

func TestContainerApp_CRUD(t *testing.T) {
	var builtProps map[string]any
	require.NoError(t, json.Unmarshal(createCAProps(), &builtProps))
	built, err := newTestContainerApp(nil).buildContainerAppParams(builtProps, "eastus")
	require.NoError(t, err)
	built.ID = to.Ptr(testCANativeID)
	built.Name = to.Ptr("app-1")
	built.Location = to.Ptr("eastus")

	doneResult := armappcontainers.ContainerAppsClientCreateOrUpdateResponse{ContainerApp: built}

	fake := &fakeContainerAppsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armappcontainers.ContainerApp, _ *armappcontainers.ContainerAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappcontainers.ContainerAppsClientCreateOrUpdateResponse], error) {
			return newDonePoller(doneResult), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armappcontainers.ContainerAppsClientGetOptions) (armappcontainers.ContainerAppsClientGetResponse, error) {
			return armappcontainers.ContainerAppsClientGetResponse{ContainerApp: built}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armappcontainers.ContainerAppsClientBeginDeleteOptions) (*runtime.Poller[armappcontainers.ContainerAppsClientDeleteResponse], error) {
			return newInProgressPoller[armappcontainers.ContainerAppsClientDeleteResponse](), nil
		},
		newListByRGPagerFn: func(_ string, _ *armappcontainers.ContainerAppsClientListByResourceGroupOptions) *runtime.Pager[armappcontainers.ContainerAppsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappcontainers.ContainerAppsClientListByResourceGroupResponse]{
				More: func(_ armappcontainers.ContainerAppsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappcontainers.ContainerAppsClientListByResourceGroupResponse) (armappcontainers.ContainerAppsClientListByResourceGroupResponse, error) {
					return armappcontainers.ContainerAppsClientListByResourceGroupResponse{
						ContainerAppCollection: armappcontainers.ContainerAppCollection{
							Value: []*armappcontainers.ContainerApp{{ID: to.Ptr(testCANativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubPagerFn: func(_ *armappcontainers.ContainerAppsClientListBySubscriptionOptions) *runtime.Pager[armappcontainers.ContainerAppsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappcontainers.ContainerAppsClientListBySubscriptionResponse]{
				More: func(_ armappcontainers.ContainerAppsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappcontainers.ContainerAppsClientListBySubscriptionResponse) (armappcontainers.ContainerAppsClientListBySubscriptionResponse, error) {
					return armappcontainers.ContainerAppsClientListBySubscriptionResponse{
						ContainerAppCollection: armappcontainers.ContainerAppCollection{
							Value: []*armappcontainers.ContainerApp{{ID: to.Ptr(testCANativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestContainerApp(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCAProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCANativeID, got.ProgressResult.NativeID)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "app-1", props["name"])
		require.Equal(t, testCAEnvID, props["managedEnvironmentId"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCANativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "app-1", props["name"])
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testCANativeID, DesiredProperties: createCAProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCANativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armappcontainers.ContainerAppsClientBeginDeleteOptions) (*runtime.Poller[armappcontainers.ContainerAppsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCANativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"}})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)

		gotAll, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: map[string]string{}})
		require.NoError(t, err)
		require.Len(t, gotAll.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armappcontainers.ContainerApp, _ *armappcontainers.ContainerAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappcontainers.ContainerAppsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCAProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestContainerApp(api containerAppsAPI) *ContainerApp {
	return &ContainerApp{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeContainerAppsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, appName string, envelope armappcontainers.ContainerApp, opts *armappcontainers.ContainerAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappcontainers.ContainerAppsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, appName string, opts *armappcontainers.ContainerAppsClientGetOptions) (armappcontainers.ContainerAppsClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, appName string, opts *armappcontainers.ContainerAppsClientBeginDeleteOptions) (*runtime.Poller[armappcontainers.ContainerAppsClientDeleteResponse], error)
	newListByRGPagerFn    func(rgName string, opts *armappcontainers.ContainerAppsClientListByResourceGroupOptions) *runtime.Pager[armappcontainers.ContainerAppsClientListByResourceGroupResponse]
	newListBySubPagerFn   func(opts *armappcontainers.ContainerAppsClientListBySubscriptionOptions) *runtime.Pager[armappcontainers.ContainerAppsClientListBySubscriptionResponse]
}

func (f *fakeContainerAppsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, appName string, envelope armappcontainers.ContainerApp, opts *armappcontainers.ContainerAppsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappcontainers.ContainerAppsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, appName, envelope, opts)
}

func (f *fakeContainerAppsAPI) Get(ctx context.Context, rgName, appName string, opts *armappcontainers.ContainerAppsClientGetOptions) (armappcontainers.ContainerAppsClientGetResponse, error) {
	return f.getFn(ctx, rgName, appName, opts)
}

func (f *fakeContainerAppsAPI) BeginDelete(ctx context.Context, rgName, appName string, opts *armappcontainers.ContainerAppsClientBeginDeleteOptions) (*runtime.Poller[armappcontainers.ContainerAppsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, appName, opts)
}

func (f *fakeContainerAppsAPI) NewListByResourceGroupPager(rgName string, opts *armappcontainers.ContainerAppsClientListByResourceGroupOptions) *runtime.Pager[armappcontainers.ContainerAppsClientListByResourceGroupResponse] {
	return f.newListByRGPagerFn(rgName, opts)
}

func (f *fakeContainerAppsAPI) NewListBySubscriptionPager(opts *armappcontainers.ContainerAppsClientListBySubscriptionOptions) *runtime.Pager[armappcontainers.ContainerAppsClientListBySubscriptionResponse] {
	return f.newListBySubPagerFn(opts)
}
