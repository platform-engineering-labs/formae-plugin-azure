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

const testMENativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.App/managedEnvironments/env-1"

// consumptionMEProps is a consumption-only environment with NO log-analytics
// (no write-only sharedKey), matching the default conformance fixture.
func consumptionMEProps() map[string]any {
	return map[string]any{
		"resourceGroupName": "rg-1",
		"name":              "env-1",
		"location":          "eastus",
	}
}

// fullMEProps adds the optional appLogsConfiguration with a write-only sharedKey
// to prove the marshaller never serializes the secret back.
func fullMEProps() map[string]any {
	return map[string]any{
		"resourceGroupName": "rg-1",
		"name":              "env-1",
		"location":          "eastus",
		"zoneRedundant":     false,
		"appLogsConfiguration": map[string]any{
			"destination": "log-analytics",
			"logAnalyticsConfiguration": map[string]any{
				"customerId": "cust-123",
				"sharedKey":  "super-secret-shared-key",
			},
		},
	}
}

func createMEProps() json.RawMessage {
	props, _ := json.Marshal(consumptionMEProps())
	return props
}

// TestManagedEnvironment_MarshallerRoundTrip proves the build/serialize pair
// round-trips structural fields and that the write-only logAnalytics sharedKey
// is never serialized back into state (Azure never returns it -> false drift).
func TestManagedEnvironment_MarshallerRoundTrip(t *testing.T) {
	env := newTestManagedEnvironment(nil)

	var props map[string]any
	require.NoError(t, json.Unmarshal(mustJSON(t, fullMEProps()), &props))

	params, err := env.buildManagedEnvironmentParams(props, "eastus")
	require.NoError(t, err)
	params.ID = to.Ptr(testMENativeID)
	// Simulate read-only outputs Azure fills in.
	params.Properties.DefaultDomain = to.Ptr("env-1.eastus.azurecontainerapps.io")
	params.Properties.StaticIP = to.Ptr("20.1.2.3")

	raw, err := serializeManagedEnvironmentProperties(params, "rg-1", "env-1")
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))

	require.Equal(t, "env-1", got["name"])
	require.Equal(t, "eastus", got["location"])
	require.Equal(t, testMENativeID, got["id"])
	require.Equal(t, "env-1.eastus.azurecontainerapps.io", got["defaultDomain"])
	require.Equal(t, "20.1.2.3", got["staticIp"])

	alc := got["appLogsConfiguration"].(map[string]any)
	require.Equal(t, "log-analytics", alc["destination"])
	la := alc["logAnalyticsConfiguration"].(map[string]any)
	require.Equal(t, "cust-123", la["customerId"])
	require.Nil(t, la["sharedKey"], "log-analytics sharedKey must never surface in serialized state")
}

func TestManagedEnvironment_CRUD(t *testing.T) {
	var builtProps map[string]any
	require.NoError(t, json.Unmarshal(createMEProps(), &builtProps))
	built, err := newTestManagedEnvironment(nil).buildManagedEnvironmentParams(builtProps, "eastus")
	require.NoError(t, err)
	built.ID = to.Ptr(testMENativeID)
	built.Name = to.Ptr("env-1")
	built.Location = to.Ptr("eastus")

	doneResult := armappcontainers.ManagedEnvironmentsClientCreateOrUpdateResponse{ManagedEnvironment: built}

	fake := &fakeManagedEnvironmentsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armappcontainers.ManagedEnvironment, _ *armappcontainers.ManagedEnvironmentsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappcontainers.ManagedEnvironmentsClientCreateOrUpdateResponse], error) {
			return newDonePoller(doneResult), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armappcontainers.ManagedEnvironmentsClientGetOptions) (armappcontainers.ManagedEnvironmentsClientGetResponse, error) {
			return armappcontainers.ManagedEnvironmentsClientGetResponse{ManagedEnvironment: built}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armappcontainers.ManagedEnvironmentsClientBeginDeleteOptions) (*runtime.Poller[armappcontainers.ManagedEnvironmentsClientDeleteResponse], error) {
			return newInProgressPoller[armappcontainers.ManagedEnvironmentsClientDeleteResponse](), nil
		},
		newListByRGPagerFn: func(_ string, _ *armappcontainers.ManagedEnvironmentsClientListByResourceGroupOptions) *runtime.Pager[armappcontainers.ManagedEnvironmentsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappcontainers.ManagedEnvironmentsClientListByResourceGroupResponse]{
				More: func(_ armappcontainers.ManagedEnvironmentsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappcontainers.ManagedEnvironmentsClientListByResourceGroupResponse) (armappcontainers.ManagedEnvironmentsClientListByResourceGroupResponse, error) {
					return armappcontainers.ManagedEnvironmentsClientListByResourceGroupResponse{
						ManagedEnvironmentsCollection: armappcontainers.ManagedEnvironmentsCollection{
							Value: []*armappcontainers.ManagedEnvironment{{ID: to.Ptr(testMENativeID)}},
						},
					}, nil
				},
			})
		},
		newListBySubPagerFn: func(_ *armappcontainers.ManagedEnvironmentsClientListBySubscriptionOptions) *runtime.Pager[armappcontainers.ManagedEnvironmentsClientListBySubscriptionResponse] {
			return runtime.NewPager(runtime.PagingHandler[armappcontainers.ManagedEnvironmentsClientListBySubscriptionResponse]{
				More: func(_ armappcontainers.ManagedEnvironmentsClientListBySubscriptionResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armappcontainers.ManagedEnvironmentsClientListBySubscriptionResponse) (armappcontainers.ManagedEnvironmentsClientListBySubscriptionResponse, error) {
					return armappcontainers.ManagedEnvironmentsClientListBySubscriptionResponse{
						ManagedEnvironmentsCollection: armappcontainers.ManagedEnvironmentsCollection{
							Value: []*armappcontainers.ManagedEnvironment{{ID: to.Ptr(testMENativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestManagedEnvironment(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createMEProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testMENativeID, got.ProgressResult.NativeID)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "env-1", props["name"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testMENativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "env-1", props["name"])
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testMENativeID, DesiredProperties: createMEProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMENativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armappcontainers.ManagedEnvironmentsClientBeginDeleteOptions) (*runtime.Poller[armappcontainers.ManagedEnvironmentsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testMENativeID})
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
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armappcontainers.ManagedEnvironment, _ *armappcontainers.ManagedEnvironmentsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappcontainers.ManagedEnvironmentsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createMEProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func newTestManagedEnvironment(api managedEnvironmentsAPI) *ManagedEnvironment {
	return &ManagedEnvironment{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeManagedEnvironmentsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, envName string, envelope armappcontainers.ManagedEnvironment, opts *armappcontainers.ManagedEnvironmentsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappcontainers.ManagedEnvironmentsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, envName string, opts *armappcontainers.ManagedEnvironmentsClientGetOptions) (armappcontainers.ManagedEnvironmentsClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, envName string, opts *armappcontainers.ManagedEnvironmentsClientBeginDeleteOptions) (*runtime.Poller[armappcontainers.ManagedEnvironmentsClientDeleteResponse], error)
	newListByRGPagerFn    func(rgName string, opts *armappcontainers.ManagedEnvironmentsClientListByResourceGroupOptions) *runtime.Pager[armappcontainers.ManagedEnvironmentsClientListByResourceGroupResponse]
	newListBySubPagerFn   func(opts *armappcontainers.ManagedEnvironmentsClientListBySubscriptionOptions) *runtime.Pager[armappcontainers.ManagedEnvironmentsClientListBySubscriptionResponse]
}

func (f *fakeManagedEnvironmentsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, envName string, envelope armappcontainers.ManagedEnvironment, opts *armappcontainers.ManagedEnvironmentsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappcontainers.ManagedEnvironmentsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, envName, envelope, opts)
}

func (f *fakeManagedEnvironmentsAPI) Get(ctx context.Context, rgName, envName string, opts *armappcontainers.ManagedEnvironmentsClientGetOptions) (armappcontainers.ManagedEnvironmentsClientGetResponse, error) {
	return f.getFn(ctx, rgName, envName, opts)
}

func (f *fakeManagedEnvironmentsAPI) BeginDelete(ctx context.Context, rgName, envName string, opts *armappcontainers.ManagedEnvironmentsClientBeginDeleteOptions) (*runtime.Poller[armappcontainers.ManagedEnvironmentsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, envName, opts)
}

func (f *fakeManagedEnvironmentsAPI) NewListByResourceGroupPager(rgName string, opts *armappcontainers.ManagedEnvironmentsClientListByResourceGroupOptions) *runtime.Pager[armappcontainers.ManagedEnvironmentsClientListByResourceGroupResponse] {
	return f.newListByRGPagerFn(rgName, opts)
}

func (f *fakeManagedEnvironmentsAPI) NewListBySubscriptionPager(opts *armappcontainers.ManagedEnvironmentsClientListBySubscriptionOptions) *runtime.Pager[armappcontainers.ManagedEnvironmentsClientListBySubscriptionResponse] {
	return f.newListBySubPagerFn(opts)
}
