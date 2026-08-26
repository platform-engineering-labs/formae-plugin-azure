// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testContainerGroupNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerInstance/containerGroups/cg-1"

func newTestContainerGroup(api containerGroupsAPI) *ContainerGroup {
	return &ContainerGroup{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func containerGroupDesired(image string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":              "cg-1",
		"location":          "eastus",
		"resourceGroupName": "rg-1",
		"osType":            "Linux",
		"restartPolicy":     "Never",
		"containers": []map[string]any{{
			"name":      "hello",
			"image":     image,
			"resources": map[string]any{"cpu": 0.5, "memoryInGB": 0.5},
			"ports":     []map[string]any{{"port": 80}},
			"command":   []string{"/bin/sh", "-c", "echo hi"},
			"environmentVariables": []map[string]any{
				{"name": "GREETING", "value": "hello"},
			},
		}},
		"ipAddress": map[string]any{
			"type":  "Public",
			"ports": []map[string]any{{"port": 80, "protocol": "TCP"}},
		},
	})
	return out
}

func TestContainerGroup_CRUD(t *testing.T) {
	cgResult := armcontainerinstance.ContainerGroup{
		ID:       to.Ptr(testContainerGroupNativeID),
		Name:     to.Ptr("cg-1"),
		Location: to.Ptr("East US"),
		Properties: &armcontainerinstance.ContainerGroupPropertiesProperties{
			OSType:        to.Ptr(armcontainerinstance.OperatingSystemTypesLinux),
			RestartPolicy: to.Ptr(armcontainerinstance.ContainerGroupRestartPolicyNever),
			Containers: []*armcontainerinstance.Container{{
				Name: to.Ptr("hello"),
				Properties: &armcontainerinstance.ContainerProperties{
					Image: to.Ptr("mcr.microsoft.com/hello-world:latest"),
					Resources: &armcontainerinstance.ResourceRequirements{
						Requests: &armcontainerinstance.ResourceRequests{
							CPU:        to.Ptr(0.5),
							MemoryInGB: to.Ptr(0.5),
						},
					},
					Ports: []*armcontainerinstance.ContainerPort{
						{Port: to.Ptr(int32(80)), Protocol: to.Ptr(armcontainerinstance.ContainerNetworkProtocolTCP)},
					},
					Command: []*string{to.Ptr("/bin/sh"), to.Ptr("-c"), to.Ptr("echo hi")},
					EnvironmentVariables: []*armcontainerinstance.EnvironmentVariable{
						{Name: to.Ptr("GREETING"), Value: to.Ptr("hello")},
						// A secureValue variable: ARM returns the name but never the
						// value, so it must not become desired state.
						{Name: to.Ptr("API_TOKEN")},
					},
				},
			}},
			IPAddress: &armcontainerinstance.IPAddress{
				Type:  to.Ptr(armcontainerinstance.ContainerGroupIPAddressTypePublic),
				Ports: []*armcontainerinstance.Port{{Port: to.Ptr(int32(80)), Protocol: to.Ptr(armcontainerinstance.ContainerGroupNetworkProtocolTCP)}},
				Fqdn:  to.Ptr("cg-1.eastus.azurecontainer.io"),
			},
		},
	}

	var sent armcontainerinstance.ContainerGroup
	var sentPatch armcontainerinstance.Resource
	putCalls := 0
	fake := &fakeContainerGroupsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, name string, params armcontainerinstance.ContainerGroup, _ *armcontainerinstance.ContainerGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientCreateOrUpdateResponse], error) {
			require.Equal(t, "cg-1", name)
			putCalls++
			sent = params
			return newDonePoller(armcontainerinstance.ContainerGroupsClientCreateOrUpdateResponse{ContainerGroup: cgResult}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcontainerinstance.ContainerGroupsClientGetOptions) (armcontainerinstance.ContainerGroupsClientGetResponse, error) {
			return armcontainerinstance.ContainerGroupsClientGetResponse{ContainerGroup: cgResult}, nil
		},
		updateFn: func(_ context.Context, _, _ string, res armcontainerinstance.Resource, _ *armcontainerinstance.ContainerGroupsClientUpdateOptions) (armcontainerinstance.ContainerGroupsClientUpdateResponse, error) {
			sentPatch = res
			return armcontainerinstance.ContainerGroupsClientUpdateResponse{}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armcontainerinstance.ContainerGroupsClientBeginDeleteOptions) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientDeleteResponse], error) {
			return newDonePoller(armcontainerinstance.ContainerGroupsClientDeleteResponse{}), nil
		},
		newListPagerFn: func(_ *armcontainerinstance.ContainerGroupsClientListOptions) *runtime.Pager[armcontainerinstance.ContainerGroupsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcontainerinstance.ContainerGroupsClientListResponse]{
				More: func(_ armcontainerinstance.ContainerGroupsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcontainerinstance.ContainerGroupsClientListResponse) (armcontainerinstance.ContainerGroupsClientListResponse, error) {
					return armcontainerinstance.ContainerGroupsClientListResponse{
						ContainerGroupListResult: armcontainerinstance.ContainerGroupListResult{
							Value: []*armcontainerinstance.ContainerGroup{
								{ID: to.Ptr(testContainerGroupNativeID)},
								{ID: to.Ptr("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.ContainerInstance/containerGroups/cg-2")},
							},
						},
					}, nil
				},
			})
		},
		newListByResourceGroupPagerFn: func(_ string, _ *armcontainerinstance.ContainerGroupsClientListByResourceGroupOptions) *runtime.Pager[armcontainerinstance.ContainerGroupsClientListByResourceGroupResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcontainerinstance.ContainerGroupsClientListByResourceGroupResponse]{
				More: func(_ armcontainerinstance.ContainerGroupsClientListByResourceGroupResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcontainerinstance.ContainerGroupsClientListByResourceGroupResponse) (armcontainerinstance.ContainerGroupsClientListByResourceGroupResponse, error) {
					return armcontainerinstance.ContainerGroupsClientListByResourceGroupResponse{
						ContainerGroupListResult: armcontainerinstance.ContainerGroupListResult{
							Value: []*armcontainerinstance.ContainerGroup{{ID: to.Ptr(testContainerGroupNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestContainerGroup(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "cg-1", Properties: containerGroupDesired("mcr.microsoft.com/hello-world:latest")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testContainerGroupNativeID, got.ProgressResult.NativeID)

		require.Len(t, sent.Properties.Containers, 1)
		ctr := sent.Properties.Containers[0]
		require.Equal(t, "hello", *ctr.Name)
		require.Equal(t, 0.5, *ctr.Properties.Resources.Requests.CPU)
		require.Equal(t, 0.5, *ctr.Properties.Resources.Requests.MemoryInGB)
		// Command entries go out as separate argv elements, not one shell string.
		require.Len(t, ctr.Properties.Command, 3)
		require.Equal(t, "/bin/sh", *ctr.Properties.Command[0])
		// Port protocol defaults to TCP when omitted.
		require.Equal(t, armcontainerinstance.ContainerNetworkProtocolTCP, *ctr.Properties.Ports[0].Protocol)
		require.Equal(t, armcontainerinstance.ContainerGroupIPAddressTypePublic, *sent.Properties.IPAddress.Type)
	})

	t.Run("Create_requires_a_container", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "cg-1", "location": "eastus", "resourceGroupName": "rg-1", "osType": "Linux",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "at least one container")
	})

	t.Run("Create_requires_osType", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "cg-1", "location": "eastus", "resourceGroupName": "rg-1",
			"containers": []map[string]any{{"name": "c", "image": "i", "resources": map[string]any{"cpu": 1, "memoryInGB": 1}}},
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "osType is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testContainerGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "cg-1", props["name"])
		require.Equal(t, "eastus", props["location"])
		require.Equal(t, "Linux", props["osType"])
		require.Equal(t, "Never", props["restartPolicy"])
		require.Equal(t, "cg-1.eastus.azurecontainer.io", props["fqdn"])

		containers := props["containers"].([]any)
		require.Len(t, containers, 1)
		ctr := containers[0].(map[string]any)
		require.Equal(t, "hello", ctr["name"])
		res := ctr["resources"].(map[string]any)
		require.EqualValues(t, 0.5, res["cpu"])

		// Only the plain env var round-trips; the secureValue one has no value and
		// would otherwise drift on every reconcile.
		envs := ctr["environmentVariables"].([]any)
		require.Len(t, envs, 1)
		require.Equal(t, "GREETING", envs[0].(map[string]any)["name"])
	})

	// ACI's PUT drops tags, so Update must go through the tags-only PATCH.
	t.Run("Update_uses_tags_patch_not_put", func(t *testing.T) {
		putsBefore := putCalls
		props, _ := json.Marshal(map[string]any{
			"name": "cg-1", "location": "eastus", "resourceGroupName": "rg-1", "osType": "Linux",
			"containers": []map[string]any{{
				"name": "hello", "image": "img",
				"resources": map[string]any{"cpu": 0.5, "memoryInGB": 0.5},
			}},
			"Tags": []map[string]string{{"Key": "Environment", "Value": "updated"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testContainerGroupNativeID, DesiredProperties: props,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testContainerGroupNativeID, got.ProgressResult.NativeID)
		require.Equal(t, putsBefore, putCalls, "Update must not issue a CreateOrUpdate PUT")
		require.Equal(t, "updated", *sentPatch.Tags["Environment"])
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testContainerGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armcontainerinstance.ContainerGroupsClientBeginDeleteOptions) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testContainerGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_resource_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testContainerGroupNativeID}, got.NativeIDs)
	})

	t.Run("List_without_group_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armcontainerinstance.ContainerGroup, _ *armcontainerinstance.ContainerGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "cg-1", Properties: containerGroupDesired("bad-image")})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// ACI's LRO terminal body omits tags. Serializing that body straight through
// reports a tagless group right after a tag update, which failed conformance
// [Update] with "Property Tags should exist in actual resource (after update)".
// The completion path must re-read instead.
func TestContainerGroup_CreateCompletionRereadsAfterLRO(t *testing.T) {
	tagless := armcontainerinstance.ContainerGroup{
		ID:       to.Ptr(testContainerGroupNativeID),
		Name:     to.Ptr("cg-1"),
		Location: to.Ptr("eastus"),
		// No Tags: this is what the poller hands back.
	}
	tagged := tagless
	tagged.Tags = map[string]*string{"Environment": to.Ptr("updated")}

	getCalls := 0
	fake := &fakeContainerGroupsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armcontainerinstance.ContainerGroup, _ *armcontainerinstance.ContainerGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientCreateOrUpdateResponse], error) {
			return newDonePoller(armcontainerinstance.ContainerGroupsClientCreateOrUpdateResponse{ContainerGroup: tagless}), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armcontainerinstance.ContainerGroupsClientGetOptions) (armcontainerinstance.ContainerGroupsClientGetResponse, error) {
			getCalls++
			return armcontainerinstance.ContainerGroupsClientGetResponse{ContainerGroup: tagged}, nil
		},
	}
	prov := newTestContainerGroup(fake)

	props, _ := json.Marshal(map[string]any{
		"name": "cg-1", "location": "eastus", "resourceGroupName": "rg-1", "osType": "Linux",
		"containers": []map[string]any{{
			"name": "hello", "image": "img",
			"resources": map[string]any{"cpu": 0.5, "memoryInGB": 0.5},
		}},
		"Tags": []map[string]string{{"Key": "Environment", "Value": "updated"}},
	})
	got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "cg-1", Properties: props})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	require.Positive(t, getCalls, "completion must re-read rather than trust the poller body")

	var serialized map[string]any
	require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
	require.Contains(t, serialized, "Tags")
}

func TestContainerGroup_ReadNotFound(t *testing.T) {
	fake := &fakeContainerGroupsAPI{
		getFn: func(_ context.Context, _, _ string, _ *armcontainerinstance.ContainerGroupsClientGetOptions) (armcontainerinstance.ContainerGroupsClientGetResponse, error) {
			return armcontainerinstance.ContainerGroupsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestContainerGroup(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testContainerGroupNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

// --- Test helpers ---

type fakeContainerGroupsAPI struct {
	beginCreateOrUpdateFn         func(ctx context.Context, rgName, name string, cg armcontainerinstance.ContainerGroup, options *armcontainerinstance.ContainerGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientCreateOrUpdateResponse], error)
	getFn                         func(ctx context.Context, rgName, name string, options *armcontainerinstance.ContainerGroupsClientGetOptions) (armcontainerinstance.ContainerGroupsClientGetResponse, error)
	updateFn                      func(ctx context.Context, rgName, name string, res armcontainerinstance.Resource, options *armcontainerinstance.ContainerGroupsClientUpdateOptions) (armcontainerinstance.ContainerGroupsClientUpdateResponse, error)
	beginDeleteFn                 func(ctx context.Context, rgName, name string, options *armcontainerinstance.ContainerGroupsClientBeginDeleteOptions) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientDeleteResponse], error)
	newListPagerFn                func(options *armcontainerinstance.ContainerGroupsClientListOptions) *runtime.Pager[armcontainerinstance.ContainerGroupsClientListResponse]
	newListByResourceGroupPagerFn func(rgName string, options *armcontainerinstance.ContainerGroupsClientListByResourceGroupOptions) *runtime.Pager[armcontainerinstance.ContainerGroupsClientListByResourceGroupResponse]
}

func (f *fakeContainerGroupsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, name string, cg armcontainerinstance.ContainerGroup, options *armcontainerinstance.ContainerGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, name, cg, options)
}

func (f *fakeContainerGroupsAPI) Get(ctx context.Context, rgName, name string, options *armcontainerinstance.ContainerGroupsClientGetOptions) (armcontainerinstance.ContainerGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, name, options)
}

func (f *fakeContainerGroupsAPI) Update(ctx context.Context, rgName, name string, res armcontainerinstance.Resource, options *armcontainerinstance.ContainerGroupsClientUpdateOptions) (armcontainerinstance.ContainerGroupsClientUpdateResponse, error) {
	return f.updateFn(ctx, rgName, name, res, options)
}

func (f *fakeContainerGroupsAPI) BeginDelete(ctx context.Context, rgName, name string, options *armcontainerinstance.ContainerGroupsClientBeginDeleteOptions) (*runtime.Poller[armcontainerinstance.ContainerGroupsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, name, options)
}

func (f *fakeContainerGroupsAPI) NewListPager(options *armcontainerinstance.ContainerGroupsClientListOptions) *runtime.Pager[armcontainerinstance.ContainerGroupsClientListResponse] {
	return f.newListPagerFn(options)
}

func (f *fakeContainerGroupsAPI) NewListByResourceGroupPager(rgName string, options *armcontainerinstance.ContainerGroupsClientListByResourceGroupOptions) *runtime.Pager[armcontainerinstance.ContainerGroupsClientListByResourceGroupResponse] {
	return f.newListByResourceGroupPagerFn(rgName, options)
}
