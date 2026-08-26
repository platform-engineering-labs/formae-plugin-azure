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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testSchemaGroupNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.EventHub/namespaces/ehns1/schemagroups/sg1"

type fakeSchemaRegistryAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, namespaceName, name string, params armeventhub.SchemaGroup, options *armeventhub.SchemaRegistryClientCreateOrUpdateOptions) (armeventhub.SchemaRegistryClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, namespaceName, name string, options *armeventhub.SchemaRegistryClientGetOptions) (armeventhub.SchemaRegistryClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, namespaceName, name string, options *armeventhub.SchemaRegistryClientDeleteOptions) (armeventhub.SchemaRegistryClientDeleteResponse, error)
	listPagerFn      func(rgName, namespaceName string, options *armeventhub.SchemaRegistryClientListByNamespaceOptions) *runtime.Pager[armeventhub.SchemaRegistryClientListByNamespaceResponse]
}

func (f *fakeSchemaRegistryAPI) CreateOrUpdate(ctx context.Context, rgName, namespaceName, name string, params armeventhub.SchemaGroup, options *armeventhub.SchemaRegistryClientCreateOrUpdateOptions) (armeventhub.SchemaRegistryClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, namespaceName, name, params, options)
}

func (f *fakeSchemaRegistryAPI) Get(ctx context.Context, rgName, namespaceName, name string, options *armeventhub.SchemaRegistryClientGetOptions) (armeventhub.SchemaRegistryClientGetResponse, error) {
	return f.getFn(ctx, rgName, namespaceName, name, options)
}

func (f *fakeSchemaRegistryAPI) Delete(ctx context.Context, rgName, namespaceName, name string, options *armeventhub.SchemaRegistryClientDeleteOptions) (armeventhub.SchemaRegistryClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, namespaceName, name, options)
}

func (f *fakeSchemaRegistryAPI) NewListByNamespacePager(rgName, namespaceName string, options *armeventhub.SchemaRegistryClientListByNamespaceOptions) *runtime.Pager[armeventhub.SchemaRegistryClientListByNamespaceResponse] {
	return f.listPagerFn(rgName, namespaceName, options)
}

func newTestSchemaGroup(api eventHubSchemaGroupsAPI) *EventHubSchemaGroup {
	return &EventHubSchemaGroup{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func schemaGroupDesired(compatibility string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                "sg1",
		"resourceGroupName":   "rg-1",
		"namespaceName":       "ehns1",
		"schemaType":          "Avro",
		"schemaCompatibility": compatibility,
	})
	return out
}

func TestEventHubSchemaGroup_CRUD(t *testing.T) {
	stamped := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	groupResult := armeventhub.SchemaGroup{
		ID:   to.Ptr(testSchemaGroupNativeID),
		Name: to.Ptr("sg1"),
		// The group's location is the namespace's; it is not settable.
		Location: to.Ptr("East US"),
		Properties: &armeventhub.SchemaGroupProperties{
			SchemaType:          to.Ptr(armeventhub.SchemaTypeAvro),
			SchemaCompatibility: to.Ptr(armeventhub.SchemaCompatibilityBackward),
			// Free-form map the service echoes back, plus service state.
			GroupProperties: map[string]*string{"unmodelledKey": to.Ptr("unmodelled-value")},
			CreatedAtUTC:    to.Ptr(stamped),
			UpdatedAtUTC:    to.Ptr(stamped),
			ETag:            to.Ptr("etag-1"),
		},
	}

	var sent armeventhub.SchemaGroup
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeSchemaRegistryAPI{
		createOrUpdateFn: func(_ context.Context, rgName, namespaceName, name string, params armeventhub.SchemaGroup, _ *armeventhub.SchemaRegistryClientCreateOrUpdateOptions) (armeventhub.SchemaRegistryClientCreateOrUpdateResponse, error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ehns1", namespaceName)
			require.Equal(t, "sg1", name)
			sent = params
			writeCalls++
			return armeventhub.SchemaRegistryClientCreateOrUpdateResponse{SchemaGroup: groupResult}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armeventhub.SchemaRegistryClientGetOptions) (armeventhub.SchemaRegistryClientGetResponse, error) {
			return armeventhub.SchemaRegistryClientGetResponse{SchemaGroup: groupResult}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ *armeventhub.SchemaRegistryClientDeleteOptions) (armeventhub.SchemaRegistryClientDeleteResponse, error) {
			deleteCalls++
			return armeventhub.SchemaRegistryClientDeleteResponse{}, nil
		},
		listPagerFn: func(_, _ string, _ *armeventhub.SchemaRegistryClientListByNamespaceOptions) *runtime.Pager[armeventhub.SchemaRegistryClientListByNamespaceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armeventhub.SchemaRegistryClientListByNamespaceResponse]{
				More: func(_ armeventhub.SchemaRegistryClientListByNamespaceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armeventhub.SchemaRegistryClientListByNamespaceResponse) (armeventhub.SchemaRegistryClientListByNamespaceResponse, error) {
					return armeventhub.SchemaRegistryClientListByNamespaceResponse{
						SchemaGroupListResult: armeventhub.SchemaGroupListResult{
							Value: []*armeventhub.SchemaGroup{
								{ID: to.Ptr(testSchemaGroupNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestSchemaGroup(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "sg1", Properties: schemaGroupDesired("Backward"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testSchemaGroupNativeID, got.ProgressResult.NativeID)

		require.Equal(t, armeventhub.SchemaTypeAvro, *sent.Properties.SchemaType)
		require.Equal(t, armeventhub.SchemaCompatibilityBackward, *sent.Properties.SchemaCompatibility)
		// Neither the free-form map nor a location is ours to send.
		require.Nil(t, sent.Properties.GroupProperties)
		require.Nil(t, sent.Location)
	})

	t.Run("Create_requires_schema_type", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sg1", "resourceGroupName": "rg-1", "namespaceName": "ehns1",
			"schemaCompatibility": "Backward",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "schemaType is required")
	})

	t.Run("Create_requires_compatibility", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "sg1", "resourceGroupName": "rg-1", "namespaceName": "ehns1",
			"schemaType": "Avro",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "schemaCompatibility is required")
	})

	t.Run("Create_requires_namespace", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "sg1", "resourceGroupName": "rg-1"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "namespaceName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSchemaGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "sg1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ehns1", props["namespaceName"])
		require.Equal(t, "Avro", props["schemaType"])
		require.Equal(t, "Backward", props["schemaCompatibility"])
	})

	// The location belongs to the namespace, and the rest is service state or an
	// unmodelled map — none may reach desired state.
	t.Run("Read_drops_unmodelled_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSchemaGroupNativeID})
		require.NoError(t, err)
		for _, key := range []string{
			"groupProperties", "unmodelledKey", "unmodelled-value",
			"createdAtUtc", "updatedAtUtc", "eTag", "location", "systemData",
		} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// CreateOrUpdate is the only write verb; only the compatibility rule is mutable.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testSchemaGroupNativeID,
			DesiredProperties: schemaGroupDesired("Forward"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, armeventhub.SchemaCompatibilityForward, *sent.Properties.SchemaCompatibility)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSchemaGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ *armeventhub.SchemaRegistryClientDeleteOptions) (armeventhub.SchemaRegistryClientDeleteResponse, error) {
			return armeventhub.SchemaRegistryClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testSchemaGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "namespaceName": "ehns1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testSchemaGroupNativeID}, got.NativeIDs)
	})

	t.Run("List_without_namespace_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armeventhub.SchemaRegistryClientGetOptions) (armeventhub.SchemaRegistryClientGetResponse, error) {
			return armeventhub.SchemaRegistryClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testSchemaGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
