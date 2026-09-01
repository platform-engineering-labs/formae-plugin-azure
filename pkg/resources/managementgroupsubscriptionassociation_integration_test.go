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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testAssociatedSubscriptionID = "00000000-0000-0000-0000-000000000001"
	testAssociationNativeID      = testManagementGroupNativeID + "/subscriptions/" + testAssociatedSubscriptionID
)

type fakeManagementGroupSubscriptionsAPI struct {
	createFn func(ctx context.Context, groupID, subscriptionID string, options *armmanagementgroups.ManagementGroupSubscriptionsClientCreateOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientCreateResponse, error)
	getFn    func(ctx context.Context, groupID, subscriptionID string, options *armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionResponse, error)
	deleteFn func(ctx context.Context, groupID, subscriptionID string, options *armmanagementgroups.ManagementGroupSubscriptionsClientDeleteOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientDeleteResponse, error)

	sentGroupID        string
	sentSubscriptionID string
	listedGroupID      string
}

func (f *fakeManagementGroupSubscriptionsAPI) Create(ctx context.Context, groupID, subscriptionID string, options *armmanagementgroups.ManagementGroupSubscriptionsClientCreateOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientCreateResponse, error) {
	f.sentGroupID, f.sentSubscriptionID = groupID, subscriptionID
	return f.createFn(ctx, groupID, subscriptionID, options)
}

func (f *fakeManagementGroupSubscriptionsAPI) GetSubscription(ctx context.Context, groupID, subscriptionID string, options *armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionResponse, error) {
	f.sentGroupID, f.sentSubscriptionID = groupID, subscriptionID
	return f.getFn(ctx, groupID, subscriptionID, options)
}

func (f *fakeManagementGroupSubscriptionsAPI) Delete(ctx context.Context, groupID, subscriptionID string, options *armmanagementgroups.ManagementGroupSubscriptionsClientDeleteOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientDeleteResponse, error) {
	f.sentGroupID, f.sentSubscriptionID = groupID, subscriptionID
	return f.deleteFn(ctx, groupID, subscriptionID, options)
}

func (f *fakeManagementGroupSubscriptionsAPI) NewGetSubscriptionsUnderManagementGroupPager(groupID string, _ *armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionsUnderManagementGroupOptions) *runtime.Pager[armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionsUnderManagementGroupResponse] {
	f.listedGroupID = groupID
	return runtime.NewPager(runtime.PagingHandler[armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionsUnderManagementGroupResponse]{
		More: func(_ armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionsUnderManagementGroupResponse) bool {
			return false
		},
		Fetcher: func(_ context.Context, _ *armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionsUnderManagementGroupResponse) (armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionsUnderManagementGroupResponse, error) {
			return armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionsUnderManagementGroupResponse{
				ListSubscriptionUnderManagementGroup: armmanagementgroups.ListSubscriptionUnderManagementGroup{
					Value: []*armmanagementgroups.SubscriptionUnderManagementGroup{
						{ID: to.Ptr(testAssociationNativeID)},
						// A nil entry must not panic the walk.
						nil,
					},
				},
			}, nil
		},
	})
}

func associationResult() armmanagementgroups.SubscriptionUnderManagementGroup {
	return armmanagementgroups.SubscriptionUnderManagementGroup{
		ID:   to.Ptr(testAssociationNativeID),
		Name: to.Ptr(testAssociatedSubscriptionID),
		Type: to.Ptr("Microsoft.Management/managementGroups/subscriptions"),
		Properties: &armmanagementgroups.SubscriptionUnderManagementGroupProperties{
			DisplayName: to.Ptr("conformance test subscription"),
			// The service's own view.
			State:  to.Ptr("Active"),
			Tenant: to.Ptr("tenant-1"),
			Parent: &armmanagementgroups.DescendantParentGroupInfo{ID: to.Ptr(testManagementGroupNativeID)},
		},
	}
}

func newAssociationFake() *fakeManagementGroupSubscriptionsAPI {
	result := associationResult()
	return &fakeManagementGroupSubscriptionsAPI{
		createFn: func(_ context.Context, _, _ string, _ *armmanagementgroups.ManagementGroupSubscriptionsClientCreateOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientCreateResponse, error) {
			return armmanagementgroups.ManagementGroupSubscriptionsClientCreateResponse{SubscriptionUnderManagementGroup: result}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionResponse, error) {
			return armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionResponse{SubscriptionUnderManagementGroup: result}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armmanagementgroups.ManagementGroupSubscriptionsClientDeleteOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientDeleteResponse, error) {
			return armmanagementgroups.ManagementGroupSubscriptionsClientDeleteResponse{}, nil
		},
	}
}

func newTestManagementGroupSubscriptionAssociation(api managementGroupSubscriptionsAPI) *ManagementGroupSubscriptionAssociation {
	return &ManagementGroupSubscriptionAssociation{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func associationDesired(subscriptionID string) []byte {
	out, _ := json.Marshal(map[string]any{
		"managementGroupId": testManagementGroupNativeID,
		"subscriptionId":    subscriptionID,
	})
	return out
}

func TestManagementGroupSubscriptionAssociation_CRUD(t *testing.T) {
	fake := newAssociationFake()
	prov := newTestManagementGroupSubscriptionAssociation(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "assoc", Properties: associationDesired(testAssociatedSubscriptionID),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAssociationNativeID, got.ProgressResult.NativeID)

		// The API takes the group ID and the bare subscription GUID, not the two
		// fully qualified IDs the schema carries.
		require.Equal(t, testManagementGroupName, fake.sentGroupID)
		require.Equal(t, testAssociatedSubscriptionID, fake.sentSubscriptionID)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, testManagementGroupNativeID, props["managementGroupId"])
		require.Equal(t, testAssociatedSubscriptionID, props["subscriptionId"])
		require.Equal(t, "conformance test subscription", props["displayName"])
	})

	// A resolvable reference to a subscription yields the scope form; both spellings
	// have to reach the API as the bare GUID.
	t.Run("Create_accepts_a_subscription_scope_as_well_as_a_guid", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "assoc", Properties: associationDesired("/subscriptions/" + testAssociatedSubscriptionID),
		})
		require.NoError(t, err)
		require.Equal(t, testAssociatedSubscriptionID, fake.sentSubscriptionID)
		require.Equal(t, testAssociationNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Create_requires_both_ids", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"subscriptionId": testAssociatedSubscriptionID})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "managementGroupId is required")

		props, _ = json.Marshal(map[string]any{"managementGroupId": testManagementGroupNativeID})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "subscriptionId is required")
	})

	t.Run("Create_requires_a_fully_qualified_management_group_id", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"managementGroupId": testManagementGroupName,
			"subscriptionId":    testAssociatedSubscriptionID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "must be a fully qualified management group ID")
	})

	t.Run("Create_surfaces_the_provider_error", func(t *testing.T) {
		failing := newAssociationFake()
		failing.createFn = func(_ context.Context, _, _ string, _ *armmanagementgroups.ManagementGroupSubscriptionsClientCreateOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientCreateResponse, error) {
			return armmanagementgroups.ManagementGroupSubscriptionsClientCreateResponse{}, &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}
		}
		got, err := newTestManagementGroupSubscriptionAssociation(failing).Create(context.Background(), &resource.CreateRequest{
			Label: "assoc", Properties: associationDesired(testAssociatedSubscriptionID),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "AuthorizationFailed")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAssociationNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, testManagementGroupName, fake.sentGroupID)
		require.Equal(t, testAssociatedSubscriptionID, fake.sentSubscriptionID)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testManagementGroupNativeID, props["managementGroupId"])
		require.Equal(t, testAssociatedSubscriptionID, props["subscriptionId"])
		require.Equal(t, testAssociationNativeID, props["id"])
	})

	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAssociationNativeID})
		require.NoError(t, err)
		for _, key := range []string{"state", "tenant", "parent", "type"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("IDParts", func(t *testing.T) {
		groupID, subscriptionID, err := managementGroupSubscriptionAssociationIDParts(testAssociationNativeID)
		require.NoError(t, err)
		require.Equal(t, testManagementGroupNativeID, groupID)
		require.Equal(t, testAssociatedSubscriptionID, subscriptionID)

		// A bare management group ID is not an association.
		_, _, err = managementGroupSubscriptionAssociationIDParts(testManagementGroupNativeID)
		require.ErrorContains(t, err, "not a management group subscription association resource ID")

		// Neither is a plain subscription scope.
		_, _, err = managementGroupSubscriptionAssociationIDParts("/subscriptions/" + testAssociatedSubscriptionID)
		require.ErrorContains(t, err, "not a management group subscription association resource ID")
	})

	// Both fields are createOnly; there is no PATCH verb at all.
	t.Run("Update_is_refused", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testAssociationNativeID, DesiredProperties: associationDesired(testAssociatedSubscriptionID),
		})
		require.Error(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "immutable")
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAssociationNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testManagementGroupName, fake.sentGroupID)
		require.Equal(t, testAssociatedSubscriptionID, fake.sentSubscriptionID)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		gone := newAssociationFake()
		gone.deleteFn = func(_ context.Context, _, _ string, _ *armmanagementgroups.ManagementGroupSubscriptionsClientDeleteOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientDeleteResponse, error) {
			return armmanagementgroups.ManagementGroupSubscriptionsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := newTestManagementGroupSubscriptionAssociation(gone).Delete(context.Background(), &resource.DeleteRequest{NativeID: testAssociationNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_needs_a_management_group", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"managementGroupId": testManagementGroupNativeID},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAssociationNativeID}, got.NativeIDs)
		require.Equal(t, testManagementGroupName, fake.listedGroupID)
	})

	// There is no tenant-wide listing of associations, so without a parent there is
	// nothing to enumerate rather than an error.
	t.Run("List_without_a_management_group_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		missing := newAssociationFake()
		missing.getFn = func(_ context.Context, _, _ string, _ *armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionOptions) (armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionResponse, error) {
			return armmanagementgroups.ManagementGroupSubscriptionsClientGetSubscriptionResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := newTestManagementGroupSubscriptionAssociation(missing).Read(context.Background(), &resource.ReadRequest{NativeID: testAssociationNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
