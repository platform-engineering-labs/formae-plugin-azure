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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testLockResourceGroupScope = "/subscriptions/sub-1/resourceGroups/rg-1"
	testLockResourceScope      = testLockResourceGroupScope + "/providers/Microsoft.Network/networkSecurityGroups/nsg-1"
	testLockNativeID           = testLockResourceScope + "/providers/Microsoft.Authorization/locks/lock-1"
)

// lockCall records the level-specific verb a call landed on, so the tests can
// assert that a scope is dispatched to the right one.
type lockCall struct {
	verb               string
	resourceGroupName  string
	providerNamespace  string
	parentResourcePath string
	resourceType       string
	resourceName       string
	lockName           string
	parameters         armlocks.ManagementLockObject
}

type fakeManagementLocksAPI struct {
	calls []lockCall

	putErr    error
	getErr    error
	deleteErr error
	getResult armlocks.ManagementLockObject

	// getErrsByCall lets a test script a different Get outcome per call, which is
	// how the delete read-back is exercised.
	getErrs []error
}

func (f *fakeManagementLocksAPI) record(call lockCall) {
	f.calls = append(f.calls, call)
}

func (f *fakeManagementLocksAPI) lastCall() lockCall {
	return f.calls[len(f.calls)-1]
}

func (f *fakeManagementLocksAPI) nextGetErr() error {
	if len(f.getErrs) > 0 {
		err := f.getErrs[0]
		f.getErrs = f.getErrs[1:]
		return err
	}
	return f.getErr
}

func (f *fakeManagementLocksAPI) CreateOrUpdateAtSubscriptionLevel(_ context.Context, lockName string, parameters armlocks.ManagementLockObject, _ *armlocks.ManagementLocksClientCreateOrUpdateAtSubscriptionLevelOptions) (armlocks.ManagementLocksClientCreateOrUpdateAtSubscriptionLevelResponse, error) {
	f.record(lockCall{verb: "putSubscription", lockName: lockName, parameters: parameters})
	return armlocks.ManagementLocksClientCreateOrUpdateAtSubscriptionLevelResponse{ManagementLockObject: f.getResult}, f.putErr
}

func (f *fakeManagementLocksAPI) CreateOrUpdateAtResourceGroupLevel(_ context.Context, resourceGroupName, lockName string, parameters armlocks.ManagementLockObject, _ *armlocks.ManagementLocksClientCreateOrUpdateAtResourceGroupLevelOptions) (armlocks.ManagementLocksClientCreateOrUpdateAtResourceGroupLevelResponse, error) {
	f.record(lockCall{verb: "putResourceGroup", resourceGroupName: resourceGroupName, lockName: lockName, parameters: parameters})
	return armlocks.ManagementLocksClientCreateOrUpdateAtResourceGroupLevelResponse{ManagementLockObject: f.getResult}, f.putErr
}

func (f *fakeManagementLocksAPI) CreateOrUpdateAtResourceLevel(_ context.Context, resourceGroupName, resourceProviderNamespace, parentResourcePath, resourceType, resourceName, lockName string, parameters armlocks.ManagementLockObject, _ *armlocks.ManagementLocksClientCreateOrUpdateAtResourceLevelOptions) (armlocks.ManagementLocksClientCreateOrUpdateAtResourceLevelResponse, error) {
	f.record(lockCall{
		verb: "putResource", resourceGroupName: resourceGroupName, providerNamespace: resourceProviderNamespace,
		parentResourcePath: parentResourcePath, resourceType: resourceType, resourceName: resourceName,
		lockName: lockName, parameters: parameters,
	})
	return armlocks.ManagementLocksClientCreateOrUpdateAtResourceLevelResponse{ManagementLockObject: f.getResult}, f.putErr
}

func (f *fakeManagementLocksAPI) GetAtSubscriptionLevel(_ context.Context, lockName string, _ *armlocks.ManagementLocksClientGetAtSubscriptionLevelOptions) (armlocks.ManagementLocksClientGetAtSubscriptionLevelResponse, error) {
	f.record(lockCall{verb: "getSubscription", lockName: lockName})
	return armlocks.ManagementLocksClientGetAtSubscriptionLevelResponse{ManagementLockObject: f.getResult}, f.nextGetErr()
}

func (f *fakeManagementLocksAPI) GetAtResourceGroupLevel(_ context.Context, resourceGroupName, lockName string, _ *armlocks.ManagementLocksClientGetAtResourceGroupLevelOptions) (armlocks.ManagementLocksClientGetAtResourceGroupLevelResponse, error) {
	f.record(lockCall{verb: "getResourceGroup", resourceGroupName: resourceGroupName, lockName: lockName})
	return armlocks.ManagementLocksClientGetAtResourceGroupLevelResponse{ManagementLockObject: f.getResult}, f.nextGetErr()
}

func (f *fakeManagementLocksAPI) GetAtResourceLevel(_ context.Context, resourceGroupName, resourceProviderNamespace, parentResourcePath, resourceType, resourceName, lockName string, _ *armlocks.ManagementLocksClientGetAtResourceLevelOptions) (armlocks.ManagementLocksClientGetAtResourceLevelResponse, error) {
	f.record(lockCall{
		verb: "getResource", resourceGroupName: resourceGroupName, providerNamespace: resourceProviderNamespace,
		parentResourcePath: parentResourcePath, resourceType: resourceType, resourceName: resourceName, lockName: lockName,
	})
	return armlocks.ManagementLocksClientGetAtResourceLevelResponse{ManagementLockObject: f.getResult}, f.nextGetErr()
}

func (f *fakeManagementLocksAPI) DeleteAtSubscriptionLevel(_ context.Context, lockName string, _ *armlocks.ManagementLocksClientDeleteAtSubscriptionLevelOptions) (armlocks.ManagementLocksClientDeleteAtSubscriptionLevelResponse, error) {
	f.record(lockCall{verb: "deleteSubscription", lockName: lockName})
	return armlocks.ManagementLocksClientDeleteAtSubscriptionLevelResponse{}, f.deleteErr
}

func (f *fakeManagementLocksAPI) DeleteAtResourceGroupLevel(_ context.Context, resourceGroupName, lockName string, _ *armlocks.ManagementLocksClientDeleteAtResourceGroupLevelOptions) (armlocks.ManagementLocksClientDeleteAtResourceGroupLevelResponse, error) {
	f.record(lockCall{verb: "deleteResourceGroup", resourceGroupName: resourceGroupName, lockName: lockName})
	return armlocks.ManagementLocksClientDeleteAtResourceGroupLevelResponse{}, f.deleteErr
}

func (f *fakeManagementLocksAPI) DeleteAtResourceLevel(_ context.Context, resourceGroupName, resourceProviderNamespace, parentResourcePath, resourceType, resourceName, lockName string, _ *armlocks.ManagementLocksClientDeleteAtResourceLevelOptions) (armlocks.ManagementLocksClientDeleteAtResourceLevelResponse, error) {
	f.record(lockCall{
		verb: "deleteResource", resourceGroupName: resourceGroupName, providerNamespace: resourceProviderNamespace,
		parentResourcePath: parentResourcePath, resourceType: resourceType, resourceName: resourceName, lockName: lockName,
	})
	return armlocks.ManagementLocksClientDeleteAtResourceLevelResponse{}, f.deleteErr
}

func (f *fakeManagementLocksAPI) NewListAtSubscriptionLevelPager(_ *armlocks.ManagementLocksClientListAtSubscriptionLevelOptions) *runtime.Pager[armlocks.ManagementLocksClientListAtSubscriptionLevelResponse] {
	return runtime.NewPager(runtime.PagingHandler[armlocks.ManagementLocksClientListAtSubscriptionLevelResponse]{
		More: func(_ armlocks.ManagementLocksClientListAtSubscriptionLevelResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armlocks.ManagementLocksClientListAtSubscriptionLevelResponse) (armlocks.ManagementLocksClientListAtSubscriptionLevelResponse, error) {
			return armlocks.ManagementLocksClientListAtSubscriptionLevelResponse{
				ManagementLockListResult: armlocks.ManagementLockListResult{
					Value: []*armlocks.ManagementLockObject{
						{ID: to.Ptr(testLockNativeID)},
						{ID: to.Ptr(testLockResourceGroupScope + "/providers/Microsoft.Authorization/locks/lock-2")},
						// A nil entry must not panic the walk.
						nil,
					},
				},
			}, nil
		},
	})
}

func (f *fakeManagementLocksAPI) NewListAtResourceGroupLevelPager(resourceGroupName string, _ *armlocks.ManagementLocksClientListAtResourceGroupLevelOptions) *runtime.Pager[armlocks.ManagementLocksClientListAtResourceGroupLevelResponse] {
	f.record(lockCall{verb: "listResourceGroup", resourceGroupName: resourceGroupName})
	return runtime.NewPager(runtime.PagingHandler[armlocks.ManagementLocksClientListAtResourceGroupLevelResponse]{
		More: func(_ armlocks.ManagementLocksClientListAtResourceGroupLevelResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armlocks.ManagementLocksClientListAtResourceGroupLevelResponse) (armlocks.ManagementLocksClientListAtResourceGroupLevelResponse, error) {
			return armlocks.ManagementLocksClientListAtResourceGroupLevelResponse{
				ManagementLockListResult: armlocks.ManagementLockListResult{
					Value: []*armlocks.ManagementLockObject{{ID: to.Ptr(testLockResourceGroupScope + "/providers/Microsoft.Authorization/locks/lock-2")}},
				},
			}, nil
		},
	})
}

func (f *fakeManagementLocksAPI) NewListAtResourceLevelPager(resourceGroupName, resourceProviderNamespace, parentResourcePath, resourceType, resourceName string, _ *armlocks.ManagementLocksClientListAtResourceLevelOptions) *runtime.Pager[armlocks.ManagementLocksClientListAtResourceLevelResponse] {
	f.record(lockCall{
		verb: "listResource", resourceGroupName: resourceGroupName, providerNamespace: resourceProviderNamespace,
		parentResourcePath: parentResourcePath, resourceType: resourceType, resourceName: resourceName,
	})
	return runtime.NewPager(runtime.PagingHandler[armlocks.ManagementLocksClientListAtResourceLevelResponse]{
		More: func(_ armlocks.ManagementLocksClientListAtResourceLevelResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armlocks.ManagementLocksClientListAtResourceLevelResponse) (armlocks.ManagementLocksClientListAtResourceLevelResponse, error) {
			return armlocks.ManagementLocksClientListAtResourceLevelResponse{
				ManagementLockListResult: armlocks.ManagementLockListResult{
					Value: []*armlocks.ManagementLockObject{{ID: to.Ptr(testLockNativeID)}},
				},
			}, nil
		},
	})
}

func newTestManagementLock(api managementLocksAPI) *ManagementLock {
	return &ManagementLock{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func lockDesired(scope, level string, notes any) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":  "lock-1",
		"scope": scope,
		"level": level,
		"notes": notes,
	})
	return out
}

func newLockFake() *fakeManagementLocksAPI {
	return &fakeManagementLocksAPI{
		getResult: armlocks.ManagementLockObject{
			ID:   to.Ptr(testLockNativeID),
			Name: to.Ptr("lock-1"),
			Properties: &armlocks.ManagementLockProperties{
				Level: to.Ptr(armlocks.LockLevelCanNotDelete),
				Notes: to.Ptr("conformance test lock"),
				// Unmodelled: ARM accepts owners and never acts on them.
				Owners: []*armlocks.ManagementLockOwner{{ApplicationID: to.Ptr("app-1")}},
			},
			SystemData: &armlocks.SystemData{CreatedBy: to.Ptr("someone")},
		},
	}
}

func TestManagementLock_CRUD(t *testing.T) {
	fake := newLockFake()
	prov := newTestManagementLock(fake)

	t.Run("Create_at_resource_scope_dispatches_to_resource_level_verb", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "lock-1", Properties: lockDesired(testLockResourceScope, "CanNotDelete", "conformance test lock"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLockNativeID, got.ProgressResult.NativeID)

		call := fake.lastCall()
		require.Equal(t, "putResource", call.verb)
		require.Equal(t, "rg-1", call.resourceGroupName)
		require.Equal(t, "Microsoft.Network", call.providerNamespace)
		// A top-level resource has no parent path; ARM's URL template collapses the
		// resulting double slash.
		require.Equal(t, "", call.parentResourcePath)
		require.Equal(t, "networkSecurityGroups", call.resourceType)
		require.Equal(t, "nsg-1", call.resourceName)
		require.Equal(t, "lock-1", call.lockName)
		require.Equal(t, armlocks.LockLevelCanNotDelete, *call.parameters.Properties.Level)
		require.Equal(t, "conformance test lock", *call.parameters.Properties.Notes)
	})

	t.Run("Create_at_resource_group_scope_dispatches_to_group_level_verb", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "lock-1", Properties: lockDesired(testLockResourceGroupScope, "ReadOnly", nil),
		})
		require.NoError(t, err)

		call := fake.lastCall()
		require.Equal(t, "putResourceGroup", call.verb)
		require.Equal(t, "rg-1", call.resourceGroupName)
		require.Equal(t, armlocks.LockLevelReadOnly, *call.parameters.Properties.Level)
		// An unset note must not be sent as "".
		require.Nil(t, call.parameters.Properties.Notes)
	})

	t.Run("Create_at_subscription_scope_dispatches_to_subscription_level_verb", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "lock-1", Properties: lockDesired("/subscriptions/sub-1", "CanNotDelete", nil),
		})
		require.NoError(t, err)
		require.Equal(t, "putSubscription", fake.lastCall().verb)
	})

	// A nested resource puts everything above the leaf type into parentResourcePath,
	// which ARM interpolates raw.
	t.Run("Create_at_nested_resource_scope_splits_the_parent_path", func(t *testing.T) {
		nested := testLockResourceGroupScope + "/providers/Microsoft.Sql/servers/srv-1/databases/db-1"
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "lock-1", Properties: lockDesired(nested, "CanNotDelete", nil),
		})
		require.NoError(t, err)

		call := fake.lastCall()
		require.Equal(t, "putResource", call.verb)
		require.Equal(t, "Microsoft.Sql", call.providerNamespace)
		require.Equal(t, "servers/srv-1", call.parentResourcePath)
		require.Equal(t, "databases", call.resourceType)
		require.Equal(t, "db-1", call.resourceName)
	})

	t.Run("Create_requires_scope_and_level", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": "lock-1", "level": "CanNotDelete"})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "scope is required")

		props, _ = json.Marshal(map[string]any{"name": "lock-1", "scope": testLockResourceGroupScope})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "level is required")
	})

	// The level-specific verbs take the subscription from the client, so a scope
	// naming a different one would silently write to the bound subscription.
	t.Run("Create_rejects_a_scope_in_another_subscription", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "lock-1", Properties: lockDesired("/subscriptions/sub-2/resourceGroups/rg-1", "CanNotDelete", nil),
		})
		require.ErrorContains(t, err, "bound to sub-1")
	})

	t.Run("Create_rejects_a_management_group_scope", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "lock-1", Properties: lockDesired("/providers/Microsoft.Management/managementGroups/mg-1", "CanNotDelete", nil),
		})
		require.ErrorContains(t, err, "must name a subscription, a resource group or a resource")
	})

	t.Run("Create_surfaces_the_provider_error", func(t *testing.T) {
		fake.putErr = &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}
		defer func() { fake.putErr = nil }()

		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "lock-1", Properties: lockDesired(testLockResourceScope, "CanNotDelete", nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "AuthorizationFailed")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLockNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, "getResource", fake.lastCall().verb)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "lock-1", props["name"])
		require.Equal(t, testLockResourceScope, props["scope"])
		require.Equal(t, "CanNotDelete", props["level"])
		require.Equal(t, "conformance test lock", props["notes"])
		require.Equal(t, testLockNativeID, props["id"])
	})

	t.Run("Read_drops_unmodelled_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLockNativeID})
		require.NoError(t, err)
		for _, key := range []string{"owners", "applicationId", "systemData", "createdBy", "type"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// ARM answers a group-level lock PUT with a lower-case `resourcegroups`; the
	// scope must come back spelled the way desired state spells it.
	t.Run("Scope_casing_round_trips", func(t *testing.T) {
		props := managementLockProperties(&armlocks.ManagementLockObject{
			ID:         to.Ptr("/subscriptions/sub-1/resourcegroups/rg-1/providers/Microsoft.Authorization/locks/lock-1"),
			Properties: &armlocks.ManagementLockProperties{Level: to.Ptr(armlocks.LockLevelCanNotDelete)},
		}, testLockResourceGroupScope, "lock-1")
		require.Equal(t, testLockResourceGroupScope, props["scope"])
		require.Equal(t, testLockResourceGroupScope+"/providers/Microsoft.Authorization/locks/lock-1", props["id"])
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLockNativeID,
			DesiredProperties: lockDesired(testLockResourceScope, "ReadOnly", "revised note"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)

		call := fake.lastCall()
		require.Equal(t, "putResource", call.verb)
		require.Equal(t, armlocks.LockLevelReadOnly, *call.parameters.Properties.Level)
		require.Equal(t, "revised note", *call.parameters.Properties.Notes)
	})

	t.Run("IDParts", func(t *testing.T) {
		scope, name, err := managementLockIDParts(testLockNativeID)
		require.NoError(t, err)
		require.Equal(t, testLockResourceScope, scope)
		require.Equal(t, "lock-1", name)

		// Casing on the provider segment is ARM's to choose.
		scope, name, err = managementLockIDParts(testLockResourceGroupScope + "/providers/microsoft.authorization/locks/lock-2")
		require.NoError(t, err)
		require.Equal(t, testLockResourceGroupScope, scope)
		require.Equal(t, "lock-2", name)

		_, _, err = managementLockIDParts(testLockResourceGroupScope)
		require.ErrorContains(t, err, "not a management lock resource ID")
	})

	t.Run("List_without_scope_is_subscription_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 2)
	})

	t.Run("List_at_resource_group_scope", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"scope": testLockResourceGroupScope},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
		require.Equal(t, "listResourceGroup", fake.calls[len(fake.calls)-1].verb)
	})

	t.Run("List_at_resource_scope", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"scope": testLockResourceScope},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLockNativeID}, got.NativeIDs)
		require.Equal(t, "listResource", fake.calls[len(fake.calls)-1].verb)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})
}

// A lock that outlives its formae resource wedges everything under its scope, so
// Delete reads the lock back and only reports success once it is really gone.
func TestManagementLock_Delete(t *testing.T) {
	notFound := &azcore.ResponseError{StatusCode: 404}

	t.Run("reports_success_once_the_lock_is_gone", func(t *testing.T) {
		fake := newLockFake()
		fake.getErrs = []error{notFound}
		prov := newTestManagementLock(fake)

		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLockNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, "deleteResource", fake.calls[0].verb)
		require.Equal(t, "getResource", fake.calls[1].verb)
	})

	t.Run("tolerates_read_after_write_lag_before_the_lock_disappears", func(t *testing.T) {
		fake := newLockFake()
		// The first read-back still sees the lock; the second does not.
		fake.getErrs = []error{nil, notFound}
		prov := newTestManagementLock(fake)

		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLockNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// The whole point of the read-back: a DELETE that answered 200 while the lock is
	// still there must NOT be reported as success.
	t.Run("fails_when_the_lock_still_exists_after_delete", func(t *testing.T) {
		fake := newLockFake()
		prov := newTestManagementLock(fake)

		// Every read-back finds the lock still there. The context is already
		// cancelled so the bounded wait between attempts gives up at once rather
		// than sleeping through the full budget in a unit test — the point being
		// that neither path is allowed to report success.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		got, err := prov.Delete(ctx, &resource.DeleteRequest{NativeID: testLockNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, "deleteResource", fake.calls[0].verb)
		require.Equal(t, "getResource", fake.calls[1].verb)
		require.Contains(t, got.ProgressResult.StatusMessage, "still exists")
	})

	t.Run("a_delete_that_404s_is_still_confirmed", func(t *testing.T) {
		fake := newLockFake()
		fake.deleteErr = notFound
		fake.getErrs = []error{notFound}
		prov := newTestManagementLock(fake)

		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLockNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("surfaces_a_delete_error", func(t *testing.T) {
		fake := newLockFake()
		fake.deleteErr = &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}
		prov := newTestManagementLock(fake)

		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLockNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "AuthorizationFailed")
	})
}
