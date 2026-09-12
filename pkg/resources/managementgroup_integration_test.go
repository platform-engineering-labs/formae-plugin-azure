// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testManagementGroupName     = "mg-1"
	testManagementGroupNativeID = "/providers/Microsoft.Management/managementGroups/mg-1"
	testParentManagementGroupID = "/providers/Microsoft.Management/managementGroups/mg-parent"
)

type fakeManagementGroupsAPI struct {
	createFn func(ctx context.Context, groupID string, request armmanagementgroups.CreateManagementGroupRequest, options *armmanagementgroups.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armmanagementgroups.ClientCreateOrUpdateResponse], error)
	getFn    func(ctx context.Context, groupID string, options *armmanagementgroups.ClientGetOptions) (armmanagementgroups.ClientGetResponse, error)
	updateFn func(ctx context.Context, groupID string, patch armmanagementgroups.PatchManagementGroupRequest, options *armmanagementgroups.ClientUpdateOptions) (armmanagementgroups.ClientUpdateResponse, error)
	deleteFn func(ctx context.Context, groupID string, options *armmanagementgroups.ClientBeginDeleteOptions) (*runtime.Poller[armmanagementgroups.ClientDeleteResponse], error)
}

func (f *fakeManagementGroupsAPI) BeginCreateOrUpdate(ctx context.Context, groupID string, request armmanagementgroups.CreateManagementGroupRequest, options *armmanagementgroups.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armmanagementgroups.ClientCreateOrUpdateResponse], error) {
	return f.createFn(ctx, groupID, request, options)
}

func (f *fakeManagementGroupsAPI) Get(ctx context.Context, groupID string, options *armmanagementgroups.ClientGetOptions) (armmanagementgroups.ClientGetResponse, error) {
	return f.getFn(ctx, groupID, options)
}

func (f *fakeManagementGroupsAPI) Update(ctx context.Context, groupID string, patch armmanagementgroups.PatchManagementGroupRequest, options *armmanagementgroups.ClientUpdateOptions) (armmanagementgroups.ClientUpdateResponse, error) {
	return f.updateFn(ctx, groupID, patch, options)
}

func (f *fakeManagementGroupsAPI) BeginDelete(ctx context.Context, groupID string, options *armmanagementgroups.ClientBeginDeleteOptions) (*runtime.Poller[armmanagementgroups.ClientDeleteResponse], error) {
	return f.deleteFn(ctx, groupID, options)
}

func (f *fakeManagementGroupsAPI) NewListPager(_ *armmanagementgroups.ClientListOptions) *runtime.Pager[armmanagementgroups.ClientListResponse] {
	return runtime.NewPager(runtime.PagingHandler[armmanagementgroups.ClientListResponse]{
		More: func(_ armmanagementgroups.ClientListResponse) bool { return false },
		Fetcher: func(_ context.Context, _ *armmanagementgroups.ClientListResponse) (armmanagementgroups.ClientListResponse, error) {
			return armmanagementgroups.ClientListResponse{
				ManagementGroupListResult: armmanagementgroups.ManagementGroupListResult{
					Value: []*armmanagementgroups.ManagementGroupInfo{
						{ID: to.Ptr(testManagementGroupNativeID)},
						{ID: to.Ptr(testParentManagementGroupID)},
						// A nil entry must not panic the walk.
						nil,
					},
				},
			}, nil
		},
	})
}

// unreachableTransport fails any request. A poller built from an already-terminal
// response must never need one, so reaching it is itself the assertion.
type unreachableTransport struct{}

func (unreachableTransport) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("no HTTP call is expected from a completed poller")
}

// managementGroupResultJSON is the ARM body a completed create answers with. It
// mirrors managementGroupResult(), because a poller hands its result back by
// unmarshalling the response body rather than by returning a Go value.
const managementGroupResultJSON = `{
  "id": "/providers/Microsoft.Management/managementGroups/mg-1",
  "type": "Microsoft.Management/managementGroups",
  "name": "mg-1",
  "properties": {
    "tenantId": "tenant-1",
    "displayName": "conformance test group",
    "details": {
      "version": 3,
      "updatedBy": "someone",
      "parent": { "id": "/providers/Microsoft.Management/managementGroups/mg-parent" }
    },
    "children": [ { "name": "unmodelled-child" } ]
  }
}`

// donePoller builds a poller that has already completed, so Create and Delete take
// their synchronous path without any HTTP traffic. A 200 with no LRO headers is
// exactly what azcore treats as an operation that finished in one round trip.
func donePoller[T any](t *testing.T, body string) *runtime.Poller[T] {
	t.Helper()
	pipeline := runtime.NewPipeline("test", "v1.0.0", runtime.PipelineOptions{}, &policy.ClientOptions{
		Transport: unreachableTransport{},
	})
	requestURL, err := url.Parse("https://management.azure.com" + testManagementGroupNativeID)
	require.NoError(t, err)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{Method: http.MethodPut, URL: requestURL},
	}
	poller, err := runtime.NewPoller[T](resp, pipeline, nil)
	require.NoError(t, err)
	return poller
}

func newTestManagementGroup(api managementGroupsAPI) *ManagementGroup {
	return &ManagementGroup{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

func managementGroupResult() armmanagementgroups.ManagementGroup {
	return armmanagementgroups.ManagementGroup{
		ID:   to.Ptr(testManagementGroupNativeID),
		Name: to.Ptr(testManagementGroupName),
		Type: to.Ptr("Microsoft.Management/managementGroups"),
		Properties: &armmanagementgroups.ManagementGroupProperties{
			DisplayName: to.Ptr("conformance test group"),
			TenantID:    to.Ptr("tenant-1"),
			Details: &armmanagementgroups.ManagementGroupDetails{
				Parent:    &armmanagementgroups.ParentGroupInfo{ID: to.Ptr(testParentManagementGroupID)},
				UpdatedBy: to.Ptr("someone"),
				Version:   to.Ptr(int32(3)),
			},
			// The service's own view of what sits under the group.
			Children: []*armmanagementgroups.ManagementGroupChildInfo{{
				Name: to.Ptr("unmodelled-child"),
			}},
		},
	}
}

func TestManagementGroup_CRUD(t *testing.T) {
	var sentGroupID string
	var sent armmanagementgroups.CreateManagementGroupRequest
	var sentPatch armmanagementgroups.PatchManagementGroupRequest

	fake := &fakeManagementGroupsAPI{
		createFn: func(_ context.Context, groupID string, request armmanagementgroups.CreateManagementGroupRequest, _ *armmanagementgroups.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armmanagementgroups.ClientCreateOrUpdateResponse], error) {
			sentGroupID, sent = groupID, request
			return donePoller[armmanagementgroups.ClientCreateOrUpdateResponse](t, managementGroupResultJSON), nil
		},
		getFn: func(_ context.Context, groupID string, _ *armmanagementgroups.ClientGetOptions) (armmanagementgroups.ClientGetResponse, error) {
			sentGroupID = groupID
			return armmanagementgroups.ClientGetResponse{ManagementGroup: managementGroupResult()}, nil
		},
		updateFn: func(_ context.Context, groupID string, patch armmanagementgroups.PatchManagementGroupRequest, _ *armmanagementgroups.ClientUpdateOptions) (armmanagementgroups.ClientUpdateResponse, error) {
			sentGroupID, sentPatch = groupID, patch
			return armmanagementgroups.ClientUpdateResponse{ManagementGroup: managementGroupResult()}, nil
		},
		deleteFn: func(_ context.Context, groupID string, _ *armmanagementgroups.ClientBeginDeleteOptions) (*runtime.Poller[armmanagementgroups.ClientDeleteResponse], error) {
			sentGroupID = groupID
			return donePoller[armmanagementgroups.ClientDeleteResponse](t, "{}"), nil
		},
	}
	prov := newTestManagementGroup(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name":        testManagementGroupName,
			"displayName": "conformance test group",
			"parentId":    testParentManagementGroupID,
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "mg", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testManagementGroupNativeID, got.ProgressResult.NativeID)

		// The group ID is the path parameter, and is echoed in the body's name.
		require.Equal(t, testManagementGroupName, sentGroupID)
		require.Equal(t, testManagementGroupName, *sent.Name)
		require.Equal(t, "conformance test group", *sent.Properties.DisplayName)
		require.Equal(t, testParentManagementGroupID, *sent.Properties.Details.Parent.ID)
	})

	t.Run("Create_omits_unset_optionals", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{"name": testManagementGroupName})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Nil(t, sent.Properties.DisplayName)
		// No parent means the tenant root group, which ARM fills in.
		require.Nil(t, sent.Properties.Details)
	})

	t.Run("Create_falls_back_to_the_label", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "mg-from-label", Properties: props})
		require.NoError(t, err)
		require.Equal(t, "mg-from-label", sentGroupID)

		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "name is required")
	})

	t.Run("Create_surfaces_the_provider_error", func(t *testing.T) {
		failing := *fake
		failing.createFn = func(_ context.Context, _ string, _ armmanagementgroups.CreateManagementGroupRequest, _ *armmanagementgroups.ClientBeginCreateOrUpdateOptions) (*runtime.Poller[armmanagementgroups.ClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}
		}
		props, _ := json.Marshal(map[string]any{"name": testManagementGroupName})
		got, err := newTestManagementGroup(&failing).Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
		// The tenant-scope authorization failure is the one every caller without a
		// role at the tenant root will see, so it has to reach the status message.
		require.Contains(t, got.ProgressResult.StatusMessage, "AuthorizationFailed")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testManagementGroupNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, testManagementGroupName, sentGroupID)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, testManagementGroupName, props["name"])
		require.Equal(t, testManagementGroupNativeID, props["id"])
		require.Equal(t, "conformance test group", props["displayName"])
		require.Equal(t, "tenant-1", props["tenantId"])
		require.Equal(t, testParentManagementGroupID, props["parentId"])
	})

	t.Run("Read_drops_unmodelled_and_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testManagementGroupNativeID})
		require.NoError(t, err)
		for _, key := range []string{"children", "unmodelled-child", "updatedBy", "version", "type"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	t.Run("IDParts", func(t *testing.T) {
		name, err := managementGroupIDParts(testManagementGroupNativeID)
		require.NoError(t, err)
		require.Equal(t, testManagementGroupName, name)

		// ARM's casing on the provider segment is its own.
		name, err = managementGroupIDParts("/providers/microsoft.management/managementgroups/mg-2")
		require.NoError(t, err)
		require.Equal(t, "mg-2", name)

		_, err = managementGroupIDParts("/subscriptions/sub-1")
		require.ErrorContains(t, err, "not a management group resource ID")

		// A subscription association ID is not a group ID.
		_, err = managementGroupIDParts(testManagementGroupNativeID + "/subscriptions/sub-1")
		require.ErrorContains(t, err, "not a management group resource ID")
	})

	// Update is a synchronous PATCH reaching the only two mutable fields.
	t.Run("Update_patches_display_name_and_parent", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name":        testManagementGroupName,
			"displayName": "conformance test group, renamed",
			"parentId":    "/providers/Microsoft.Management/managementGroups/mg-other-parent",
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testManagementGroupNativeID, DesiredProperties: props,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testManagementGroupName, sentGroupID)
		require.Equal(t, "conformance test group, renamed", *sentPatch.DisplayName)
		require.Equal(t, "/providers/Microsoft.Management/managementGroups/mg-other-parent", *sentPatch.ParentGroupID)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testManagementGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testManagementGroupName, sentGroupID)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		gone := *fake
		gone.deleteFn = func(_ context.Context, _ string, _ *armmanagementgroups.ClientBeginDeleteOptions) (*runtime.Poller[armmanagementgroups.ClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := newTestManagementGroup(&gone).Delete(context.Background(), &resource.DeleteRequest{NativeID: testManagementGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// ARM refuses while the group still has children.
	t.Run("Delete_surfaces_a_still_populated_group", func(t *testing.T) {
		populated := *fake
		populated.deleteFn = func(_ context.Context, _ string, _ *armmanagementgroups.ClientBeginDeleteOptions) (*runtime.Poller[armmanagementgroups.ClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 400, ErrorCode: "ManagementGroupNotEmpty"}
		}
		got, err := newTestManagementGroup(&populated).Delete(context.Background(), &resource.DeleteRequest{NativeID: testManagementGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "ManagementGroupNotEmpty")
	})

	t.Run("List_is_tenant_wide", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Equal(t, []string{testManagementGroupNativeID, testParentManagementGroupID}, got.NativeIDs)
	})

	t.Run("Status_rejects_an_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("nonsense", "token", testManagementGroupNativeID)
		require.NoError(t, err)
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.Error(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Contains(t, got.ProgressResult.StatusMessage, "unknown LRO operation type")
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		missing := *fake
		missing.getFn = func(_ context.Context, _ string, _ *armmanagementgroups.ClientGetOptions) (armmanagementgroups.ClientGetResponse, error) {
			return armmanagementgroups.ClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := newTestManagementGroup(&missing).Read(context.Background(), &resource.ReadRequest{NativeID: testManagementGroupNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
