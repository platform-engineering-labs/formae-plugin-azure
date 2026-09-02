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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	// ARM answers with a fully lower-cased ID for this type, which is exactly the
	// case the ID parser has to canonicalize back.
	testLinkedServiceNativeID = "/subscriptions/sub-1/resourcegroups/rg-1/providers/microsoft.operationalinsights/workspaces/ws1/linkedservices/cluster"
	testLinkedServiceClusterID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/clusters/lac1"
)

type fakeLogAnalyticsLinkedServicesAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, workspaceName, serviceName string, params armoperationalinsights.LinkedService, options *armoperationalinsights.LinkedServicesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, workspaceName, serviceName string, options *armoperationalinsights.LinkedServicesClientGetOptions) (armoperationalinsights.LinkedServicesClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, workspaceName, serviceName string, options *armoperationalinsights.LinkedServicesClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientDeleteResponse], error)
	listPagerFn           func(rgName, workspaceName string, options *armoperationalinsights.LinkedServicesClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.LinkedServicesClientListByWorkspaceResponse]
}

func (f *fakeLogAnalyticsLinkedServicesAPI) BeginCreateOrUpdate(ctx context.Context, rgName, workspaceName, serviceName string, params armoperationalinsights.LinkedService, options *armoperationalinsights.LinkedServicesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, workspaceName, serviceName, params, options)
}

func (f *fakeLogAnalyticsLinkedServicesAPI) Get(ctx context.Context, rgName, workspaceName, serviceName string, options *armoperationalinsights.LinkedServicesClientGetOptions) (armoperationalinsights.LinkedServicesClientGetResponse, error) {
	return f.getFn(ctx, rgName, workspaceName, serviceName, options)
}

func (f *fakeLogAnalyticsLinkedServicesAPI) BeginDelete(ctx context.Context, rgName, workspaceName, serviceName string, options *armoperationalinsights.LinkedServicesClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, workspaceName, serviceName, options)
}

func (f *fakeLogAnalyticsLinkedServicesAPI) NewListByWorkspacePager(rgName, workspaceName string, options *armoperationalinsights.LinkedServicesClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.LinkedServicesClientListByWorkspaceResponse] {
	return f.listPagerFn(rgName, workspaceName, options)
}

func newTestLogAnalyticsLinkedService(api logAnalyticsLinkedServicesAPI) *LogAnalyticsLinkedService {
	return &LogAnalyticsLinkedService{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func linkedServiceDesired(writeAccessResourceID string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                  "Cluster",
		"resourceGroupName":     "rg-1",
		"workspaceName":         "ws1",
		"writeAccessResourceId": writeAccessResourceID,
	})
	return out
}

func TestLogAnalyticsLinkedService_CRUD(t *testing.T) {
	linkResult := armoperationalinsights.LinkedService{
		ID: to.Ptr(testLinkedServiceNativeID),
		// ARM returns the name workspace-qualified, which is not what the schema
		// declares — the read path must not surface this verbatim.
		Name: to.Ptr("ws1/Cluster"),
		Properties: &armoperationalinsights.LinkedServiceProperties{
			WriteAccessResourceID: to.Ptr(testLinkedServiceClusterID),
			// Service state.
			ProvisioningState: to.Ptr(armoperationalinsights.LinkedServiceEntityStatusSucceeded),
		},
	}

	var sent armoperationalinsights.LinkedService
	var sentName string
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeLogAnalyticsLinkedServicesAPI{
		beginCreateOrUpdateFn: func(_ context.Context, rgName, workspaceName, serviceName string, params armoperationalinsights.LinkedService, _ *armoperationalinsights.LinkedServicesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse], error) {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "ws1", workspaceName)
			sent = params
			sentName = serviceName
			writeCalls++
			return newDonePoller(armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse{LinkedService: linkResult}), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armoperationalinsights.LinkedServicesClientGetOptions) (armoperationalinsights.LinkedServicesClientGetResponse, error) {
			return armoperationalinsights.LinkedServicesClientGetResponse{LinkedService: linkResult}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armoperationalinsights.LinkedServicesClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientDeleteResponse], error) {
			deleteCalls++
			return newDonePoller(armoperationalinsights.LinkedServicesClientDeleteResponse{}), nil
		},
		listPagerFn: func(_, _ string, _ *armoperationalinsights.LinkedServicesClientListByWorkspaceOptions) *runtime.Pager[armoperationalinsights.LinkedServicesClientListByWorkspaceResponse] {
			return runtime.NewPager(runtime.PagingHandler[armoperationalinsights.LinkedServicesClientListByWorkspaceResponse]{
				More: func(_ armoperationalinsights.LinkedServicesClientListByWorkspaceResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armoperationalinsights.LinkedServicesClientListByWorkspaceResponse) (armoperationalinsights.LinkedServicesClientListByWorkspaceResponse, error) {
					return armoperationalinsights.LinkedServicesClientListByWorkspaceResponse{
						LinkedServiceListResult: armoperationalinsights.LinkedServiceListResult{
							Value: []*armoperationalinsights.LinkedService{
								{ID: to.Ptr(testLinkedServiceNativeID)},
								// A nil entry must not panic the walk.
								nil,
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestLogAnalyticsLinkedService(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "Cluster", Properties: linkedServiceDesired(testLinkedServiceClusterID),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testLinkedServiceNativeID, got.ProgressResult.NativeID)

		// The kind is the resource's own path segment, not a body field.
		require.Equal(t, "Cluster", sentName)
		require.Equal(t, testLinkedServiceClusterID, *sent.Properties.WriteAccessResourceID)
		require.Nil(t, sent.Properties.ResourceID)
	})

	// ARM rejects a link that points nowhere, so the handler refuses first.
	t.Run("Create_requires_a_target", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "Cluster", "resourceGroupName": "rg-1", "workspaceName": "ws1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "one of resourceId or writeAccessResourceId is required")
	})

	t.Run("Create_accepts_read_access_target", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "Automation", "resourceGroupName": "rg-1", "workspaceName": "ws1",
			"resourceId": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Automation/automationAccounts/aa1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, "Automation", sentName)
		require.NotNil(t, sent.Properties.ResourceID)
		require.Nil(t, sent.Properties.WriteAccessResourceID)
	})

	// A create that has not finished must pin the ID ARM will finally assign, or
	// the resource is orphaned on completion.
	t.Run("Create_in_progress_pins_the_expected_native_id", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armoperationalinsights.LinkedService, _ *armoperationalinsights.LinkedServicesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse], error) {
			return newInProgressPoller[armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse](), nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "Cluster", Properties: linkedServiceDesired(testLinkedServiceClusterID),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t,
			"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/ws1/linkedServices/Cluster",
			got.ProgressResult.NativeID)
		require.NotEmpty(t, got.ProgressResult.RequestID)

		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpCreate, reqID.OperationType)

		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, serviceName string, params armoperationalinsights.LinkedService, _ *armoperationalinsights.LinkedServicesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse], error) {
			sent = params
			sentName = serviceName
			writeCalls++
			return newDonePoller(armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse{LinkedService: linkResult}), nil
		}
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLinkedServiceNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypeLogAnalyticsLinkedService, got.ResourceType)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		// The lower-cased leaf of the ID is restored to the declared casing, and
		// ARM's workspace-qualified Name is not used at all.
		require.Equal(t, "Cluster", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "ws1", props["workspaceName"])
		require.Equal(t, testLinkedServiceClusterID, props["writeAccessResourceId"])
		// Not declared, so absent rather than "".
		require.NotContains(t, props, "resourceId")
	})

	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLinkedServiceNativeID})
		require.NoError(t, err)
		for _, key := range []string{"provisioningState", "Succeeded", "ws1/Cluster"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// BeginCreateOrUpdate is the only write verb this API has.
	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := writeCalls
		other := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/clusters/lac2"
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testLinkedServiceNativeID,
			DesiredProperties: linkedServiceDesired(other),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, "Cluster", sentName)
		require.Equal(t, other, *sent.Properties.WriteAccessResourceID)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLinkedServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_in_progress_reports_a_resume_token", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.LinkedServicesClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientDeleteResponse], error) {
			return newInProgressPoller[armoperationalinsights.LinkedServicesClientDeleteResponse](), nil
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLinkedServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		reqID, err := decodeLROStatus(got.ProgressResult.RequestID)
		require.NoError(t, err)
		require.Equal(t, lroOpDelete, reqID.OperationType)
		require.Equal(t, testLinkedServiceNativeID, reqID.NativeID)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.LinkedServicesClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testLinkedServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_rejects_an_unknown_operation", func(t *testing.T) {
		reqID, err := encodeLROStart("nonsense", "token", testLinkedServiceNativeID)
		require.NoError(t, err)
		_, err = prov.Status(context.Background(), &resource.StatusRequest{RequestID: reqID})
		require.ErrorContains(t, err, "unknown operation type")
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "workspaceName": "ws1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testLinkedServiceNativeID}, got.NativeIDs)
	})

	t.Run("List_without_workspace_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _, _ string, _ *armoperationalinsights.LinkedServicesClientGetOptions) (armoperationalinsights.LinkedServicesClientGetResponse, error) {
			return armoperationalinsights.LinkedServicesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testLinkedServiceNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})

	t.Run("Create_failure_reports_the_provider_error", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _, _ string, _ armoperationalinsights.LinkedService, _ *armoperationalinsights.LinkedServicesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.LinkedServicesClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 400}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "Cluster", Properties: linkedServiceDesired(testLinkedServiceClusterID),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
		require.NotEmpty(t, got.ProgressResult.StatusMessage)
	})
}
