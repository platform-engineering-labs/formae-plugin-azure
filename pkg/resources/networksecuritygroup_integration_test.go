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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testNSGNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-1"

func TestNetworkSecurityGroup_CRUD(t *testing.T) {
	direction := armnetwork.SecurityRuleDirectionInbound
	access := armnetwork.SecurityRuleAccessAllow
	protocol := armnetwork.SecurityRuleProtocolTCP

	fake := &fakeNetworkSecurityGroupsAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.SecurityGroup, _ *armnetwork.SecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.SecurityGroupsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.SecurityGroupsClientGetOptions) (armnetwork.SecurityGroupsClientGetResponse, error) {
			return armnetwork.SecurityGroupsClientGetResponse{
				SecurityGroup: armnetwork.SecurityGroup{
					ID:       to.Ptr(testNSGNativeID),
					Name:     to.Ptr("nsg-1"),
					Location: to.Ptr("eastus"),
					Properties: &armnetwork.SecurityGroupPropertiesFormat{
						SecurityRules: []*armnetwork.SecurityRule{
							{
								Name: to.Ptr("allow-ssh"),
								Properties: &armnetwork.SecurityRulePropertiesFormat{
									Priority:                 to.Ptr(int32(100)),
									Direction:                &direction,
									Access:                   &access,
									Protocol:                 &protocol,
									SourcePortRange:          to.Ptr("*"),
									DestinationPortRange:     to.Ptr("22"),
									SourceAddressPrefix:      to.Ptr("*"),
									DestinationAddressPrefix: to.Ptr("*"),
								},
							},
						},
					},
				},
			}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.SecurityGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SecurityGroupsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		},
		newListPagerFn: func(_ string, _ *armnetwork.SecurityGroupsClientListOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.SecurityGroupsClientListResponse]{
				More: func(_ armnetwork.SecurityGroupsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.SecurityGroupsClientListResponse) (armnetwork.SecurityGroupsClientListResponse, error) {
					return armnetwork.SecurityGroupsClientListResponse{
						SecurityGroupListResult: armnetwork.SecurityGroupListResult{
							Value: []*armnetwork.SecurityGroup{
								{ID: to.Ptr(testNSGNativeID)},
							},
						},
					}, nil
				},
			})
		},
		newListAllPagerFn: func(_ *armnetwork.SecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.SecurityGroupsClientListAllResponse]{
				More: func(_ armnetwork.SecurityGroupsClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.SecurityGroupsClientListAllResponse) (armnetwork.SecurityGroupsClientListAllResponse, error) {
					return armnetwork.SecurityGroupsClientListAllResponse{
						SecurityGroupListResult: armnetwork.SecurityGroupListResult{
							Value: []*armnetwork.SecurityGroup{
								{ID: to.Ptr(testNSGNativeID)},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestNetworkSecurityGroup(fake)

	t.Run("Create", func(t *testing.T) {
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "location": "eastus", "name": "nsg-1",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Label: "test-nsg", Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testNSGNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "nsg-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "eastus", props["location"])
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testNSGNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
		require.Equal(t, testNSGNativeID, got.NativeIDs[0])
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.SecurityGroup, _ *armnetwork.SecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.SecurityGroupsClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		props, _ := json.Marshal(map[string]interface{}{
			"resourceGroupName": "rg-1", "location": "eastus", "name": "nsg-1",
		})
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestNetworkSecurityGroup(api networkSecurityGroupsAPI) *NetworkSecurityGroup {
	return &NetworkSecurityGroup{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeNetworkSecurityGroupsAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, nsgName string, params armnetwork.SecurityGroup, opts *armnetwork.SecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.SecurityGroupsClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, nsgName string, opts *armnetwork.SecurityGroupsClientGetOptions) (armnetwork.SecurityGroupsClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, nsgName string, opts *armnetwork.SecurityGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SecurityGroupsClientDeleteResponse], error)
	newListPagerFn        func(rgName string, opts *armnetwork.SecurityGroupsClientListOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListResponse]
	newListAllPagerFn     func(opts *armnetwork.SecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListAllResponse]
	resumeCreatePollerFn  func(token string) (*runtime.Poller[armnetwork.SecurityGroupsClientCreateOrUpdateResponse], error)
	resumeDeletePollerFn  func(token string) (*runtime.Poller[armnetwork.SecurityGroupsClientDeleteResponse], error)
}

func (f *fakeNetworkSecurityGroupsAPI) BeginCreateOrUpdate(ctx context.Context, rgName, nsgName string, params armnetwork.SecurityGroup, opts *armnetwork.SecurityGroupsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.SecurityGroupsClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, nsgName, params, opts)
}

func (f *fakeNetworkSecurityGroupsAPI) Get(ctx context.Context, rgName, nsgName string, opts *armnetwork.SecurityGroupsClientGetOptions) (armnetwork.SecurityGroupsClientGetResponse, error) {
	return f.getFn(ctx, rgName, nsgName, opts)
}

func (f *fakeNetworkSecurityGroupsAPI) BeginDelete(ctx context.Context, rgName, nsgName string, opts *armnetwork.SecurityGroupsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.SecurityGroupsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, nsgName, opts)
}

func (f *fakeNetworkSecurityGroupsAPI) NewListPager(rgName string, opts *armnetwork.SecurityGroupsClientListOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakeNetworkSecurityGroupsAPI) NewListAllPager(opts *armnetwork.SecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListAllResponse] {
	return f.newListAllPagerFn(opts)
}

func (f *fakeNetworkSecurityGroupsAPI) ResumeCreatePoller(token string) (*runtime.Poller[armnetwork.SecurityGroupsClientCreateOrUpdateResponse], error) {
	return f.resumeCreatePollerFn(token)
}

func (f *fakeNetworkSecurityGroupsAPI) ResumeDeletePoller(token string) (*runtime.Poller[armnetwork.SecurityGroupsClientDeleteResponse], error) {
	return f.resumeDeletePollerFn(token)
}
