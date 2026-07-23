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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testCdnCustomDomainNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Cdn/profiles/afd-1/customDomains/cd-1"
const testCdnCustomDomainSecretID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Cdn/profiles/afd-1/secrets/sec-1"

// managed-cert custom domain (the default, CI-friendly shape)
func managedCdnCustomDomainProps() map[string]any {
	return map[string]any{
		"resourceGroupName": "rg-1",
		"profileName":       "afd-1",
		"name":              "cd-1",
		"hostName":          "www.example.com",
		"tlsSettings": map[string]any{
			"certificateType":   "ManagedCertificate",
			"minimumTlsVersion": "TLS12",
		},
	}
}

// BYO-cert custom domain referencing an AFD Secret
func customerCertCdnCustomDomainProps() map[string]any {
	return map[string]any{
		"resourceGroupName": "rg-1",
		"profileName":       "afd-1",
		"name":              "cd-1",
		"hostName":          "www.example.com",
		"tlsSettings": map[string]any{
			"certificateType":   "CustomerCertificate",
			"minimumTlsVersion": "TLS12",
			"secretId":          testCdnCustomDomainSecretID,
		},
	}
}

func createCdnCustomDomainProps() json.RawMessage {
	props, _ := json.Marshal(managedCdnCustomDomainProps())
	return props
}

// TestCdnAFDCustomDomain_MarshallerRoundTrip covers the tlsSettings block for
// both the managed-cert default and a BYO customer-certificate that references
// an AFD Secret by ARM id.
func TestCdnAFDCustomDomain_MarshallerRoundTrip(t *testing.T) {
	t.Run("managed certificate", func(t *testing.T) {
		params := buildCdnAFDCustomDomainParams(managedCdnCustomDomainProps())
		params.ID = to.Ptr(testCdnCustomDomainNativeID)
		params.Name = to.Ptr("cd-1")
		raw, err := serializeCdnAFDCustomDomainProperties(params, "rg-1", "afd-1", "cd-1")
		require.NoError(t, err)
		var got map[string]any
		require.NoError(t, json.Unmarshal(raw, &got))
		require.Equal(t, "www.example.com", got["hostName"])
		tls := got["tlsSettings"].(map[string]any)
		require.Equal(t, "ManagedCertificate", tls["certificateType"])
		require.Equal(t, "TLS12", tls["minimumTlsVersion"])
		require.Nil(t, tls["secretId"], "managed cert must not carry a secret reference")
	})

	t.Run("customer certificate references AFD secret", func(t *testing.T) {
		params := buildCdnAFDCustomDomainParams(customerCertCdnCustomDomainProps())
		params.ID = to.Ptr(testCdnCustomDomainNativeID)
		params.Name = to.Ptr("cd-1")
		raw, err := serializeCdnAFDCustomDomainProperties(params, "rg-1", "afd-1", "cd-1")
		require.NoError(t, err)
		var got map[string]any
		require.NoError(t, json.Unmarshal(raw, &got))
		tls := got["tlsSettings"].(map[string]any)
		require.Equal(t, "CustomerCertificate", tls["certificateType"])
		require.Equal(t, testCdnCustomDomainSecretID, tls["secretId"], "BYO cert secret ref must round-trip as a full ARM id")
	})
}

func TestCdnAFDCustomDomain_CRUD(t *testing.T) {
	built := buildCdnAFDCustomDomainParams(managedCdnCustomDomainProps())
	built.ID = to.Ptr(testCdnCustomDomainNativeID)
	built.Name = to.Ptr("cd-1")

	doneResult := armcdn.AFDCustomDomainsClientCreateResponse{AFDDomain: built}

	fake := &fakeCdnAFDCustomDomainsAPI{
		beginCreateFn: func(_ context.Context, _, _, _ string, _ armcdn.AFDDomain, _ *armcdn.AFDCustomDomainsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDCustomDomainsClientCreateResponse], error) {
			return newDonePoller(doneResult), nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ *armcdn.AFDCustomDomainsClientGetOptions) (armcdn.AFDCustomDomainsClientGetResponse, error) {
			return armcdn.AFDCustomDomainsClientGetResponse{AFDDomain: built}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _, _ string, _ *armcdn.AFDCustomDomainsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDCustomDomainsClientDeleteResponse], error) {
			return newInProgressPoller[armcdn.AFDCustomDomainsClientDeleteResponse](), nil
		},
		newListByProfilePagerFn: func(_, _ string, _ *armcdn.AFDCustomDomainsClientListByProfileOptions) *runtime.Pager[armcdn.AFDCustomDomainsClientListByProfileResponse] {
			return runtime.NewPager(runtime.PagingHandler[armcdn.AFDCustomDomainsClientListByProfileResponse]{
				More: func(_ armcdn.AFDCustomDomainsClientListByProfileResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armcdn.AFDCustomDomainsClientListByProfileResponse) (armcdn.AFDCustomDomainsClientListByProfileResponse, error) {
					return armcdn.AFDCustomDomainsClientListByProfileResponse{
						AFDDomainListResult: armcdn.AFDDomainListResult{Value: []*armcdn.AFDDomain{{ID: to.Ptr(testCdnCustomDomainNativeID)}}},
					}, nil
				},
			})
		},
	}
	prov := newTestCdnAFDCustomDomain(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnCustomDomainProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testCdnCustomDomainNativeID, got.ProgressResult.NativeID)
		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "www.example.com", props["hostName"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testCdnCustomDomainNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "afd-1", props["profileName"])
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testCdnCustomDomainNativeID, DesiredProperties: createCdnCustomDomainProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnCustomDomainNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _, _ string, _ *armcdn.AFDCustomDomainsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDCustomDomainsClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testCdnCustomDomainNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "profileName": "afd-1"}})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateFn = func(_ context.Context, _, _, _ string, _ armcdn.AFDDomain, _ *armcdn.AFDCustomDomainsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDCustomDomainsClientCreateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createCdnCustomDomainProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestCdnAFDCustomDomain(api cdnAFDCustomDomainsAPI) *CdnAFDCustomDomain {
	return &CdnAFDCustomDomain{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeCdnAFDCustomDomainsAPI struct {
	beginCreateFn           func(ctx context.Context, rgName, profileName, customDomainName string, customDomain armcdn.AFDDomain, opts *armcdn.AFDCustomDomainsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDCustomDomainsClientCreateResponse], error)
	getFn                   func(ctx context.Context, rgName, profileName, customDomainName string, opts *armcdn.AFDCustomDomainsClientGetOptions) (armcdn.AFDCustomDomainsClientGetResponse, error)
	beginDeleteFn           func(ctx context.Context, rgName, profileName, customDomainName string, opts *armcdn.AFDCustomDomainsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDCustomDomainsClientDeleteResponse], error)
	newListByProfilePagerFn func(rgName, profileName string, opts *armcdn.AFDCustomDomainsClientListByProfileOptions) *runtime.Pager[armcdn.AFDCustomDomainsClientListByProfileResponse]
}

func (f *fakeCdnAFDCustomDomainsAPI) BeginCreate(ctx context.Context, rgName, profileName, customDomainName string, customDomain armcdn.AFDDomain, opts *armcdn.AFDCustomDomainsClientBeginCreateOptions) (*runtime.Poller[armcdn.AFDCustomDomainsClientCreateResponse], error) {
	return f.beginCreateFn(ctx, rgName, profileName, customDomainName, customDomain, opts)
}

func (f *fakeCdnAFDCustomDomainsAPI) Get(ctx context.Context, rgName, profileName, customDomainName string, opts *armcdn.AFDCustomDomainsClientGetOptions) (armcdn.AFDCustomDomainsClientGetResponse, error) {
	return f.getFn(ctx, rgName, profileName, customDomainName, opts)
}

func (f *fakeCdnAFDCustomDomainsAPI) BeginDelete(ctx context.Context, rgName, profileName, customDomainName string, opts *armcdn.AFDCustomDomainsClientBeginDeleteOptions) (*runtime.Poller[armcdn.AFDCustomDomainsClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, profileName, customDomainName, opts)
}

func (f *fakeCdnAFDCustomDomainsAPI) NewListByProfilePager(rgName, profileName string, opts *armcdn.AFDCustomDomainsClientListByProfileOptions) *runtime.Pager[armcdn.AFDCustomDomainsClientListByProfileResponse] {
	return f.newListByProfilePagerFn(rgName, profileName, opts)
}
