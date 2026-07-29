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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const (
	testPrivateRecordSetNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/privateDnsZones/internal.example.com/A/www"
	testPrivateSOANativeID       = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/privateDnsZones/internal.example.com/SOA/@"
)

func TestPrivateDnsRecordSet_CRUD(t *testing.T) {
	model := armprivatedns.RecordSet{
		ID:   to.Ptr(testPrivateRecordSetNativeID),
		Name: to.Ptr("www"),
		Type: to.Ptr("Microsoft.Network/privateDnsZones/A"),
		Properties: &armprivatedns.RecordSetProperties{
			TTL:      to.Ptr(int64(3600)),
			ARecords: []*armprivatedns.ARecord{{IPv4Address: to.Ptr("10.0.0.4")}},
		},
	}
	fake := &fakePrivateDnsRecordSetsAPI{
		createOrUpdateFn: func(_ context.Context, _, _ string, _ armprivatedns.RecordType, _ string, _ armprivatedns.RecordSet, _ *armprivatedns.RecordSetsClientCreateOrUpdateOptions) (armprivatedns.RecordSetsClientCreateOrUpdateResponse, error) {
			return armprivatedns.RecordSetsClientCreateOrUpdateResponse{RecordSet: model}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ armprivatedns.RecordType, _ string, _ *armprivatedns.RecordSetsClientGetOptions) (armprivatedns.RecordSetsClientGetResponse, error) {
			return armprivatedns.RecordSetsClientGetResponse{RecordSet: model}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ armprivatedns.RecordType, _ string, _ *armprivatedns.RecordSetsClientDeleteOptions) (armprivatedns.RecordSetsClientDeleteResponse, error) {
			return armprivatedns.RecordSetsClientDeleteResponse{}, nil
		},
		newListPagerFn: func(_, _ string, _ *armprivatedns.RecordSetsClientListOptions) *runtime.Pager[armprivatedns.RecordSetsClientListResponse] {
			return runtime.NewPager(runtime.PagingHandler[armprivatedns.RecordSetsClientListResponse]{
				More: func(_ armprivatedns.RecordSetsClientListResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armprivatedns.RecordSetsClientListResponse) (armprivatedns.RecordSetsClientListResponse, error) {
					return armprivatedns.RecordSetsClientListResponse{
						RecordSetListResult: armprivatedns.RecordSetListResult{
							Value: []*armprivatedns.RecordSet{
								{ID: to.Ptr(testPrivateSOANativeID), Type: to.Ptr("Microsoft.Network/privateDnsZones/SOA")},
								{ID: to.Ptr(testPrivateRecordSetNativeID), Type: to.Ptr("Microsoft.Network/privateDnsZones/A")},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := &PrivateDnsRecordSet{api: fake, config: &config.Config{SubscriptionId: "sub-1"}}

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"privateZoneName":   "internal.example.com",
			"name":              "www",
			"recordType":        "A",
			"ttl":               3600,
			"aRecords":          []map[string]any{{"ipv4Address": "10.0.0.4"}},
		})
		return props
	}

	// The SDK argument order here is (rg, zone, recordType, relativeName) — the
	// opposite of armdns, and both are (string, string, X, Y) so a swap still
	// compiles. This asserts each value lands in the right slot.
	t.Run("Create passes recordType before relativeName", func(t *testing.T) {
		var seenRG, seenZone, seenName string
		var seenType armprivatedns.RecordType
		var seen armprivatedns.RecordSet
		fake.createOrUpdateFn = func(_ context.Context, rg, zone string, rt armprivatedns.RecordType, name string, params armprivatedns.RecordSet, _ *armprivatedns.RecordSetsClientCreateOrUpdateOptions) (armprivatedns.RecordSetsClientCreateOrUpdateResponse, error) {
			seenRG, seenZone, seenType, seenName, seen = rg, zone, rt, name, params
			return armprivatedns.RecordSetsClientCreateOrUpdateResponse{RecordSet: model}, nil
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testPrivateRecordSetNativeID, got.ProgressResult.NativeID)
		require.Equal(t, "rg-1", seenRG)
		require.Equal(t, "internal.example.com", seenZone)
		require.Equal(t, armprivatedns.RecordTypeA, seenType)
		require.Equal(t, "www", seenName)
		require.Equal(t, int64(3600), *seen.Properties.TTL)
		require.Len(t, seen.Properties.ARecords, 1)
		require.Equal(t, "10.0.0.4", *seen.Properties.ARecords[0].IPv4Address)

		var serialized map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &serialized))
		require.Equal(t, "www", serialized["name"])
		require.Equal(t, "internal.example.com", serialized["privateZoneName"])
		require.Equal(t, "A", serialized["recordType"])
		require.Equal(t, float64(3600), serialized["ttl"])
		require.Equal(t, []any{map[string]any{"ipv4Address": "10.0.0.4"}}, serialized["aRecords"])
	})

	t.Run("Create supports CNAME and TXT", func(t *testing.T) {
		var seen armprivatedns.RecordSet
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armprivatedns.RecordType, _ string, params armprivatedns.RecordSet, _ *armprivatedns.RecordSetsClientCreateOrUpdateOptions) (armprivatedns.RecordSetsClientCreateOrUpdateResponse, error) {
			seen = params
			return armprivatedns.RecordSetsClientCreateOrUpdateResponse{RecordSet: model}, nil
		}

		cnameProps, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "privateZoneName": "internal.example.com",
			"name": "alias", "recordType": "CNAME", "ttl": 300, "cname": "www.internal.example.com",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: cnameProps})
		require.NoError(t, err)
		require.Equal(t, "www.internal.example.com", *seen.Properties.CnameRecord.Cname)

		txtProps, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "privateZoneName": "internal.example.com",
			"name": "txt", "recordType": "TXT", "ttl": 300,
			"txtRecords": []map[string]any{{"value": []any{"hello", "world"}}},
		})
		_, err = prov.Create(context.Background(), &resource.CreateRequest{Properties: txtProps})
		require.NoError(t, err)
		require.Len(t, seen.Properties.TxtRecords, 1)
		require.Len(t, seen.Properties.TxtRecords[0].Value, 2)
	})

	t.Run("Create validates per record type", func(t *testing.T) {
		cases := []struct{ name, body, want string }{
			{"missing recordType", `{"resourceGroupName":"rg-1","privateZoneName":"z","name":"n"}`, "recordType is required"},
			{"unsupported recordType", `{"resourceGroupName":"rg-1","privateZoneName":"z","name":"n","recordType":"MX"}`, "unsupported recordType"},
			{"A without records", `{"resourceGroupName":"rg-1","privateZoneName":"z","name":"n","recordType":"A"}`, "aRecords is required"},
			{"CNAME without cname", `{"resourceGroupName":"rg-1","privateZoneName":"z","name":"n","recordType":"CNAME"}`, "cname is required"},
			{"TXT without records", `{"resourceGroupName":"rg-1","privateZoneName":"z","name":"n","recordType":"TXT"}`, "txtRecords is required"},
			{"missing privateZoneName", `{"resourceGroupName":"rg-1","name":"n","recordType":"A"}`, "privateZoneName is required"},
			{"missing resourceGroupName", `{"privateZoneName":"z","name":"n","recordType":"A"}`, "resourceGroupName is required"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: json.RawMessage(c.body)})
				require.ErrorContains(t, err, c.want)
			})
		}
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPrivateRecordSetNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		require.Equal(t, ResourceTypePrivateDnsRecordSet, got.ResourceType)
	})

	t.Run("Read_not_found", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ armprivatedns.RecordType, _ string, _ *armprivatedns.RecordSetsClientGetOptions) (armprivatedns.RecordSetsClientGetResponse, error) {
			return armprivatedns.RecordSetsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testPrivateRecordSetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)

		fake.getFn = func(_ context.Context, _, _ string, _ armprivatedns.RecordType, _ string, _ *armprivatedns.RecordSetsClientGetOptions) (armprivatedns.RecordSetsClientGetResponse, error) {
			return armprivatedns.RecordSetsClientGetResponse{RecordSet: model}, nil
		}
	})

	// The record type is fixed by the native ID, so a payload claiming a different
	// type must not retarget the call.
	t.Run("Update takes recordType from the native ID, not the payload", func(t *testing.T) {
		var seenType armprivatedns.RecordType
		var seenRG, seenZone, seenName string
		fake.createOrUpdateFn = func(_ context.Context, rg, zone string, rt armprivatedns.RecordType, name string, _ armprivatedns.RecordSet, _ *armprivatedns.RecordSetsClientCreateOrUpdateOptions) (armprivatedns.RecordSetsClientCreateOrUpdateResponse, error) {
			seenRG, seenZone, seenType, seenName = rg, zone, rt, name
			return armprivatedns.RecordSetsClientCreateOrUpdateResponse{RecordSet: model}, nil
		}
		desired, _ := json.Marshal(map[string]any{
			"recordType": "TXT", // deliberately wrong; the ID says A
			"ttl":        60,
			"aRecords":   []map[string]any{{"ipv4Address": "10.0.0.5"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID: testPrivateRecordSetNativeID, DesiredProperties: desired,
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, armprivatedns.RecordTypeA, seenType)
		require.Equal(t, []string{"rg-1", "internal.example.com", "www"}, []string{seenRG, seenZone, seenName})
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ armprivatedns.RecordType, _ string, _ *armprivatedns.RecordSetsClientDeleteOptions) (armprivatedns.RecordSetsClientDeleteResponse, error) {
			return armprivatedns.RecordSetsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testPrivateRecordSetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_sync_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// Azure auto-creates an SOA record set per private zone and refuses to delete it.
	t.Run("List filters the implicit SOA record set", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "privateZoneName": "internal.example.com",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testPrivateRecordSetNativeID}, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _ string, _ armprivatedns.RecordType, _ string, _ armprivatedns.RecordSet, _ *armprivatedns.RecordSetsClientCreateOrUpdateOptions) (armprivatedns.RecordSetsClientCreateOrUpdateResponse, error) {
			return armprivatedns.RecordSetsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

func TestPrivateDnsRecordSetIDParts(t *testing.T) {
	rg, zone, rt, name, err := privateDnsRecordSetIDParts(testPrivateRecordSetNativeID)
	require.NoError(t, err)
	require.Equal(t, []string{"rg-1", "internal.example.com", "A", "www"}, []string{rg, zone, rt, name})

	// The record type is a path segment, so it is read off the leaf, uppercased.
	_, _, rt, _, err = privateDnsRecordSetIDParts(
		"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/privateDnsZones/z/txt/rec")
	require.NoError(t, err)
	require.Equal(t, "TXT", rt)

	// A public DNS zone record set must not parse as a private one.
	_, _, _, _, err = privateDnsRecordSetIDParts(
		"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnszones/example.com/A/www")
	require.ErrorContains(t, err, "missing privateDnsZones")

	_, _, _, _, err = privateDnsRecordSetIDParts("/subscriptions/sub-1/resourceGroups/rg-1")
	require.Error(t, err)
}

// --- Test helpers ---

type fakePrivateDnsRecordSetsAPI struct {
	createOrUpdateFn func(ctx context.Context, rgName, zoneName string, recordType armprivatedns.RecordType, relativeName string, params armprivatedns.RecordSet, opts *armprivatedns.RecordSetsClientCreateOrUpdateOptions) (armprivatedns.RecordSetsClientCreateOrUpdateResponse, error)
	getFn            func(ctx context.Context, rgName, zoneName string, recordType armprivatedns.RecordType, relativeName string, opts *armprivatedns.RecordSetsClientGetOptions) (armprivatedns.RecordSetsClientGetResponse, error)
	deleteFn         func(ctx context.Context, rgName, zoneName string, recordType armprivatedns.RecordType, relativeName string, opts *armprivatedns.RecordSetsClientDeleteOptions) (armprivatedns.RecordSetsClientDeleteResponse, error)
	newListPagerFn   func(rgName, zoneName string, opts *armprivatedns.RecordSetsClientListOptions) *runtime.Pager[armprivatedns.RecordSetsClientListResponse]
}

func (f *fakePrivateDnsRecordSetsAPI) CreateOrUpdate(ctx context.Context, rgName, zoneName string, recordType armprivatedns.RecordType, relativeName string, params armprivatedns.RecordSet, opts *armprivatedns.RecordSetsClientCreateOrUpdateOptions) (armprivatedns.RecordSetsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, zoneName, recordType, relativeName, params, opts)
}

func (f *fakePrivateDnsRecordSetsAPI) Get(ctx context.Context, rgName, zoneName string, recordType armprivatedns.RecordType, relativeName string, opts *armprivatedns.RecordSetsClientGetOptions) (armprivatedns.RecordSetsClientGetResponse, error) {
	return f.getFn(ctx, rgName, zoneName, recordType, relativeName, opts)
}

func (f *fakePrivateDnsRecordSetsAPI) Delete(ctx context.Context, rgName, zoneName string, recordType armprivatedns.RecordType, relativeName string, opts *armprivatedns.RecordSetsClientDeleteOptions) (armprivatedns.RecordSetsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, zoneName, recordType, relativeName, opts)
}

func (f *fakePrivateDnsRecordSetsAPI) NewListPager(rgName, zoneName string, opts *armprivatedns.RecordSetsClientListOptions) *runtime.Pager[armprivatedns.RecordSetsClientListResponse] {
	return f.newListPagerFn(rgName, zoneName, opts)
}
