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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testRecordSetNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnszones/example-1.com/A/www"

func TestDnsRecordSet_CRUD(t *testing.T) {
	result := armdns.RecordSet{
		ID:   to.Ptr(testRecordSetNativeID),
		Name: to.Ptr("www"),
		Type: to.Ptr("Microsoft.Network/dnszones/A"),
		Properties: &armdns.RecordSetProperties{
			TTL:      to.Ptr[int64](3600),
			Fqdn:     to.Ptr("www.example-1.com."),
			ARecords: []*armdns.ARecord{{IPv4Address: to.Ptr("10.0.0.1")}},
		},
	}
	fake := &fakeRecordSetsAPI{
		createOrUpdateFn: func(_ context.Context, _, _, _ string, _ armdns.RecordType, _ armdns.RecordSet, _ *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
			return armdns.RecordSetsClientCreateOrUpdateResponse{RecordSet: result}, nil
		},
		getFn: func(_ context.Context, _, _, _ string, _ armdns.RecordType, _ *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
			return armdns.RecordSetsClientGetResponse{RecordSet: result}, nil
		},
		deleteFn: func(_ context.Context, _, _, _ string, _ armdns.RecordType, _ *armdns.RecordSetsClientDeleteOptions) (armdns.RecordSetsClientDeleteResponse, error) {
			return armdns.RecordSetsClientDeleteResponse{}, nil
		},
		newListByDNSZonePagerFn: func(_, _ string, _ *armdns.RecordSetsClientListByDNSZoneOptions) *runtime.Pager[armdns.RecordSetsClientListByDNSZoneResponse] {
			return runtime.NewPager(runtime.PagingHandler[armdns.RecordSetsClientListByDNSZoneResponse]{
				More: func(_ armdns.RecordSetsClientListByDNSZoneResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armdns.RecordSetsClientListByDNSZoneResponse) (armdns.RecordSetsClientListByDNSZoneResponse, error) {
					return armdns.RecordSetsClientListByDNSZoneResponse{
						RecordSetListResult: armdns.RecordSetListResult{Value: []*armdns.RecordSet{{ID: to.Ptr(testRecordSetNativeID)}}},
					}, nil
				},
			})
		},
	}
	prov := newTestDnsRecordSet(fake)

	mkProps := func() json.RawMessage {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"zoneName":          "example-1.com",
			"name":              "www",
			"recordType":        "A",
			"ttl":               3600,
			"aRecords":          []map[string]any{{"ipv4Address": "10.0.0.1"}},
		})
		return props
	}

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testRecordSetNativeID, got.ProgressResult.NativeID)
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testRecordSetNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "A", props["recordType"])
		require.Equal(t, "www.example-1.com.", props["fqdn"])
	})

	t.Run("Update", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1",
			"zoneName":          "example-1.com",
			"name":              "www",
			"recordType":        "A",
			"ttl":               7200,
			"aRecords":          []map[string]any{{"ipv4Address": "10.0.0.2"}},
		})
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testRecordSetNativeID, DesiredProperties: props})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRecordSetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _, _ string, _ armdns.RecordType, _ *armdns.RecordSetsClientDeleteOptions) (armdns.RecordSetsClientDeleteResponse, error) {
			return armdns.RecordSetsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testRecordSetNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List_by_zone", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "zoneName": "example-1.com"},
		})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("List_missing_params_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: map[string]string{}})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdns.RecordType, _ armdns.RecordSet, _ *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
			return armdns.RecordSetsClientCreateOrUpdateResponse{}, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: mkProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// TestDnsRecordSet_MarshalRoundTrip proves that A, CNAME and TXT record sets
// round-trip through build -> Azure -> serialize with zero drift: the desired
// type-specific properties are reproduced exactly on read-back.
func TestDnsRecordSet_MarshalRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		relName string
		recType armdns.RecordType
		desired map[string]any
		// azure is the RecordSetProperties Azure would return for the built params.
		azure *armdns.RecordSetProperties
	}{
		{
			name:    "A",
			relName: "www",
			recType: armdns.RecordTypeA,
			desired: map[string]any{
				"ttl":      float64(3600),
				"aRecords": []any{map[string]any{"ipv4Address": "10.0.0.1"}, map[string]any{"ipv4Address": "10.0.0.2"}},
			},
			azure: &armdns.RecordSetProperties{
				TTL:      to.Ptr[int64](3600),
				ARecords: []*armdns.ARecord{{IPv4Address: to.Ptr("10.0.0.1")}, {IPv4Address: to.Ptr("10.0.0.2")}},
			},
		},
		{
			name:    "CNAME",
			relName: "alias",
			recType: armdns.RecordTypeCNAME,
			desired: map[string]any{
				"ttl":   float64(300),
				"cname": "target.example.com",
			},
			azure: &armdns.RecordSetProperties{
				TTL:         to.Ptr[int64](300),
				CnameRecord: &armdns.CnameRecord{Cname: to.Ptr("target.example.com")},
			},
		},
		{
			name:    "TXT",
			relName: "@",
			recType: armdns.RecordTypeTXT,
			desired: map[string]any{
				"ttl":        float64(600),
				"txtRecords": []any{map[string]any{"value": []any{"v=spf1 -all"}}, map[string]any{"value": []any{"part-a", "part-b"}}},
			},
			azure: &armdns.RecordSetProperties{
				TTL: to.Ptr[int64](600),
				TxtRecords: []*armdns.TxtRecord{
					{Value: []*string{to.Ptr("v=spf1 -all")}},
					{Value: []*string{to.Ptr("part-a"), to.Ptr("part-b")}},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			props := map[string]any{
				"resourceGroupName": "rg-1",
				"zoneName":          "example-1.com",
				"name":              tc.relName,
				"recordType":        string(tc.recType),
			}
			for k, v := range tc.desired {
				props[k] = v
			}

			// Build the Azure request body from the desired props.
			params, recType, err := buildRecordSetParams(props)
			require.NoError(t, err)
			require.Equal(t, tc.recType, recType)

			// Simulate the Azure round-trip: Azure echoes the properties back
			// (with the read-only Name/ID/Type/Fqdn it assigns).
			echoed := armdns.RecordSet{
				ID:         to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnszones/example-1.com/" + string(tc.recType) + "/" + tc.relName),
				Name:       to.Ptr(tc.relName),
				Properties: tc.azure,
			}
			// The build must have produced the same type-specific body Azure echoes.
			require.Equal(t, tc.azure.ARecords, params.Properties.ARecords)
			require.Equal(t, tc.azure.CnameRecord, params.Properties.CnameRecord)
			require.Equal(t, tc.azure.TxtRecords, params.Properties.TxtRecords)
			require.Equal(t, tc.azure.TTL, params.Properties.TTL)

			raw, err := serializeDnsRecordSetProperties(echoed, "rg-1", "example-1.com", string(tc.recType), tc.relName)
			require.NoError(t, err)

			var got map[string]any
			require.NoError(t, json.Unmarshal(raw, &got))

			// TTL survives.
			require.EqualValues(t, tc.desired["ttl"], got["ttl"])
			// recordType survives.
			require.Equal(t, string(tc.recType), got["recordType"])

			// Type-specific fields round-trip exactly (zero drift).
			switch tc.recType {
			case armdns.RecordTypeA:
				require.Equal(t, tc.desired["aRecords"], got["aRecords"])
			case armdns.RecordTypeCNAME:
				require.Equal(t, tc.desired["cname"], got["cname"])
			case armdns.RecordTypeTXT:
				require.Equal(t, tc.desired["txtRecords"], got["txtRecords"])
			}
		})
	}
}

func TestDnsRecordSetIDParts(t *testing.T) {
	rg, zone, rt, name, err := dnsRecordSetIDParts(testRecordSetNativeID)
	require.NoError(t, err)
	require.Equal(t, "rg-1", rg)
	require.Equal(t, "example-1.com", zone)
	require.Equal(t, "A", rt)
	require.Equal(t, "www", name)

	// Apex TXT record with mixed-case zone segment.
	rg, zone, rt, name, err = dnsRecordSetIDParts("/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Network/dnsZones/z.example.com/TXT/@")
	require.NoError(t, err)
	require.Equal(t, "rg-2", rg)
	require.Equal(t, "z.example.com", zone)
	require.Equal(t, "TXT", rt)
	require.Equal(t, "@", name)
}

// --- Test helpers ---

func newTestDnsRecordSet(api recordSetsAPI) *DnsRecordSet {
	return &DnsRecordSet{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeRecordSetsAPI struct {
	createOrUpdateFn        func(ctx context.Context, rgName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, params armdns.RecordSet, opts *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error)
	getFn                   func(ctx context.Context, rgName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, opts *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error)
	deleteFn                func(ctx context.Context, rgName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, opts *armdns.RecordSetsClientDeleteOptions) (armdns.RecordSetsClientDeleteResponse, error)
	newListByDNSZonePagerFn func(rgName, zoneName string, opts *armdns.RecordSetsClientListByDNSZoneOptions) *runtime.Pager[armdns.RecordSetsClientListByDNSZoneResponse]
}

func (f *fakeRecordSetsAPI) CreateOrUpdate(ctx context.Context, rgName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, params armdns.RecordSet, opts *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
	return f.createOrUpdateFn(ctx, rgName, zoneName, relativeRecordSetName, recordType, params, opts)
}

func (f *fakeRecordSetsAPI) Get(ctx context.Context, rgName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, opts *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
	return f.getFn(ctx, rgName, zoneName, relativeRecordSetName, recordType, opts)
}

func (f *fakeRecordSetsAPI) Delete(ctx context.Context, rgName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, opts *armdns.RecordSetsClientDeleteOptions) (armdns.RecordSetsClientDeleteResponse, error) {
	return f.deleteFn(ctx, rgName, zoneName, relativeRecordSetName, recordType, opts)
}

func (f *fakeRecordSetsAPI) NewListByDNSZonePager(rgName, zoneName string, opts *armdns.RecordSetsClientListByDNSZoneOptions) *runtime.Pager[armdns.RecordSetsClientListByDNSZoneResponse] {
	return f.newListByDNSZonePagerFn(rgName, zoneName, opts)
}
