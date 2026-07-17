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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testAGWNativeID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/applicationGateways/agw-1"
const testAGWPipID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/publicIPAddresses/pip-1"
const testAGWSubnetID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/agw-subnet"
const testAGWUAIID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uai-1"

// fullAGWProps is a maximal, cross-referencing property map used by both the
// round-trip test and the CRUD test. Every child-ID reference (listener→port/
// frontendIP/sslCert, rule→listener/pool/settings, settings→probe) is exercised.
func fullAGWProps() map[string]any {
	return map[string]any{
		"resourceGroupName": "rg-1",
		"name":              "agw-1",
		"location":          "eastus",
		"sku":               map[string]any{"name": "Standard_v2", "tier": "Standard_v2", "capacity": 2},
		"gatewayIPConfigurations": []map[string]any{
			{"name": "gwip", "subnetId": testAGWSubnetID},
		},
		"frontendIPConfigurations": []map[string]any{
			{"name": "feip-public", "publicIPAddressId": testAGWPipID},
			{"name": "feip-private", "subnetId": testAGWSubnetID, "privateIPAddress": "10.0.1.10"},
		},
		"frontendPorts": []map[string]any{
			{"name": "https", "port": 443},
		},
		"backendAddressPools": []map[string]any{
			{"name": "agent-pool", "backendAddresses": []map[string]any{
				{"ipAddress": "10.0.2.4"},
				{"fqdn": "backend.example.com"},
			}},
		},
		"backendHttpSettingsCollection": []map[string]any{
			{"name": "agent-http", "port": 49684, "protocol": "Http", "probeName": "health", "requestTimeout": 30, "cookieBasedAffinity": "Disabled"},
		},
		"httpListeners": []map[string]any{
			{"name": "l443", "frontendIPConfigurationName": "feip-public", "frontendPortName": "https", "protocol": "Https", "sslCertificateName": "cert", "hostName": "app.example.com"},
		},
		"requestRoutingRules": []map[string]any{
			{"name": "r1", "ruleType": "Basic", "priority": 100, "httpListenerName": "l443", "backendAddressPoolName": "agent-pool", "backendHTTPSettingsName": "agent-http"},
		},
		"probes": []map[string]any{
			{"name": "health", "protocol": "Http", "path": "/api/v1/health", "host": "app.example.com", "interval": 30, "timeout": 30, "unhealthyThreshold": 3, "port": 49684},
		},
		"sslCertificates": []map[string]any{
			{"name": "cert", "data": "TUlJQkFTRQ==", "password": "s3cr3t"},
		},
		"identity": map[string]any{
			"type":                    "UserAssigned",
			"userAssignedIdentityIds": []any{testAGWUAIID},
		},
	}
}

func createAGWProps() json.RawMessage {
	props, _ := json.Marshal(fullAGWProps())
	return props
}

// TestApplicationGateway_MarshallerRoundTrip is the correctness gate for the two
// bespoke marshallers. It builds an armnetwork.ApplicationGateway from a full
// property map, then serializes it back, asserting every child-ID reference
// normalizes to its bare name and structural fields survive. If child-ID build
// and read-back normalization ever diverge, re-apply drifts and this test fails.
func TestApplicationGateway_MarshallerRoundTrip(t *testing.T) {
	gw := newTestApplicationGateway(nil)
	// Normalize through JSON so slices/objects arrive as []any/map[string]any,
	// exactly as they do from request.Properties in Create/Update.
	var props map[string]any
	require.NoError(t, json.Unmarshal(createAGWProps(), &props))

	params, err := gw.buildApplicationGatewayParams(props, "rg-1", "agw-1", "eastus")
	require.NoError(t, err)
	// Azure assigns the top-level ID; simulate it so serialize populates props["id"].
	params.ID = to.Ptr(testAGWNativeID)

	raw, err := serializeApplicationGatewayProperties(params, "rg-1", "agw-1")
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))

	require.Equal(t, "agw-1", got["name"])
	require.Equal(t, "eastus", got["location"])
	require.Equal(t, testAGWNativeID, got["id"])

	sku := got["sku"].(map[string]any)
	require.Equal(t, "Standard_v2", sku["name"])
	require.Equal(t, "Standard_v2", sku["tier"])
	require.EqualValues(t, 2, sku["capacity"])

	gwip := got["gatewayIPConfigurations"].([]any)
	require.Len(t, gwip, 1)
	require.Equal(t, testAGWSubnetID, gwip[0].(map[string]any)["subnetId"])

	feips := got["frontendIPConfigurations"].([]any)
	require.Len(t, feips, 2)
	pub := feips[0].(map[string]any)
	require.Equal(t, "feip-public", pub["name"])
	require.Equal(t, testAGWPipID, pub["publicIPAddressId"])
	priv := feips[1].(map[string]any)
	require.Equal(t, "feip-private", priv["name"])
	require.Equal(t, testAGWSubnetID, priv["subnetId"])
	require.Equal(t, "10.0.1.10", priv["privateIPAddress"])

	ports := got["frontendPorts"].([]any)
	require.EqualValues(t, 443, ports[0].(map[string]any)["port"])

	pool := got["backendAddressPools"].([]any)[0].(map[string]any)
	require.Equal(t, "agent-pool", pool["name"])
	addrs := pool["backendAddresses"].([]any)
	require.Len(t, addrs, 2)
	require.Equal(t, "10.0.2.4", addrs[0].(map[string]any)["ipAddress"])
	require.Equal(t, "backend.example.com", addrs[1].(map[string]any)["fqdn"])

	settings := got["backendHttpSettingsCollection"].([]any)[0].(map[string]any)
	require.Equal(t, "agent-http", settings["name"])
	require.EqualValues(t, 49684, settings["port"])
	require.Equal(t, "Http", settings["protocol"])
	require.Equal(t, "health", settings["probeName"], "probe ref must normalize back to name")
	require.EqualValues(t, 30, settings["requestTimeout"])
	require.Equal(t, "Disabled", settings["cookieBasedAffinity"])

	listener := got["httpListeners"].([]any)[0].(map[string]any)
	require.Equal(t, "l443", listener["name"])
	require.Equal(t, "feip-public", listener["frontendIPConfigurationName"], "frontendIP ref must normalize back to name")
	require.Equal(t, "https", listener["frontendPortName"], "frontendPort ref must normalize back to name")
	require.Equal(t, "Https", listener["protocol"])
	require.Equal(t, "cert", listener["sslCertificateName"], "sslCert ref must normalize back to name")
	require.Equal(t, "app.example.com", listener["hostName"])

	rule := got["requestRoutingRules"].([]any)[0].(map[string]any)
	require.Equal(t, "r1", rule["name"])
	require.Equal(t, "Basic", rule["ruleType"])
	require.EqualValues(t, 100, rule["priority"])
	require.Equal(t, "l443", rule["httpListenerName"], "listener ref must normalize back to name")
	require.Equal(t, "agent-pool", rule["backendAddressPoolName"], "pool ref must normalize back to name")
	require.Equal(t, "agent-http", rule["backendHTTPSettingsName"], "settings ref must normalize back to name")

	probe := got["probes"].([]any)[0].(map[string]any)
	require.Equal(t, "health", probe["name"])
	require.Equal(t, "Http", probe["protocol"])
	require.Equal(t, "/api/v1/health", probe["path"])
	require.Equal(t, "app.example.com", probe["host"])
	require.EqualValues(t, 30, probe["interval"])
	require.EqualValues(t, 30, probe["timeout"])
	require.EqualValues(t, 3, probe["unhealthyThreshold"])
	require.EqualValues(t, 49684, probe["port"])

	// SSL cert name round-trips; data/password are write-only and never read back.
	cert := got["sslCertificates"].([]any)[0].(map[string]any)
	require.Equal(t, "cert", cert["name"])
	require.Nil(t, cert["data"], "PFX data must not surface in serialized state")
	require.Nil(t, cert["password"], "PFX password must not surface in serialized state")

	identity := got["identity"].(map[string]any)
	require.Equal(t, "UserAssigned", identity["type"])
	ids := identity["userAssignedIdentityIds"].([]any)
	require.Len(t, ids, 1)
	require.Equal(t, testAGWUAIID, ids[0])
}

func TestApplicationGateway_CRUD(t *testing.T) {
	var builtProps map[string]any
	require.NoError(t, json.Unmarshal(createAGWProps(), &builtProps))
	built, err := (&ApplicationGateway{config: &config.Config{SubscriptionId: "sub-1"}}).
		buildApplicationGatewayParams(builtProps, "rg-1", "agw-1", "eastus")
	require.NoError(t, err)
	built.ID = to.Ptr(testAGWNativeID)
	built.Name = to.Ptr("agw-1")
	built.Location = to.Ptr("eastus")

	donePollerResult := armnetwork.ApplicationGatewaysClientCreateOrUpdateResponse{ApplicationGateway: built}

	fake := &fakeApplicationGatewaysAPI{
		beginCreateOrUpdateFn: func(_ context.Context, _, _ string, _ armnetwork.ApplicationGateway, _ *armnetwork.ApplicationGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationGatewaysClientCreateOrUpdateResponse], error) {
			return newDonePoller(donePollerResult), nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armnetwork.ApplicationGatewaysClientGetOptions) (armnetwork.ApplicationGatewaysClientGetResponse, error) {
			return armnetwork.ApplicationGatewaysClientGetResponse{ApplicationGateway: built}, nil
		},
		beginDeleteFn: func(_ context.Context, _, _ string, _ *armnetwork.ApplicationGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ApplicationGatewaysClientDeleteResponse], error) {
			return newInProgressPoller[armnetwork.ApplicationGatewaysClientDeleteResponse](), nil
		},
		newListAllPagerFn: func(_ *armnetwork.ApplicationGatewaysClientListAllOptions) *runtime.Pager[armnetwork.ApplicationGatewaysClientListAllResponse] {
			return runtime.NewPager(runtime.PagingHandler[armnetwork.ApplicationGatewaysClientListAllResponse]{
				More: func(_ armnetwork.ApplicationGatewaysClientListAllResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armnetwork.ApplicationGatewaysClientListAllResponse) (armnetwork.ApplicationGatewaysClientListAllResponse, error) {
					return armnetwork.ApplicationGatewaysClientListAllResponse{
						ApplicationGatewayListResult: armnetwork.ApplicationGatewayListResult{
							Value: []*armnetwork.ApplicationGateway{{ID: to.Ptr(testAGWNativeID)}},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestApplicationGateway(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createAGWProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAGWNativeID, got.ProgressResult.NativeID)

		var props map[string]any
		require.NoError(t, json.Unmarshal(got.ProgressResult.ResourceProperties, &props))
		require.Equal(t, "agw-1", props["name"])
		rules := props["requestRoutingRules"].([]any)
		require.Len(t, rules, 1)
		require.Equal(t, "l443", rules[0].(map[string]any)["httpListenerName"])
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAGWNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "agw-1", props["name"])
	})

	t.Run("Update", func(t *testing.T) {
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{NativeID: testAGWNativeID, DesiredProperties: createAGWProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete", func(t *testing.T) {
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAGWNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.beginDeleteFn = func(_ context.Context, _, _ string, _ *armnetwork.ApplicationGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ApplicationGatewaysClientDeleteResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAGWNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("List", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{AdditionalProperties: map[string]string{}})
		require.NoError(t, err)
		require.Len(t, got.NativeIDs, 1)
	})

	t.Run("Azure_error_maps_to_failure", func(t *testing.T) {
		fake.beginCreateOrUpdateFn = func(_ context.Context, _, _ string, _ armnetwork.ApplicationGateway, _ *armnetwork.ApplicationGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationGatewaysClientCreateOrUpdateResponse], error) {
			return nil, &azcore.ResponseError{StatusCode: 403}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: createAGWProps()})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
	})
}

// --- Test helpers ---

func newTestApplicationGateway(api applicationGatewaysAPI) *ApplicationGateway {
	return &ApplicationGateway{api: api, config: &config.Config{SubscriptionId: "sub-1"}}
}

type fakeApplicationGatewaysAPI struct {
	beginCreateOrUpdateFn func(ctx context.Context, rgName, gwName string, params armnetwork.ApplicationGateway, opts *armnetwork.ApplicationGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationGatewaysClientCreateOrUpdateResponse], error)
	getFn                 func(ctx context.Context, rgName, gwName string, opts *armnetwork.ApplicationGatewaysClientGetOptions) (armnetwork.ApplicationGatewaysClientGetResponse, error)
	beginDeleteFn         func(ctx context.Context, rgName, gwName string, opts *armnetwork.ApplicationGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ApplicationGatewaysClientDeleteResponse], error)
	newListPagerFn        func(rgName string, opts *armnetwork.ApplicationGatewaysClientListOptions) *runtime.Pager[armnetwork.ApplicationGatewaysClientListResponse]
	newListAllPagerFn     func(opts *armnetwork.ApplicationGatewaysClientListAllOptions) *runtime.Pager[armnetwork.ApplicationGatewaysClientListAllResponse]
}

func (f *fakeApplicationGatewaysAPI) BeginCreateOrUpdate(ctx context.Context, rgName, gwName string, params armnetwork.ApplicationGateway, opts *armnetwork.ApplicationGatewaysClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.ApplicationGatewaysClientCreateOrUpdateResponse], error) {
	return f.beginCreateOrUpdateFn(ctx, rgName, gwName, params, opts)
}

func (f *fakeApplicationGatewaysAPI) Get(ctx context.Context, rgName, gwName string, opts *armnetwork.ApplicationGatewaysClientGetOptions) (armnetwork.ApplicationGatewaysClientGetResponse, error) {
	return f.getFn(ctx, rgName, gwName, opts)
}

func (f *fakeApplicationGatewaysAPI) BeginDelete(ctx context.Context, rgName, gwName string, opts *armnetwork.ApplicationGatewaysClientBeginDeleteOptions) (*runtime.Poller[armnetwork.ApplicationGatewaysClientDeleteResponse], error) {
	return f.beginDeleteFn(ctx, rgName, gwName, opts)
}

func (f *fakeApplicationGatewaysAPI) NewListPager(rgName string, opts *armnetwork.ApplicationGatewaysClientListOptions) *runtime.Pager[armnetwork.ApplicationGatewaysClientListResponse] {
	return f.newListPagerFn(rgName, opts)
}

func (f *fakeApplicationGatewaysAPI) NewListAllPager(opts *armnetwork.ApplicationGatewaysClientListAllOptions) *runtime.Pager[armnetwork.ApplicationGatewaysClientListAllResponse] {
	return f.newListAllPagerFn(opts)
}
