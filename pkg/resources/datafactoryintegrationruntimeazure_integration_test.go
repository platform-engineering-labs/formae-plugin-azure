// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

func newTestAzureIR(api dataFactoryIntegrationRuntimesAPI) *DataFactoryIntegrationRuntimeAzure {
	return &DataFactoryIntegrationRuntimeAzure{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func azureIRDesired(overrides map[string]any) []byte {
	props := map[string]any{
		"name":                "azir-1",
		"resourceGroupName":   "rg-1",
		"factoryName":         "adf-1",
		"description":         "managed copy runtime",
		"computeLocation":     "AutoResolve",
		"dataFlowComputeType": "General",
		"dataFlowCoreCount":   8,
		"dataFlowTimeToLive":  10,
	}
	for k, v := range overrides {
		if v == nil {
			delete(props, k)
			continue
		}
		props[k] = v
	}
	out, _ := json.Marshal(props)
	return out
}

func TestDataFactoryIntegrationRuntimeAzure_CRUD(t *testing.T) {
	irResult := armdatafactory.IntegrationRuntimeResource{
		ID:   to.Ptr(testAzureIRNativeID),
		Name: to.Ptr("azir-1"),
		Properties: &armdatafactory.ManagedIntegrationRuntime{
			Type:        to.Ptr(armdatafactory.IntegrationRuntimeTypeManaged),
			Description: to.Ptr("managed copy runtime"),
			// State is service state and must not be read back.
			State: to.Ptr(armdatafactory.IntegrationRuntimeStateStarted),
			TypeProperties: &armdatafactory.ManagedIntegrationRuntimeTypeProperties{
				ComputeProperties: &armdatafactory.IntegrationRuntimeComputeProperties{
					Location: to.Ptr("AutoResolve"),
					DataFlowProperties: &armdatafactory.IntegrationRuntimeDataFlowProperties{
						ComputeType: to.Ptr(armdatafactory.DataFlowComputeTypeGeneral),
						CoreCount:   to.Ptr(int32(8)),
						TimeToLive:  to.Ptr(int32(10)),
					},
				},
			},
		},
	}

	var sent armdatafactory.IntegrationRuntimeResource
	var sawRG, sawFactory, sawName string
	createCalls := 0
	deleteCalls := 0
	fake := newFakeIntegrationRuntimesAPI(irResult, &sent, &sawRG, &sawFactory, &sawName, &createCalls, &deleteCalls)
	prov := newTestAzureIR(fake)

	t.Run("Create_is_synchronous", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label:      "azir-1",
			Properties: azureIRDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testAzureIRNativeID, got.ProgressResult.NativeID)
		require.Empty(t, got.ProgressResult.RequestID)
		require.Equal(t, "adf-1", sawFactory)

		managed, ok := sent.Properties.(*armdatafactory.ManagedIntegrationRuntime)
		require.True(t, ok)
		require.Equal(t, armdatafactory.IntegrationRuntimeTypeManaged, *managed.Type)
		compute := managed.TypeProperties.ComputeProperties
		require.Equal(t, "AutoResolve", *compute.Location)
		require.Equal(t, armdatafactory.DataFlowComputeTypeGeneral, *compute.DataFlowProperties.ComputeType)
		require.Equal(t, int32(8), *compute.DataFlowProperties.CoreCount)
		require.Equal(t, int32(10), *compute.DataFlowProperties.TimeToLive)
	})

	// nodeSize and numberOfNodes are the Azure-SSIS half of ARM's shape: sending
	// either turns the runtime into a dedicated cluster that bills per node-hour.
	// This provisioner must never send them, whatever is in the payload.
	t.Run("Create_never_sends_ssis_node_fields", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "azir-1",
			Properties: azureIRDesired(map[string]any{
				"nodeSize":      "Standard_D8_v3",
				"numberOfNodes": 4,
			}),
		})
		require.NoError(t, err)
		managed, ok := sent.Properties.(*armdatafactory.ManagedIntegrationRuntime)
		require.True(t, ok)
		compute := managed.TypeProperties.ComputeProperties
		require.Nil(t, compute.NodeSize)
		require.Nil(t, compute.NumberOfNodes)
		require.Nil(t, compute.MaxParallelExecutionsPerNode)
		require.Nil(t, managed.TypeProperties.SsisProperties)
	})

	// With nothing to put in computeProperties the block must be left out
	// entirely, so the service applies its own AutoResolve default rather than
	// receiving an empty object.
	t.Run("Create_without_compute_fields_omits_the_block", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"resourceGroupName": "rg-1", "factoryName": "adf-1", "name": "azir-1",
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		managed, ok := sent.Properties.(*armdatafactory.ManagedIntegrationRuntime)
		require.True(t, ok)
		require.NotNil(t, managed.TypeProperties)
		require.Nil(t, managed.TypeProperties.ComputeProperties)
	})

	t.Run("Create_requires_factory", func(t *testing.T) {
		_, err := prov.Create(context.Background(), &resource.CreateRequest{
			Properties: azureIRDesired(map[string]any{"factoryName": nil}),
		})
		require.ErrorContains(t, err, "factoryName is required")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAzureIRNativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "azir-1", props["name"])
		require.Equal(t, "rg-1", props["resourceGroupName"])
		require.Equal(t, "adf-1", props["factoryName"])
		require.Equal(t, "managed copy runtime", props["description"])
		require.Equal(t, "AutoResolve", props["computeLocation"])
		require.Equal(t, "General", props["dataFlowComputeType"])
		require.Equal(t, float64(8), props["dataFlowCoreCount"])
		require.Equal(t, float64(10), props["dataFlowTimeToLive"])
	})

	// state moves on its own (Starting / Started / Stopped) and is not desired
	// state, so it must not reach the property set.
	t.Run("Read_drops_runtime_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testAzureIRNativeID})
		require.NoError(t, err)
		require.NotContains(t, got.Properties, "state")
	})

	// ARM accepts "eastus" and hands back "East US"; passing that through would
	// report drift on every sync. AutoResolve must survive untouched, which a
	// blanket fold would not manage.
	t.Run("Read_normalizes_a_region_but_not_AutoResolve", func(t *testing.T) {
		require.Equal(t, "AutoResolve", dataFactoryNormalizeComputeLocation("AutoResolve"))
		require.Equal(t, "AutoResolve", dataFactoryNormalizeComputeLocation("autoresolve"))
		require.Equal(t, "eastus", dataFactoryNormalizeComputeLocation("East US"))
		require.Equal(t, "eastus", dataFactoryNormalizeComputeLocation("eastus"))
	})

	t.Run("Update_reissues_create_or_update", func(t *testing.T) {
		before := createCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testAzureIRNativeID,
			DesiredProperties: azureIRDesired(map[string]any{"dataFlowTimeToLive": 30}),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, createCalls)
		managed, ok := sent.Properties.(*armdatafactory.ManagedIntegrationRuntime)
		require.True(t, ok)
		require.Equal(t, int32(30), *managed.TypeProperties.ComputeProperties.DataFlowProperties.TimeToLive)
	})

	t.Run("Delete_is_synchronous", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testAzureIRNativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	// The counterpart of the self-hosted filter: one pager, two kinds, and only
	// the managed ones belong to this provisioner.
	t.Run("List_keeps_only_managed", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1", "factoryName": "adf-1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testAzureIRNativeID}, got.NativeIDs)
	})

	t.Run("List_without_parents_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Azure_error_maps_to_failure_with_reason", func(t *testing.T) {
		fake.createOrUpdateFn = func(_ context.Context, _, _, _ string, _ armdatafactory.IntegrationRuntimeResource, _ *armdatafactory.IntegrationRuntimesClientCreateOrUpdateOptions) (armdatafactory.IntegrationRuntimesClientCreateOrUpdateResponse, error) {
			return armdatafactory.IntegrationRuntimesClientCreateOrUpdateResponse{},
				&azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "azir-1", Properties: azureIRDesired(nil),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
		require.Contains(t, got.ProgressResult.StatusMessage, "AuthorizationFailed")
	})
}

// A self-hosted runtime read through the Azure provisioner must degrade to the
// shared fields rather than panicking on the type assertion.
func TestDataFactoryIntegrationRuntimeAzure_ReadOfWrongKindIsSafe(t *testing.T) {
	fake := &fakeIntegrationRuntimesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.IntegrationRuntimesClientGetOptions) (armdatafactory.IntegrationRuntimesClientGetResponse, error) {
			return armdatafactory.IntegrationRuntimesClientGetResponse{
				IntegrationRuntimeResource: armdatafactory.IntegrationRuntimeResource{
					ID:   to.Ptr(testAzureIRNativeID),
					Name: to.Ptr("azir-1"),
					Properties: &armdatafactory.SelfHostedIntegrationRuntime{
						Type: to.Ptr(armdatafactory.IntegrationRuntimeTypeSelfHosted),
					},
				},
			}, nil
		},
	}
	got, err := newTestAzureIR(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testAzureIRNativeID})
	require.NoError(t, err)
	require.NotContains(t, got.Properties, "computeLocation")
}

func TestDataFactoryIntegrationRuntimeAzure_ReadNotFound(t *testing.T) {
	fake := &fakeIntegrationRuntimesAPI{
		getFn: func(_ context.Context, _, _, _ string, _ *armdatafactory.IntegrationRuntimesClientGetOptions) (armdatafactory.IntegrationRuntimesClientGetResponse, error) {
			return armdatafactory.IntegrationRuntimesClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		},
	}
	got, err := newTestAzureIR(fake).Read(context.Background(), &resource.ReadRequest{NativeID: testAzureIRNativeID})
	require.NoError(t, err)
	require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
}

func TestDataFactoryIntegrationRuntimeAzure_StatusIsAlwaysDone(t *testing.T) {
	got, err := newTestAzureIR(&fakeIntegrationRuntimesAPI{}).
		Status(context.Background(), &resource.StatusRequest{RequestID: "anything"})
	require.NoError(t, err)
	require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
}
