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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const testDCRATargetResourceID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm1"

const testDCRARuleID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/dataCollectionRules/dcr1"

const testDCRAEndpointID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/dataCollectionEndpoints/dce1"

const testDCRANativeID = testDCRATargetResourceID + "/providers/Microsoft.Insights/dataCollectionRuleAssociations/assoc1"

type fakeDataCollectionRuleAssociationsAPI struct {
	createFn     func(ctx context.Context, resourceURI, name string, body armmonitor.DataCollectionRuleAssociationProxyOnlyResource, options *armmonitor.DataCollectionRuleAssociationsClientCreateOptions) (armmonitor.DataCollectionRuleAssociationsClientCreateResponse, error)
	getFn        func(ctx context.Context, resourceURI, name string, options *armmonitor.DataCollectionRuleAssociationsClientGetOptions) (armmonitor.DataCollectionRuleAssociationsClientGetResponse, error)
	deleteFn     func(ctx context.Context, resourceURI, name string, options *armmonitor.DataCollectionRuleAssociationsClientDeleteOptions) (armmonitor.DataCollectionRuleAssociationsClientDeleteResponse, error)
	listByRuleFn func(rgName, ruleName string, options *armmonitor.DataCollectionRuleAssociationsClientListByRuleOptions) *runtime.Pager[armmonitor.DataCollectionRuleAssociationsClientListByRuleResponse]
}

func (f *fakeDataCollectionRuleAssociationsAPI) Create(ctx context.Context, resourceURI, name string, body armmonitor.DataCollectionRuleAssociationProxyOnlyResource, options *armmonitor.DataCollectionRuleAssociationsClientCreateOptions) (armmonitor.DataCollectionRuleAssociationsClientCreateResponse, error) {
	return f.createFn(ctx, resourceURI, name, body, options)
}

func (f *fakeDataCollectionRuleAssociationsAPI) Get(ctx context.Context, resourceURI, name string, options *armmonitor.DataCollectionRuleAssociationsClientGetOptions) (armmonitor.DataCollectionRuleAssociationsClientGetResponse, error) {
	return f.getFn(ctx, resourceURI, name, options)
}

func (f *fakeDataCollectionRuleAssociationsAPI) Delete(ctx context.Context, resourceURI, name string, options *armmonitor.DataCollectionRuleAssociationsClientDeleteOptions) (armmonitor.DataCollectionRuleAssociationsClientDeleteResponse, error) {
	return f.deleteFn(ctx, resourceURI, name, options)
}

func (f *fakeDataCollectionRuleAssociationsAPI) NewListByRulePager(rgName, ruleName string, options *armmonitor.DataCollectionRuleAssociationsClientListByRuleOptions) *runtime.Pager[armmonitor.DataCollectionRuleAssociationsClientListByRuleResponse] {
	return f.listByRuleFn(rgName, ruleName, options)
}

func newTestDataCollectionRuleAssociation(api monitorDataCollectionRuleAssociationsAPI) *MonitorDataCollectionRuleAssociation {
	return &MonitorDataCollectionRuleAssociation{
		api:    api,
		config: &config.Config{SubscriptionId: "sub-1"},
	}
}

func dataCollectionRuleAssociationDesired(description string) []byte {
	out, _ := json.Marshal(map[string]any{
		"name":                 "assoc1",
		"targetResourceId":     testDCRATargetResourceID,
		"dataCollectionRuleId": testDCRARuleID,
		"description":          description,
	})
	return out
}

func TestMonitorDataCollectionRuleAssociation_CRUD(t *testing.T) {
	associationResult := armmonitor.DataCollectionRuleAssociationProxyOnlyResource{
		ID:   to.Ptr(testDCRANativeID),
		Name: to.Ptr("assoc1"),
		Type: to.Ptr("Microsoft.Insights/dataCollectionRuleAssociations"),
		Etag: to.Ptr("\"etag\""),
		Properties: &armmonitor.DataCollectionRuleAssociationProxyOnlyResourceProperties{
			DataCollectionRuleID: to.Ptr(testDCRARuleID),
			Description:          to.Ptr("conformance test association"),
			ProvisioningState:    to.Ptr(armmonitor.KnownDataCollectionRuleAssociationProvisioningStateSucceeded),
			Metadata: &armmonitor.DataCollectionRuleAssociationMetadata{
				ProvisionedBy: to.Ptr("someAzureOffering"),
			},
		},
	}

	var sent armmonitor.DataCollectionRuleAssociationProxyOnlyResource
	var sentResourceURI string
	var sentName string
	writeCalls := 0
	deleteCalls := 0
	fake := &fakeDataCollectionRuleAssociationsAPI{
		createFn: func(_ context.Context, resourceURI, name string, body armmonitor.DataCollectionRuleAssociationProxyOnlyResource, _ *armmonitor.DataCollectionRuleAssociationsClientCreateOptions) (armmonitor.DataCollectionRuleAssociationsClientCreateResponse, error) {
			sentResourceURI = resourceURI
			sentName = name
			sent = body
			writeCalls++
			return armmonitor.DataCollectionRuleAssociationsClientCreateResponse{DataCollectionRuleAssociationProxyOnlyResource: associationResult}, nil
		},
		getFn: func(_ context.Context, _, _ string, _ *armmonitor.DataCollectionRuleAssociationsClientGetOptions) (armmonitor.DataCollectionRuleAssociationsClientGetResponse, error) {
			return armmonitor.DataCollectionRuleAssociationsClientGetResponse{DataCollectionRuleAssociationProxyOnlyResource: associationResult}, nil
		},
		deleteFn: func(_ context.Context, _, _ string, _ *armmonitor.DataCollectionRuleAssociationsClientDeleteOptions) (armmonitor.DataCollectionRuleAssociationsClientDeleteResponse, error) {
			deleteCalls++
			return armmonitor.DataCollectionRuleAssociationsClientDeleteResponse{}, nil
		},
		listByRuleFn: func(rgName, ruleName string, _ *armmonitor.DataCollectionRuleAssociationsClientListByRuleOptions) *runtime.Pager[armmonitor.DataCollectionRuleAssociationsClientListByRuleResponse] {
			require.Equal(t, "rg-1", rgName)
			require.Equal(t, "dcr1", ruleName)
			return runtime.NewPager(runtime.PagingHandler[armmonitor.DataCollectionRuleAssociationsClientListByRuleResponse]{
				More: func(_ armmonitor.DataCollectionRuleAssociationsClientListByRuleResponse) bool { return false },
				Fetcher: func(_ context.Context, _ *armmonitor.DataCollectionRuleAssociationsClientListByRuleResponse) (armmonitor.DataCollectionRuleAssociationsClientListByRuleResponse, error) {
					return armmonitor.DataCollectionRuleAssociationsClientListByRuleResponse{
						DataCollectionRuleAssociationProxyOnlyResourceListResult: armmonitor.DataCollectionRuleAssociationProxyOnlyResourceListResult{
							Value: []*armmonitor.DataCollectionRuleAssociationProxyOnlyResource{
								{ID: to.Ptr(testDCRANativeID)},
							},
						},
					}, nil
				},
			})
		},
	}
	prov := newTestDataCollectionRuleAssociation(fake)

	t.Run("Create", func(t *testing.T) {
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "assoc1", Properties: dataCollectionRuleAssociationDesired("conformance test association"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, testDCRANativeID, got.ProgressResult.NativeID)

		// The write is scope-based: the target's ARM id is the request path.
		require.Equal(t, testDCRATargetResourceID, sentResourceURI)
		require.Equal(t, "assoc1", sentName)
		require.Equal(t, testDCRARuleID, *sent.Properties.DataCollectionRuleID)
		require.Nil(t, sent.Properties.DataCollectionEndpointID)
		require.Equal(t, "conformance test association", *sent.Properties.Description)
	})

	t.Run("Create_accepts_an_endpoint_instead_of_a_rule", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name":                     "configurationAccessEndpoint",
			"targetResourceId":         testDCRATargetResourceID,
			"dataCollectionEndpointId": testDCRAEndpointID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.NoError(t, err)
		require.Equal(t, testDCRAEndpointID, *sent.Properties.DataCollectionEndpointID)
		require.Nil(t, sent.Properties.DataCollectionRuleID)
	})

	t.Run("Create_requires_a_target", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "assoc1", "dataCollectionRuleId": testDCRARuleID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "targetResourceId is required")
	})

	t.Run("Create_requires_a_rule_or_an_endpoint", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name": "assoc1", "targetResourceId": testDCRATargetResourceID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "one of dataCollectionRuleId or dataCollectionEndpointId is required")
	})

	t.Run("Create_rejects_both_a_rule_and_an_endpoint", func(t *testing.T) {
		props, _ := json.Marshal(map[string]any{
			"name":                     "assoc1",
			"targetResourceId":         testDCRATargetResourceID,
			"dataCollectionRuleId":     testDCRARuleID,
			"dataCollectionEndpointId": testDCRAEndpointID,
		})
		_, err := prov.Create(context.Background(), &resource.CreateRequest{Properties: props})
		require.ErrorContains(t, err, "mutually exclusive")
	})

	t.Run("Create_failure_carries_the_provider_error", func(t *testing.T) {
		fake.createFn = func(_ context.Context, _, _ string, _ armmonitor.DataCollectionRuleAssociationProxyOnlyResource, _ *armmonitor.DataCollectionRuleAssociationsClientCreateOptions) (armmonitor.DataCollectionRuleAssociationsClientCreateResponse, error) {
			return armmonitor.DataCollectionRuleAssociationsClientCreateResponse{}, &azcore.ResponseError{
				StatusCode: 400, ErrorCode: "InvalidResourceType",
			}
		}
		got, err := prov.Create(context.Background(), &resource.CreateRequest{
			Label: "assoc1", Properties: dataCollectionRuleAssociationDesired("conformance test association"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		// A target ARM will not attach a rule to is the failure mode worth naming.
		require.Contains(t, got.ProgressResult.StatusMessage, "InvalidResourceType")
	})

	t.Run("Read", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDCRANativeID})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)

		var props map[string]any
		require.NoError(t, json.Unmarshal([]byte(got.Properties), &props))
		require.Equal(t, "assoc1", props["name"])
		require.Equal(t, testDCRATargetResourceID, props["targetResourceId"])
		require.Equal(t, testDCRARuleID, props["dataCollectionRuleId"])
		require.Equal(t, "conformance test association", props["description"])
	})

	t.Run("Read_drops_service_state", func(t *testing.T) {
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDCRANativeID})
		require.NoError(t, err)
		for _, key := range []string{"provisioningState", "metadata", "etag", "systemData"} {
			require.NotContains(t, got.Properties, key)
		}
	})

	// ARM echoes the provider segment back lowercased on some responses, so the id
	// split has to be case-insensitive.
	t.Run("Read_accepts_a_lowercased_provider_segment", func(t *testing.T) {
		lowercased := testDCRATargetResourceID + "/providers/microsoft.insights/datacollectionruleassociations/assoc1"
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: lowercased})
		require.NoError(t, err)
		require.Empty(t, got.ErrorCode)
	})

	t.Run("Read_rejects_an_id_that_is_not_an_association", func(t *testing.T) {
		_, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDCRATargetResourceID})
		require.ErrorContains(t, err, "invalid data collection rule association id")
	})

	t.Run("Update_reissues_create", func(t *testing.T) {
		fake.createFn = func(_ context.Context, resourceURI, _ string, body armmonitor.DataCollectionRuleAssociationProxyOnlyResource, _ *armmonitor.DataCollectionRuleAssociationsClientCreateOptions) (armmonitor.DataCollectionRuleAssociationsClientCreateResponse, error) {
			sentResourceURI = resourceURI
			sent = body
			writeCalls++
			return armmonitor.DataCollectionRuleAssociationsClientCreateResponse{DataCollectionRuleAssociationProxyOnlyResource: associationResult}, nil
		}
		before := writeCalls
		got, err := prov.Update(context.Background(), &resource.UpdateRequest{
			NativeID:          testDCRANativeID,
			DesiredProperties: dataCollectionRuleAssociationDesired("conformance test association, revised"),
		})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, writeCalls)
		require.Equal(t, testDCRANativeID, got.ProgressResult.NativeID)
		require.Equal(t, "conformance test association, revised", *sent.Properties.Description)
	})

	t.Run("Delete", func(t *testing.T) {
		before := deleteCalls
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDCRANativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, before+1, deleteCalls)
	})

	t.Run("Delete_NotFound_is_success", func(t *testing.T) {
		fake.deleteFn = func(_ context.Context, _, _ string, _ *armmonitor.DataCollectionRuleAssociationsClientDeleteOptions) (armmonitor.DataCollectionRuleAssociationsClientDeleteResponse, error) {
			return armmonitor.DataCollectionRuleAssociationsClientDeleteResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Delete(context.Background(), &resource.DeleteRequest{NativeID: testDCRANativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	t.Run("Status_is_always_success", func(t *testing.T) {
		got, err := prov.Status(context.Background(), &resource.StatusRequest{RequestID: "whatever"})
		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
	})

	// Discovery arrives through the data collection rule parent, which is the only
	// listing this type uses: ARM's per-endpoint and per-target-resource listings
	// have no parent chain to supply their scope.
	t.Run("List_by_rule", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{
				"resourceGroupName": "rg-1", "dataCollectionRuleName": "dcr1",
			},
		})
		require.NoError(t, err)
		require.Equal(t, []string{testDCRANativeID}, got.NativeIDs)
	})

	// There is no subscription-wide listing for the type, so an unscoped List has
	// nothing to walk and must return empty rather than calling the pager with a
	// blank scope.
	t.Run("List_without_a_scope_is_empty", func(t *testing.T) {
		got, err := prov.List(context.Background(), &resource.ListRequest{})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)

		got, err = prov.List(context.Background(), &resource.ListRequest{
			AdditionalProperties: map[string]string{"resourceGroupName": "rg-1"},
		})
		require.NoError(t, err)
		require.Empty(t, got.NativeIDs)
	})

	t.Run("Read_NotFound", func(t *testing.T) {
		fake.getFn = func(_ context.Context, _, _ string, _ *armmonitor.DataCollectionRuleAssociationsClientGetOptions) (armmonitor.DataCollectionRuleAssociationsClientGetResponse, error) {
			return armmonitor.DataCollectionRuleAssociationsClientGetResponse{}, &azcore.ResponseError{StatusCode: 404}
		}
		got, err := prov.Read(context.Background(), &resource.ReadRequest{NativeID: testDCRANativeID})
		require.NoError(t, err)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
	})
}
