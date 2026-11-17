// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package resources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae/pkg/plugin"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

const unsupportedAPIMTierCode = "MethodNotAllowedInPricingTier"

var apiManagementListKinds = []string{"User", "Group", "Gateway"}

type apiManagementListStep struct {
	nativeIDs []string
	err       error
}

type apiManagementListSubject struct {
	list       func(context.Context, *resource.ListRequest) (*resource.ListResult, error)
	pagerCalls *int
	pageCalls  *int
}

func unsupportedAPIMTierError() *azcore.ResponseError {
	return &azcore.ResponseError{StatusCode: 400, ErrorCode: unsupportedAPIMTierCode}
}

// TestApiManagementTierUnsupportedFirstPageIsEmpty catches treating a provider's
// exact unsupported-tier result as a discovery failure. It exercises all three
// public List entrypoints and requires errors.As-compatible wrapping.
func TestApiManagementTierUnsupportedFirstPageIsEmpty(t *testing.T) {
	errorCases := []struct {
		name string
		err  func() error
	}{
		{name: "exact", err: func() error { return unsupportedAPIMTierError() }},
		{name: "wrapped", err: func() error {
			return fmt.Errorf("Azure pager: %w", unsupportedAPIMTierError())
		}},
	}

	for _, kind := range apiManagementListKinds {
		for _, errorCase := range errorCases {
			t.Run(kind+"/"+errorCase.name, func(t *testing.T) {
				subject := newApiManagementListSubject(t, kind, []apiManagementListStep{{err: errorCase.err()}})

				ctx, logs := apiManagementTierLogContext()
				got, err := subject.list(ctx, apiManagementListRequest("rg-test", "apim-test"))

				var event map[string]any
				require.NoError(t, json.Unmarshal(logs.Bytes(), &event), "expected one typed tier-skip DEBUG event")
				delete(event, "time")
				require.Equal(t, map[string]any{
					"level":             "DEBUG",
					"msg":               "List skipped: API Management collection unavailable in pricing tier",
					"resourceType":      "AZURE::ApiManagement::" + kind,
					"resourceGroupName": "rg-test",
					"serviceName":       "apim-test",
					"statusCode":        float64(400),
					"errorCode":         "MethodNotAllowedInPricingTier",
					"successfulPages":   float64(0),
				}, event)
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Empty(t, got.NativeIDs)
				require.Nil(t, got.NextPageToken)
				require.Equal(t, 1, *subject.pagerCalls)
				require.Equal(t, 1, *subject.pageCalls)
			})
		}
	}
}

// TestApiManagementTierNonMatchingListErrorsRemainErrors catches broad status,
// code, or message matching that would hide real provider failures.
func TestApiManagementTierNonMatchingListErrorsRemainErrors(t *testing.T) {
	errorCases := []struct {
		name string
		err  func() error
	}{
		{name: "generic_400", err: func() error { return &azcore.ResponseError{StatusCode: 400} }},
		{name: "other_400_code", err: func() error {
			return &azcore.ResponseError{StatusCode: 400, ErrorCode: "ValidationError"}
		}},
		{name: "same_code_403", err: func() error {
			return &azcore.ResponseError{StatusCode: 403, ErrorCode: unsupportedAPIMTierCode}
		}},
		{name: "same_code_404", err: func() error {
			return &azcore.ResponseError{StatusCode: 404, ErrorCode: unsupportedAPIMTierCode}
		}},
		{name: "same_code_429", err: func() error {
			return &azcore.ResponseError{StatusCode: 429, ErrorCode: unsupportedAPIMTierCode}
		}},
		{name: "same_code_500", err: func() error {
			return &azcore.ResponseError{StatusCode: 500, ErrorCode: unsupportedAPIMTierCode}
		}},
		{name: "matching_plain_text", err: func() error {
			return errors.New("provider said " + unsupportedAPIMTierCode)
		}},
	}

	for _, kind := range apiManagementListKinds {
		for _, errorCase := range errorCases {
			t.Run(kind+"/"+errorCase.name, func(t *testing.T) {
				providerErr := errorCase.err()
				subject := newApiManagementListSubject(t, kind, []apiManagementListStep{{err: providerErr}})

				ctx, logs := apiManagementTierLogContext()
				got, err := subject.list(ctx, apiManagementListRequest("rg-test", "apim-test"))

				require.Empty(t, logs.String())
				require.ErrorIs(t, err, providerErr)
				require.Nil(t, got)
				require.Equal(t, 1, *subject.pagerCalls)
				require.Equal(t, 1, *subject.pageCalls)
			})
		}
	}
}

// TestApiManagementTierUnsupportedAfterSuccessfulPageRemainsError catches
// discarding a partially observed collection, including when its first page is
// legitimately empty.
func TestApiManagementTierUnsupportedAfterSuccessfulPageRemainsError(t *testing.T) {
	firstPages := []struct {
		name      string
		nativeIDs []string
	}{
		{name: "populated", nativeIDs: []string{"/first-page/id"}},
		{name: "empty"},
	}

	for _, kind := range apiManagementListKinds {
		for _, firstPage := range firstPages {
			t.Run(kind+"/"+firstPage.name, func(t *testing.T) {
				providerErr := unsupportedAPIMTierError()
				subject := newApiManagementListSubject(t, kind, []apiManagementListStep{
					{nativeIDs: firstPage.nativeIDs},
					{err: providerErr},
				})

				ctx, logs := apiManagementTierLogContext()
				got, err := subject.list(ctx, apiManagementListRequest("rg-test", "apim-test"))

				require.Empty(t, logs.String())
				require.ErrorIs(t, err, providerErr)
				require.Nil(t, got)
				require.Equal(t, 2, *subject.pageCalls)
			})
		}
	}
}

// TestApiManagementTierSupportedMultiPageLists catches a capability-specific
// branch changing normal supported-tier pagination or result order.
func TestApiManagementTierSupportedMultiPageLists(t *testing.T) {
	for _, kind := range apiManagementListKinds {
		t.Run(kind, func(t *testing.T) {
			subject := newApiManagementListSubject(t, kind, []apiManagementListStep{
				{nativeIDs: []string{"/first/id", "/second/id"}},
				{nativeIDs: []string{"/third/id"}},
			})

			ctx, logs := apiManagementTierLogContext()
			got, err := subject.list(ctx, apiManagementListRequest("rg-test", "apim-test"))

			require.Empty(t, logs.String())
			require.NoError(t, err)
			require.Equal(t, []string{"/first/id", "/second/id", "/third/id"}, got.NativeIDs)
			require.Equal(t, 1, *subject.pagerCalls)
			require.Equal(t, 2, *subject.pageCalls)
		})
	}
}

// TestApiManagementTierMissingParentsDoNotCallListAPI catches attempting an
// unscoped ARM collection call when either required parent identifier is absent.
func TestApiManagementTierMissingParentsDoNotCallListAPI(t *testing.T) {
	requests := []struct {
		name string
		rg   string
		svc  string
	}{
		{name: "resource_group", svc: "apim-test"},
		{name: "service", rg: "rg-test"},
		{name: "both"},
	}

	for _, kind := range apiManagementListKinds {
		for _, requestCase := range requests {
			t.Run(kind+"/missing_"+requestCase.name, func(t *testing.T) {
				subject := newApiManagementListSubject(t, kind, nil)

				ctx, logs := apiManagementTierLogContext()
				got, err := subject.list(ctx, apiManagementListRequest(requestCase.rg, requestCase.svc))

				require.Empty(t, logs.String())
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Empty(t, got.NativeIDs)
				require.Nil(t, got.NextPageToken)
				require.Zero(t, *subject.pagerCalls)
				require.Zero(t, *subject.pageCalls)
			})
		}
	}
}

// TestApiManagementTierUnsupportedErrorsRemainFailuresOutsideList catches
// accidentally applying discovery-only classification to managed reads or writes.
func TestApiManagementTierUnsupportedErrorsRemainFailuresOutsideList(t *testing.T) {
	errorCases := []struct {
		name string
		err  func() error
	}{
		{name: "exact", err: func() error { return unsupportedAPIMTierError() }},
		{name: "wrapped", err: func() error {
			return fmt.Errorf("Azure operation: %w", unsupportedAPIMTierError())
		}},
	}

	for _, kind := range apiManagementListKinds {
		for _, errorCase := range errorCases {
			t.Run(kind+"/"+errorCase.name+"/Read", func(t *testing.T) {
				subject := newApiManagementNonListSubject(kind, errorCase.err())

				ctx, logs := apiManagementTierLogContext()
				got, err := subject.read(ctx)

				require.Empty(t, logs.String())
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ErrorCode)
			})

			t.Run(kind+"/"+errorCase.name+"/Create", func(t *testing.T) {
				subject := newApiManagementNonListSubject(kind, errorCase.err())

				ctx, logs := apiManagementTierLogContext()
				got, err := subject.create(ctx)

				require.Empty(t, logs.String())
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
				require.Equal(t, resource.OperationErrorCodeInvalidRequest, got.ProgressResult.ErrorCode)
				require.Contains(t, got.ProgressResult.StatusMessage, unsupportedAPIMTierCode)
			})
		}
	}
}

func apiManagementListRequest(rgName, serviceName string) *resource.ListRequest {
	return &resource.ListRequest{AdditionalProperties: map[string]string{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
	}}
}

func newApiManagementListSubject(t *testing.T, kind string, steps []apiManagementListStep) apiManagementListSubject {
	t.Helper()
	pagerCalls := 0
	pageCalls := 0

	switch kind {
	case "User":
		api := &fakeApiManagementUsersAPI{newListByServicePagerFn: func(rgName, serviceName string, _ *armapimanagement.UserClientListByServiceOptions) *runtime.Pager[armapimanagement.UserClientListByServiceResponse] {
			pagerCalls++
			require.Equal(t, "rg-test", rgName)
			require.Equal(t, "apim-test", serviceName)
			return apiManagementListPager(steps, &pageCalls, func(nativeIDs []string) armapimanagement.UserClientListByServiceResponse {
				items := make([]*armapimanagement.UserContract, 0, len(nativeIDs))
				for _, nativeID := range nativeIDs {
					items = append(items, &armapimanagement.UserContract{ID: to.Ptr(nativeID)})
				}
				return armapimanagement.UserClientListByServiceResponse{UserCollection: armapimanagement.UserCollection{Value: items}}
			})
		}}
		return apiManagementListSubject{list: newTestApiManagementUser(api).List, pagerCalls: &pagerCalls, pageCalls: &pageCalls}
	case "Group":
		api := &fakeApiManagementGroupsAPI{newListByServicePagerFn: func(rgName, serviceName string, _ *armapimanagement.GroupClientListByServiceOptions) *runtime.Pager[armapimanagement.GroupClientListByServiceResponse] {
			pagerCalls++
			require.Equal(t, "rg-test", rgName)
			require.Equal(t, "apim-test", serviceName)
			return apiManagementListPager(steps, &pageCalls, func(nativeIDs []string) armapimanagement.GroupClientListByServiceResponse {
				items := make([]*armapimanagement.GroupContract, 0, len(nativeIDs))
				for _, nativeID := range nativeIDs {
					items = append(items, &armapimanagement.GroupContract{ID: to.Ptr(nativeID)})
				}
				return armapimanagement.GroupClientListByServiceResponse{GroupCollection: armapimanagement.GroupCollection{Value: items}}
			})
		}}
		return apiManagementListSubject{list: newTestApiManagementGroup(api).List, pagerCalls: &pagerCalls, pageCalls: &pageCalls}
	case "Gateway":
		api := &fakeApiManagementGatewaysAPI{newListByServicePagerFn: func(rgName, serviceName string, _ *armapimanagement.GatewayClientListByServiceOptions) *runtime.Pager[armapimanagement.GatewayClientListByServiceResponse] {
			pagerCalls++
			require.Equal(t, "rg-test", rgName)
			require.Equal(t, "apim-test", serviceName)
			return apiManagementListPager(steps, &pageCalls, func(nativeIDs []string) armapimanagement.GatewayClientListByServiceResponse {
				items := make([]*armapimanagement.GatewayContract, 0, len(nativeIDs))
				for _, nativeID := range nativeIDs {
					items = append(items, &armapimanagement.GatewayContract{ID: to.Ptr(nativeID)})
				}
				return armapimanagement.GatewayClientListByServiceResponse{GatewayCollection: armapimanagement.GatewayCollection{Value: items}}
			})
		}}
		return apiManagementListSubject{list: newTestApiManagementGateway(api).List, pagerCalls: &pagerCalls, pageCalls: &pageCalls}
	default:
		t.Fatalf("unknown API Management list kind %q", kind)
		return apiManagementListSubject{}
	}
}

func apiManagementListPager[T any](steps []apiManagementListStep, calls *int, response func([]string) T) *runtime.Pager[T] {
	next := 0
	return runtime.NewPager(runtime.PagingHandler[T]{
		More: func(T) bool { return next < len(steps) },
		Fetcher: func(context.Context, *T) (T, error) {
			step := steps[next]
			next++
			*calls = *calls + 1
			return response(step.nativeIDs), step.err
		},
	})
}

type apiManagementNonListSubject struct {
	read   func(context.Context) (*resource.ReadResult, error)
	create func(context.Context) (*resource.CreateResult, error)
}

func newApiManagementNonListSubject(kind string, providerErr error) apiManagementNonListSubject {
	switch kind {
	case "User":
		api := &fakeApiManagementUsersAPI{
			getFn: func(context.Context, string, string, string, *armapimanagement.UserClientGetOptions) (armapimanagement.UserClientGetResponse, error) {
				return armapimanagement.UserClientGetResponse{}, providerErr
			},
			createOrUpdateFn: func(context.Context, string, string, string, armapimanagement.UserCreateParameters, *armapimanagement.UserClientCreateOrUpdateOptions) (armapimanagement.UserClientCreateOrUpdateResponse, error) {
				return armapimanagement.UserClientCreateOrUpdateResponse{}, providerErr
			},
		}
		provider := newTestApiManagementUser(api)
		return apiManagementNonListSubject{
			read: func(ctx context.Context) (*resource.ReadResult, error) {
				return provider.Read(ctx, &resource.ReadRequest{NativeID: testApimUserNativeID})
			},
			create: func(ctx context.Context) (*resource.CreateResult, error) {
				return provider.Create(ctx, &resource.CreateRequest{Properties: apimUserDesired("Conformance")})
			},
		}
	case "Group":
		api := &fakeApiManagementGroupsAPI{
			getFn: func(context.Context, string, string, string, *armapimanagement.GroupClientGetOptions) (armapimanagement.GroupClientGetResponse, error) {
				return armapimanagement.GroupClientGetResponse{}, providerErr
			},
			createOrUpdateFn: func(context.Context, string, string, string, armapimanagement.GroupCreateParameters, *armapimanagement.GroupClientCreateOrUpdateOptions) (armapimanagement.GroupClientCreateOrUpdateResponse, error) {
				return armapimanagement.GroupClientCreateOrUpdateResponse{}, providerErr
			},
		}
		provider := newTestApiManagementGroup(api)
		return apiManagementNonListSubject{
			read: func(ctx context.Context) (*resource.ReadResult, error) {
				return provider.Read(ctx, &resource.ReadRequest{NativeID: testApimGroupNativeID})
			},
			create: func(ctx context.Context) (*resource.CreateResult, error) {
				return provider.Create(ctx, &resource.CreateRequest{Properties: apimGroupDesired("Partners")})
			},
		}
	case "Gateway":
		api := &fakeApiManagementGatewaysAPI{
			getFn: func(context.Context, string, string, string, *armapimanagement.GatewayClientGetOptions) (armapimanagement.GatewayClientGetResponse, error) {
				return armapimanagement.GatewayClientGetResponse{}, providerErr
			},
			createOrUpdateFn: func(context.Context, string, string, string, armapimanagement.GatewayContract, *armapimanagement.GatewayClientCreateOrUpdateOptions) (armapimanagement.GatewayClientCreateOrUpdateResponse, error) {
				return armapimanagement.GatewayClientCreateOrUpdateResponse{}, providerErr
			},
		}
		provider := newTestApiManagementGateway(api)
		return apiManagementNonListSubject{
			read: func(ctx context.Context) (*resource.ReadResult, error) {
				return provider.Read(ctx, &resource.ReadRequest{NativeID: testApimGatewayNativeID})
			},
			create: func(ctx context.Context) (*resource.CreateResult, error) {
				return provider.Create(ctx, &resource.CreateRequest{Properties: apimGatewayDesired("On-prem gateway")})
			},
		}
	default:
		panic(fmt.Sprintf("unknown API Management kind %q", kind))
	}
}

func apiManagementTierLogContext() (context.Context, *bytes.Buffer) {
	logs := &bytes.Buffer{}
	logger := plugin.NewPluginLogger(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return plugin.WithLogger(context.Background(), logger), logs
}
