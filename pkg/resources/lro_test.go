// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/require"
)

// TestLRORequestIDJSONShape locks the wire shape of lroRequestID. The encoded
// JSON is persisted in the formae datastore; drift orphans in-flight LROs.
func TestLRORequestIDJSONShape(t *testing.T) {
	t.Run("all fields populated", func(t *testing.T) {
		in := lroRequestID{OperationType: "create", ResumeToken: "tok-abc", NativeID: "/subscriptions/x/resourceGroups/y/providers/Microsoft.Network/virtualNetworks/z"}
		want := `{"operationType":"create","resumeToken":"tok-abc","nativeID":"/subscriptions/x/resourceGroups/y/providers/Microsoft.Network/virtualNetworks/z"}`

		got, err := json.Marshal(in)

		require.NoError(t, err)
		require.JSONEq(t, want, string(got))
	})

	t.Run("nativeID omitted when empty", func(t *testing.T) {
		in := lroRequestID{OperationType: "delete", ResumeToken: "tok-xyz"}
		want := `{"operationType":"delete","resumeToken":"tok-xyz"}`

		got, err := json.Marshal(in)

		require.NoError(t, err)
		require.JSONEq(t, want, string(got))
	})

	t.Run("update with nativeID", func(t *testing.T) {
		in := lroRequestID{OperationType: "update", ResumeToken: "tok-123", NativeID: "/sub/foo"}
		want := `{"operationType":"update","resumeToken":"tok-123","nativeID":"/sub/foo"}`

		got, err := json.Marshal(in)

		require.NoError(t, err)
		require.JSONEq(t, want, string(got))
	})
}

func TestEncodeDecodeLRORoundTrip(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		want := lroRequestID{OperationType: "create", ResumeToken: "abc", NativeID: "/sub/x"}

		encoded, err := encodeLROStart(want.OperationType, want.ResumeToken, want.NativeID)
		require.NoError(t, err)
		got, err := decodeLROStatus(encoded)

		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("update", func(t *testing.T) {
		want := lroRequestID{OperationType: "update", ResumeToken: "def", NativeID: "/sub/y"}

		encoded, err := encodeLROStart(want.OperationType, want.ResumeToken, want.NativeID)
		require.NoError(t, err)
		got, err := decodeLROStatus(encoded)

		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("delete omits native id", func(t *testing.T) {
		want := lroRequestID{OperationType: "delete", ResumeToken: "ghi"}

		encoded, err := encodeLROStart(want.OperationType, want.ResumeToken, want.NativeID)
		require.NoError(t, err)
		got, err := decodeLROStatus(encoded)

		require.NoError(t, err)
		require.Equal(t, want, got)
	})
}

func TestDecodeLROStatusBackwardCompat(t *testing.T) {
	legacy := `{"operationType":"create","resumeToken":"legacy-token","nativeID":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet"}`

	got, err := decodeLROStatus(legacy)

	require.NoError(t, err)
	require.Equal(t, "create", got.OperationType)
	require.Equal(t, "legacy-token", got.ResumeToken)
	require.NotEmpty(t, got.NativeID)
}

func TestStatusLRO(t *testing.T) {
	ctx := context.Background()
	request := &resource.StatusRequest{RequestID: "req-1"}
	reqID := &lroRequestID{ResumeToken: "tok-1", NativeID: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Test/resources/r-1"}

	t.Run("done success", func(t *testing.T) {
		poller := newTestPoller(lroTestResponse{ID: reqID.NativeID}, true, nil, nil)

		got, err := statusLRO(ctx, request, reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[lroTestResponse], error) {
				require.Equal(t, "tok-1", token)
				return poller, nil
			},
			func(_ context.Context, result lroTestResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return result.ID, json.RawMessage(`{"name":"r-1"}`), nil
			})

		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, reqID.NativeID, got.ProgressResult.NativeID)
		require.JSONEq(t, `{"name":"r-1"}`, string(got.ProgressResult.ResourceProperties))
	})

	t.Run("still in progress", func(t *testing.T) {
		poller := newTestPoller(lroTestResponse{}, false, nil, nil)

		got, err := statusLRO(ctx, request, reqID, resource.OperationUpdate,
			func(string) (*runtime.Poller[lroTestResponse], error) { return poller, nil },
			func(context.Context, lroTestResponse, resource.Operation) (string, json.RawMessage, error) {
				return "", nil, fmt.Errorf("completion should not run")
			})

		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusInProgress, got.ProgressResult.OperationStatus)
		require.Equal(t, reqID.NativeID, got.ProgressResult.NativeID)
	})

	t.Run("poll error maps to failure", func(t *testing.T) {
		poller := newTestPoller(lroTestResponse{}, false, &azcore.ResponseError{StatusCode: 429}, nil)

		got, err := statusLRO(ctx, request, reqID, resource.OperationUpdate,
			func(string) (*runtime.Poller[lroTestResponse], error) { return poller, nil },
			func(context.Context, lroTestResponse, resource.Operation) (string, json.RawMessage, error) {
				return "", nil, fmt.Errorf("completion should not run")
			})

		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeThrottling, got.ProgressResult.ErrorCode)
	})
}

func TestStatusDeleteLRO(t *testing.T) {
	ctx := context.Background()
	request := &resource.StatusRequest{RequestID: "req-1"}
	reqID := &lroRequestID{ResumeToken: "tok-1", NativeID: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Test/resources/r-1"}

	t.Run("done success", func(t *testing.T) {
		poller := newTestPoller(lroTestResponse{}, true, nil, nil)

		got, err := statusDeleteLRO(ctx, request, reqID,
			func(string) (*runtime.Poller[lroTestResponse], error) { return poller, nil },
			nil)

		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, reqID.NativeID, got.ProgressResult.NativeID)
	})

	t.Run("not found during resume is success", func(t *testing.T) {
		got, err := statusDeleteLRO(ctx, request, reqID,
			func(string) (*runtime.Poller[lroTestResponse], error) {
				return nil, &azcore.ResponseError{StatusCode: 404}
			},
			nil)

		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, reqID.NativeID, got.ProgressResult.NativeID)
	})

	t.Run("uses verifier", func(t *testing.T) {
		poller := newTestPoller(lroTestResponse{}, true, nil, nil)
		wantNativeID := "verified-id"

		got, err := statusDeleteLRO(ctx, request, reqID,
			func(string) (*runtime.Poller[lroTestResponse], error) { return poller, nil },
			func(_ context.Context, _ *resource.StatusRequest, _ *lroRequestID) *resource.StatusResult {
				return lroDeleteSuccess(request.RequestID, wantNativeID)
			})

		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, wantNativeID, got.ProgressResult.NativeID)
	})
}

type lroTestResponse struct {
	ID string
}

type lroTestHandler[T any] struct {
	result  T
	done    bool
	pollErr error
	resErr  error
}

func newTestPoller[T any](result T, done bool, pollErr error, resultErr error) *runtime.Poller[T] {
	poller, err := runtime.NewPoller[T](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[T]{
		Handler: &lroTestHandler[T]{
			result:  result,
			done:    done,
			pollErr: pollErr,
			resErr:  resultErr,
		},
	})
	if err != nil {
		panic(err)
	}
	return poller
}

func (h *lroTestHandler[T]) Done() bool {
	return h.done
}

func (h *lroTestHandler[T]) Poll(context.Context) (*http.Response, error) {
	if h.pollErr != nil {
		return nil, h.pollErr
	}
	return &http.Response{StatusCode: http.StatusAccepted}, nil
}

func (h *lroTestHandler[T]) Result(_ context.Context, out *T) error {
	if h.resErr != nil {
		return h.resErr
	}
	*out = h.result
	return nil
}
