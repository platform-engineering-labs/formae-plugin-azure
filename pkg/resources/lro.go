// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

// lroRequestID is the persisted shape of an Azure long-running operation handle.
//
// JSON shape MUST remain byte-compatible across releases — it is stored in the
// formae datastore as ProgressResult.RequestID for in-flight LROs. Renaming or
// retyping a field, or changing the omitempty behavior, will orphan in-flight
// operations across an upgrade.
type lroRequestID struct {
	OperationType string `json:"operationType"`
	ResumeToken   string `json:"resumeToken"`
	NativeID      string `json:"nativeID,omitempty"`
}

const (
	lroOpCreate = "create"
	lroOpUpdate = "update"
	lroOpDelete = "delete"
)

// encodeLROStart marshals an lroRequestID into the string form returned as
// ProgressResult.RequestID when an LRO is in progress.
func encodeLROStart(opType, resumeToken, nativeID string) (string, error) {
	reqID := lroRequestID{
		OperationType: opType,
		ResumeToken:   resumeToken,
		NativeID:      nativeID,
	}
	out, err := json.Marshal(reqID)
	if err != nil {
		return "", fmt.Errorf("failed to marshal lro request id: %w", err)
	}
	return string(out), nil
}

// decodeLROStatus unmarshals a ProgressResult.RequestID back into its parts.
func decodeLROStatus(requestID string) (lroRequestID, error) {
	var reqID lroRequestID
	if err := json.Unmarshal([]byte(requestID), &reqID); err != nil {
		return lroRequestID{}, fmt.Errorf("failed to parse lro request id: %w", err)
	}
	return reqID, nil
}

// resumePoller reconstructs a typed Azure SDK poller from a resume token.
//
// Replaces the per-resource <name>Wrapper.ResumeCreatePoller / ResumeUpdatePoller /
// ResumeDeletePoller methods that previously had to be declared in each resource
// file because runtime.NewPollerFromResumeToken is a generic top-level function,
// not a client method.
//
// Callers pass the response type as the type parameter, e.g.
//
//	poller, err := resumePoller[armnetwork.VirtualNetworksClientCreateOrUpdateResponse](pipeline, token)
func resumePoller[T any](pipeline runtime.Pipeline, token string) (*runtime.Poller[T], error) {
	return runtime.NewPollerFromResumeToken[T](token, pipeline, nil)
}

type lroResumeFunc[T any] func(string) (*runtime.Poller[T], error)
type lroCompleteFunc[T any] func(context.Context, T, resource.Operation) (string, json.RawMessage, error)

// lroFailure builds a failure result. msg carries the underlying provider error
// text into ProgressResult.StatusMessage so the reason surfaces in status output
// (and across retries) instead of only an opaque error code.
func lroFailure(operation resource.Operation, requestID string, code resource.OperationErrorCode, msg string) *resource.StatusResult {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       requestID,
			ErrorCode:       code,
			StatusMessage:   msg,
		},
	}
}

func lroInProgress(operation resource.Operation, requestID, nativeID string) *resource.StatusResult {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       requestID,
			NativeID:        nativeID,
		},
	}
}

func lroSuccess(operation resource.Operation, requestID, nativeID string, properties json.RawMessage) *resource.StatusResult {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          operation,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          requestID,
			NativeID:           nativeID,
			ResourceProperties: properties,
		},
	}
}

func lroDeleteSuccess(requestID, nativeID string) *resource.StatusResult {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       requestID,
			NativeID:        nativeID,
		},
	}
}

func statusLRO[T any](ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID, operation resource.Operation, resume lroResumeFunc[T], complete lroCompleteFunc[T]) (*resource.StatusResult, error) {
	poller, err := resume(reqID.ResumeToken)
	if err != nil {
		return lroFailure(operation, request.RequestID, resource.OperationErrorCodeGeneralServiceException, fmt.Sprintf("failed to resume poller: %v", err)), fmt.Errorf("failed to resume poller: %w", err)
	}
	if !poller.Done() {
		if _, err := poller.Poll(ctx); err != nil {
			return lroFailure(operation, request.RequestID, operationErrorCode(err), err.Error()), nil
		}
		if !poller.Done() {
			return lroInProgress(operation, request.RequestID, reqID.NativeID), nil
		}
	}

	result, err := poller.Result(ctx)
	if err != nil {
		return lroFailure(operation, request.RequestID, operationErrorCode(err), err.Error()), nil
	}
	nativeID, properties, err := complete(ctx, result, operation)
	if err != nil {
		return nil, err
	}
	return lroSuccess(operation, request.RequestID, nativeID, properties), nil
}

func statusDeleteLRO[T any](ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID, resume lroResumeFunc[T], verify func(context.Context, *resource.StatusRequest, *lroRequestID) *resource.StatusResult) (*resource.StatusResult, error) {
	success := func() *resource.StatusResult {
		if verify != nil {
			return verify(ctx, request, reqID)
		}
		return lroDeleteSuccess(request.RequestID, reqID.NativeID)
	}

	poller, err := resume(reqID.ResumeToken)
	if err != nil {
		if isDeleteSuccessError(err) {
			return success(), nil
		}
		return lroFailure(resource.OperationDelete, request.RequestID, resource.OperationErrorCodeGeneralServiceException, fmt.Sprintf("failed to resume poller: %v", err)), fmt.Errorf("failed to resume poller: %w", err)
	}
	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
			return lroFailure(resource.OperationDelete, request.RequestID, operationErrorCode(err), err.Error()), nil
		}
		return success(), nil
	}
	if _, err = poller.Poll(ctx); err != nil {
		if isDeleteSuccessError(err) {
			return success(), nil
		}
		return lroFailure(resource.OperationDelete, request.RequestID, operationErrorCode(err), err.Error()), nil
	}
	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
			return lroFailure(resource.OperationDelete, request.RequestID, operationErrorCode(err), err.Error()), nil
		}
		return success(), nil
	}
	return lroInProgress(resource.OperationDelete, request.RequestID, reqID.NativeID), nil
}
