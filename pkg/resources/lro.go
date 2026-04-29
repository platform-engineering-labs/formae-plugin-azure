// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
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
