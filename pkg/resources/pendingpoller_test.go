// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
)

// pendingPollerHandler reports Done() as false so a write path takes its
// in-progress branch and produces a resume token. Every LRO-backed resource uses it
// to pin the native ID reported while an operation is still running: if that ID does
// not match the path ARM finally assigns, the resource is orphaned on completion.
type pendingPollerHandler[T any] struct{}

func (h *pendingPollerHandler[T]) Done() bool { return false }
func (h *pendingPollerHandler[T]) Poll(_ context.Context) (*http.Response, error) {
	return nil, nil
}
func (h *pendingPollerHandler[T]) Result(_ context.Context, _ *T) error { return nil }

// newPendingPoller builds a poller that never completes.
func newPendingPoller[T any]() *runtime.Poller[T] {
	p, err := runtime.NewPoller[T](nil, runtime.Pipeline{}, &runtime.NewPollerOptions[T]{
		Handler: &pendingPollerHandler[T]{},
	})
	if err != nil {
		panic(err)
	}
	return p
}
