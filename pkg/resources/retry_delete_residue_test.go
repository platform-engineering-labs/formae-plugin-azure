// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package resources

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shrinkDeleteResidueWindow makes the retry loop finish in milliseconds so these
// tests do not sleep through the real 90s window.
func shrinkDeleteResidueWindow(t *testing.T, maxWait, interval time.Duration) {
	t.Helper()
	oldMax, oldInterval := deleteResidueMaxWait, deleteResidueInterval
	deleteResidueMaxWait, deleteResidueInterval = maxWait, interval
	t.Cleanup(func() {
		deleteResidueMaxWait, deleteResidueInterval = oldMax, oldInterval
	})
}

func TestRetryOnDeleteResidue(t *testing.T) {
	conflict := &azcore.ResponseError{StatusCode: http.StatusConflict, ErrorCode: "Conflict"}

	t.Run("succeeds without retrying", func(t *testing.T) {
		shrinkDeleteResidueWindow(t, time.Second, time.Millisecond)
		calls := 0
		require.NoError(t, retryOnDeleteResidue(t.Context(), func() error {
			calls++
			return nil
		}))
		assert.Equal(t, 1, calls)
	})

	t.Run("retries a 409 until the residue clears", func(t *testing.T) {
		shrinkDeleteResidueWindow(t, time.Second, time.Millisecond)
		calls := 0
		err := retryOnDeleteResidue(t.Context(), func() error {
			calls++
			if calls < 3 {
				return conflict
			}
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 3, calls, "should have retried twice before succeeding")
	})

	t.Run("gives up on a 409 that never clears, keeping the error", func(t *testing.T) {
		shrinkDeleteResidueWindow(t, 10*time.Millisecond, time.Millisecond)
		calls := 0
		err := retryOnDeleteResidue(t.Context(), func() error {
			calls++
			return conflict
		})
		require.ErrorIs(t, err, conflict)
		assert.Greater(t, calls, 1, "should have retried before giving up")
	})

	t.Run("does not retry anything but a 409", func(t *testing.T) {
		shrinkDeleteResidueWindow(t, time.Second, time.Millisecond)
		badRequest := &azcore.ResponseError{StatusCode: http.StatusBadRequest}
		calls := 0
		err := retryOnDeleteResidue(t.Context(), func() error {
			calls++
			return badRequest
		})
		require.ErrorIs(t, err, badRequest)
		assert.Equal(t, 1, calls, "a 400 is a caller error, not residue")
	})

	t.Run("does not retry a plain error", func(t *testing.T) {
		shrinkDeleteResidueWindow(t, time.Second, time.Millisecond)
		plain := errors.New("boom")
		calls := 0
		require.ErrorIs(t, retryOnDeleteResidue(t.Context(), func() error {
			calls++
			return plain
		}), plain)
		assert.Equal(t, 1, calls)
	})

	t.Run("stops when the context is cancelled", func(t *testing.T) {
		shrinkDeleteResidueWindow(t, time.Minute, time.Hour)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		calls := 0
		err := retryOnDeleteResidue(ctx, func() error {
			calls++
			return conflict
		})
		require.ErrorIs(t, err, conflict)
		assert.Equal(t, 1, calls, "a cancelled context must not wait out the interval")
	})
}
