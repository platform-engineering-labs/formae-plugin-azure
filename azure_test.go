// © 2026 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/platform-engineering-labs/formae/pkg/plugin"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oidcTokenSourceFunc adapts a function to plugin.OidcTokenSource so a test
// can script what the source answers. The compile-time check that Plugin
// satisfies plugin.OidcAware already lives in azure.go, next to the
// production code it guards.
type oidcTokenSourceFunc func(ctx context.Context, audience string) (string, error)

func (f oidcTokenSourceFunc) IdentityToken(ctx context.Context, audience string) (string, error) {
	return f(ctx, audience)
}

func TestSetOidcTokenSource_PopulatesDeps(t *testing.T) {
	p := &Plugin{}
	assert.Nil(t, p.oidc)

	src := oidcTokenSourceFunc(func(context.Context, string) (string, error) {
		return "stub-token", nil
	})
	p.SetOidcTokenSource(src)

	require.NotNil(t, p.oidc)
	assert.NotNil(t, p.oidc.Source)
}

// recordingLogger captures log levels so tests can verify the visibility of
// expected discovery races without depending on log formatting.
type recordingLogger struct {
	debugs []string
	warns  []string
	errors []string
}

func (l *recordingLogger) Debug(msg string, _ ...any) {
	l.debugs = append(l.debugs, msg)
}
func (l *recordingLogger) Info(string, ...any) {}
func (l *recordingLogger) Warn(msg string, _ ...any) {
	l.warns = append(l.warns, msg)
}
func (l *recordingLogger) Error(msg string, _ ...any) {
	l.errors = append(l.errors, msg)
}
func (l *recordingLogger) With(...any) plugin.Logger { return l }

func TestListReportsNothingWhenTheCredentialIsNotAuthorized(t *testing.T) {
	log := &recordingLogger{}

	got, err := listOutcome(log, "AZURE::Management::ManagementGroup", "", nil,
		fmt.Errorf("failed to list management groups: %w",
			&azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}))

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Empty(t, got.NativeIDs)
	assert.Len(t, log.warns, 1, "an unexpected 403 must still be logged")
	assert.Empty(t, log.errors)
}

func TestListReportsMissingScopedResourceGroupAsEmpty(t *testing.T) {
	log := &recordingLogger{}
	missingGroup := &azcore.ResponseError{StatusCode: 404, ErrorCode: "ResourceGroupNotFound"}

	got, err := listOutcome(log, "AZURE::Storage::StorageAccount", "deleted-rg", nil,
		fmt.Errorf("failed to list storage accounts: %w", missingGroup))

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Empty(t, got.NativeIDs)
	assert.Len(t, log.debugs, 1)
	assert.Empty(t, log.errors)
	assert.Empty(t, log.warns)
}

func TestListStillFailsUnlessScopedResourceGroupIsPreciselyMissing(t *testing.T) {
	tests := []struct {
		name              string
		resourceGroupName string
		providerError     error
	}{
		{
			name:              "unrelated 404",
			resourceGroupName: "existing-rg",
			providerError:     &azcore.ResponseError{StatusCode: 404, ErrorCode: "ResourceNotFound"},
		},
		{
			name:              "missing scope",
			resourceGroupName: "",
			providerError:     &azcore.ResponseError{StatusCode: 404, ErrorCode: "ResourceGroupNotFound"},
		},
		{
			name:              "wrong status with matching provider code",
			resourceGroupName: "existing-rg",
			providerError:     &azcore.ResponseError{StatusCode: 500, ErrorCode: "ResourceGroupNotFound"},
		},
		{
			name:              "invalid credentials",
			resourceGroupName: "existing-rg",
			providerError:     &azcore.ResponseError{StatusCode: 401, ErrorCode: "InvalidAuthenticationToken"},
		},
		{
			name:              "throttled",
			resourceGroupName: "existing-rg",
			providerError:     &azcore.ResponseError{StatusCode: 429, ErrorCode: "TooManyRequests"},
		},
		{
			name:              "service error",
			resourceGroupName: "existing-rg",
			providerError:     &azcore.ResponseError{StatusCode: 500, ErrorCode: "InternalServerError"},
		},
		{
			name:              "transport error",
			resourceGroupName: "existing-rg",
			providerError:     fmt.Errorf("connection reset"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := &recordingLogger{}
			wrapped := fmt.Errorf("failed to list resources: %w", tt.providerError)

			got, err := listOutcome(log, "AZURE::Test::Resource", tt.resourceGroupName, nil, wrapped)

			assert.Nil(t, got)
			require.ErrorIs(t, err, tt.providerError)
			assert.Empty(t, log.debugs)
			assert.Empty(t, log.warns)
			assert.Len(t, log.errors, 1)
		})
	}
}

func TestLogReadOutcomeReportsNotFoundAsDebugWithoutChangingResult(t *testing.T) {
	log := &recordingLogger{}
	result := &resource.ReadResult{ErrorCode: resource.OperationErrorCodeNotFound}

	logReadOutcome(log, &resource.ReadRequest{
		ResourceType: "AZURE::Resources::ResourceGroup",
		NativeID:     "/subscriptions/example/resourceGroups/deleted-rg",
	}, result, nil)

	assert.Equal(t, resource.OperationErrorCodeNotFound, result.ErrorCode)
	assert.Len(t, log.debugs, 1)
	assert.Empty(t, log.warns)
	assert.Empty(t, log.errors)
}

func TestLogReadOutcomeKeepsFailuresAtError(t *testing.T) {
	tests := []struct {
		name   string
		result *resource.ReadResult
		err    error
	}{
		{
			name:   "access denied result",
			result: &resource.ReadResult{ErrorCode: resource.OperationErrorCodeAccessDenied},
		},
		{
			name:   "invalid credentials result",
			result: &resource.ReadResult{ErrorCode: resource.OperationErrorCodeInvalidCredentials},
		},
		{
			name: "transport error",
			err:  fmt.Errorf("connection reset"),
		},
		{
			name:   "not found result with error",
			result: &resource.ReadResult{ErrorCode: resource.OperationErrorCodeNotFound},
			err:    fmt.Errorf("read interrupted"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := &recordingLogger{}

			logReadOutcome(log, &resource.ReadRequest{
				ResourceType: "AZURE::Test::Resource",
				NativeID:     "/subscriptions/example/resources/example",
			}, tt.result, tt.err)

			assert.Empty(t, log.debugs)
			assert.Empty(t, log.warns)
			assert.Len(t, log.errors, 1)
		})
	}
}

func TestLogReadOutcomeLeavesSuccessfulReadQuiet(t *testing.T) {
	log := &recordingLogger{}

	logReadOutcome(log, &resource.ReadRequest{
		ResourceType: "AZURE::Test::Resource",
		NativeID:     "/subscriptions/example/resources/example",
	}, &resource.ReadResult{}, nil)

	assert.Empty(t, log.debugs)
	assert.Empty(t, log.warns)
	assert.Empty(t, log.errors)
}
