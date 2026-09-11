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

// recordingLogger captures what the plugin logged, so a test can assert that an
// authorization failure is reported rather than silently swallowed.
type recordingLogger struct {
	warns  []string
	errors []string
}

func (l *recordingLogger) Debug(string, ...any) {}
func (l *recordingLogger) Info(string, ...any)  {}
func (l *recordingLogger) Warn(msg string, _ ...any) {
	l.warns = append(l.warns, msg)
}
func (l *recordingLogger) Error(msg string, _ ...any) {
	l.errors = append(l.errors, msg)
}
func (l *recordingLogger) With(...any) plugin.Logger { return l }

func TestListReportsNothingWhenTheCredentialIsNotAuthorized(t *testing.T) {
	log := &recordingLogger{}

	got, err := listOutcome(log, "AZURE::Management::ManagementGroup", nil,
		fmt.Errorf("failed to list management groups: %w",
			&azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}))

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Empty(t, got.NativeIDs)
	assert.Len(t, log.warns, 1, "an unexpected 403 must still be logged")
	assert.Empty(t, log.errors)
}

func TestListStillFailsOnEveryOtherError(t *testing.T) {
	log := &recordingLogger{}
	boom := &azcore.ResponseError{StatusCode: 500}

	_, err := listOutcome(log, "AZURE::Management::ManagementGroup", nil, boom)

	require.ErrorIs(t, err, boom)
	assert.Len(t, log.errors, 1)
	assert.Empty(t, log.warns)
}
