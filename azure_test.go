// © 2026 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package main

import (
	"context"
	"testing"

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
