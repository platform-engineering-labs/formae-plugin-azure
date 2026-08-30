// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package client

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/stretchr/testify/require"
)

type fakeCredential struct{}

func (fakeCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

// resetClientCache isolates package-level cache state for a test.
func resetClientCache(t *testing.T) *int {
	t.Helper()
	orig := newCredential
	builds := 0
	newCredential = func(*config.Config) (azcore.TokenCredential, error) {
		builds++
		return fakeCredential{}, nil
	}
	clientCache = map[string]*clientEntry{}
	t.Cleanup(func() {
		newCredential = orig
		clientCache = map[string]*clientEntry{}
	})
	return &builds
}

// The core guarantee: many operations against one subscription build the
// credential exactly once, so the SDK's token cache survives across ops.
func TestNewClient_CachesCredentialPerSubscription(t *testing.T) {
	builds := resetClientCache(t)

	c1, err := NewClient(&config.Config{SubscriptionId: "sub-A"})
	require.NoError(t, err)
	c2, err := NewClient(&config.Config{SubscriptionId: "sub-A"})
	require.NoError(t, err)
	c3, err := NewClient(&config.Config{SubscriptionId: "sub-A"})
	require.NoError(t, err)

	require.Same(t, c1, c2, "same subscription must return the cached client")
	require.Same(t, c1, c3, "cache is keyed by subscription id, not by config pointer")
	require.Equal(t, 1, *builds, "credential built once for a subscription across many ops")

	c4, err := NewClient(&config.Config{SubscriptionId: "sub-B"})
	require.NoError(t, err)
	require.NotSame(t, c1, c4, "a different subscription gets its own client")
	require.Equal(t, 2, *builds, "credential built once per subscription")
}

func TestNewClient_Validation(t *testing.T) {
	resetClientCache(t)

	_, err := NewClient(nil)
	require.Error(t, err)

	_, err = NewClient(&config.Config{SubscriptionId: ""})
	require.Error(t, err)

	_, err = NewClient(&config.Config{SubscriptionId: "   "})
	require.Error(t, err)
}

// namedCredential distinguishes itself from another instance by name, so a
// test can tell which credential ended up wired into a cached Client without
// reaching into the Azure SDK's sub-clients.
type namedCredential struct{ name string }

func (namedCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

// The cache key must capture the auth block, not just the subscription: two
// targets on the same subscription with different auth must never share a
// credential, and adding an OidcAuth block to a target that already has a
// cached ambient client - exactly the onboarding path this plugin exists to
// support - must not keep serving the old ambient credential until the
// process restarts.
func TestNewClient_CacheKeyCapturesAuthBlock(t *testing.T) {
	orig := newCredential
	clientCache = map[string]*clientEntry{}
	t.Cleanup(func() {
		newCredential = orig
		clientCache = map[string]*clientEntry{}
	})

	var built []string
	newCredential = func(cfg *config.Config) (azcore.TokenCredential, error) {
		if len(cfg.Auth) == 0 {
			built = append(built, "ambient")
			return namedCredential{name: "ambient"}, nil
		}
		built = append(built, "oidc")
		return namedCredential{name: "oidc"}, nil
	}

	ambient, err := NewClient(&config.Config{SubscriptionId: "sub-A"})
	require.NoError(t, err)

	withAuth, err := NewClient(&config.Config{
		SubscriptionId: "sub-A",
		Auth:           json.RawMessage(`{"Type":"Oidc","TenantId":"11111111-1111-1111-1111-111111111111","ClientId":"22222222-2222-2222-2222-222222222222"}`),
	})
	require.NoError(t, err)

	require.NotSame(t, ambient, withAuth,
		"adding an auth block to a subscription with a cached client must not reuse the ambient client")
	require.Equal(t, []string{"ambient", "oidc"}, built,
		"the second build must actually construct the federated credential, not skip construction because the cache already had an entry for this subscription")
	require.Equal(t, namedCredential{name: "oidc"}, withAuth.Credential(),
		"the client built for the Oidc-auth config must carry the federated credential, not the ambient one")
}
