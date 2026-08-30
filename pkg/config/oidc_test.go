// © 2026 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package config

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/platform-engineering-labs/formae/pkg/plugin"
	azurex "github.com/platform-engineering-labs/oox/oidcx/azure"
)

// stubTokenSource is a plugin.OidcTokenSource that returns a fixed identity
// token and records the context each call was made with.
type stubTokenSource struct {
	mu    sync.Mutex
	calls []context.Context
}

func (s *stubTokenSource) IdentityToken(ctx context.Context, audience string) (string, error) {
	s.mu.Lock()
	s.calls = append(s.calls, ctx)
	s.mu.Unlock()
	return "fake-assertion", nil
}

// fakeCredential is a minimal azcore.TokenCredential used to prove
// construction happened without exercising any real Azure machinery.
type fakeCredential struct{}

func (fakeCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

func TestCredentialCachedPerTenantAndClient(t *testing.T) {
	var constructCount int
	deps := NewOidcDeps(&stubTokenSource{})
	deps.construct = func(plugin.OidcTokenSource, azurex.Config) (azcore.TokenCredential, error) {
		constructCount++
		return fakeCredential{}, nil
	}

	tenant := "11111111-1111-1111-1111-111111111111"
	client := "22222222-2222-2222-2222-222222222222"

	_, err := deps.credentialFor(tenant, client)
	require.NoError(t, err)
	_, err = deps.credentialFor(tenant, client)
	require.NoError(t, err)

	assert.Equal(t, 1, constructCount, "two calls for the same tenant+client must construct exactly once")

	otherClient := "33333333-3333-3333-3333-333333333333"
	_, err = deps.credentialFor(tenant, otherClient)
	require.NoError(t, err)

	assert.Equal(t, 2, constructCount, "a different client must construct again")
}

// TestTheAssertionCallbackObservesTheLiveCallContext exercises the real
// oidcx/azure.Credential chain (not an injected constructor, which would
// bypass exactly the code path under test) and proves the assertion callback
// receives the context of the call it serves, not the context of whichever
// call first built the credential.
//
// It drives the credential only as far as the assertion callback. The
// exchange itself needs the real, publicly resolvable "common" Microsoft
// Entra tenant to get past tenant discovery without touching any customer
// tenant or credential; the actual token request is expected to fail since
// the assertion is not a real signed JWT. That failure is irrelevant here -
// what matters is which context the callback observed.
func TestTheAssertionCallbackObservesTheLiveCallContext(t *testing.T) {
	stub := &stubTokenSource{}
	cfg := azurex.NewConfig(nil)
	cfg.TenantID = "common"
	cfg.ClientID = "00000000-0000-0000-0000-000000000000"

	cred, err := azurex.Credential(brokerClient{src: stub}, cfg)
	require.NoError(t, err)

	ctxA, cancelA := context.WithTimeout(context.Background(), 20*time.Second)
	_, _ = cred.GetToken(ctxA, policy.TokenRequestOptions{Scopes: cfg.Scopes()})
	cancelA()

	ctxB, cancelB := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelB()
	_, _ = cred.GetToken(ctxB, policy.TokenRequestOptions{Scopes: cfg.Scopes()})

	require.Len(t, stub.calls, 2, "the assertion callback must fire once per draw")

	// The first captured context is the one the credential was built with for
	// draw A. Now that ctxA has been cancelled, its Err() reflects that -
	// which only holds if this really is (or derives from) ctxA, not a copy
	// taken once at construction time.
	assert.ErrorIs(t, stub.calls[0].Err(), context.Canceled)

	// The second draw's context must be the live one for that call: it must
	// not be cancelled, proving the credential did not keep serving the
	// context from the first, already-cancelled, draw.
	assert.NoError(t, stub.calls[1].Err())
}
