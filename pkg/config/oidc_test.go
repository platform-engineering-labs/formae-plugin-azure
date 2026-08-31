// © 2026 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package config

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
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

// idCredential is a azcore.TokenCredential carrying a distinguishing id, so a
// test can tell distinct constructions apart. It is not zero-size (unlike
// fakeCredential above), which matters here: the Go runtime is free to alias
// the address of distinct zero-size values, which would make pointer-identity
// assertions on &fakeCredential{} pass trivially regardless of whether
// construction was actually deduplicated.
type idCredential struct{ id int }

func (idCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

// TestCredentialForConcurrent drives credentialFor from many goroutines for a
// mix of shared and distinct keys, so `go test -race` can catch a data race
// on the map if the RWMutex guard ever regresses, and asserts that racing
// callers for the same key converge on one credential instance.
func TestCredentialForConcurrent(t *testing.T) {
	var nextID int32
	deps := NewOidcDeps(&stubTokenSource{})
	deps.construct = func(plugin.OidcTokenSource, azurex.Config) (azcore.TokenCredential, error) {
		id := int(atomic.AddInt32(&nextID, 1))
		return &idCredential{id: id}, nil
	}

	const goroutines = 50
	const sharedKeys = 5

	var wg sync.WaitGroup
	results := make([]azcore.TokenCredential, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tenant := "tenant"
			client := string(rune('a' + i%sharedKeys))
			cred, err := deps.credentialFor(tenant, client)
			assert.NoError(t, err)
			results[i] = cred
		}(i)
	}
	wg.Wait()

	// All goroutines sharing a key must have observed the same instance.
	seen := make(map[string]azcore.TokenCredential)
	for i := 0; i < goroutines; i++ {
		client := string(rune('a' + i%sharedKeys))
		if prior, ok := seen[client]; ok {
			assert.Same(t, prior, results[i], "same-key callers must get the same credential instance")
		} else {
			seen[client] = results[i]
		}
	}
}

// fakeTenantID is a syntactically valid, but entirely fictional, Entra
// tenant GUID. Nothing resolves it for real: every HTTP call this test's
// credential can make is answered by fakeEntraTransport below.
const fakeTenantID = "11111111-1111-1111-1111-111111111111"

// fakeEntraTransport answers every HTTP call MSAL's confidential client can
// make for a client-assertion token acquisition - the tenant's OIDC metadata
// document, and the token endpoint itself - entirely in memory. Azure's SDK
// threads ClientOptions.Transport all the way down to the HTTP client MSAL
// is given, so this is the only seam needed to keep the exchange offline:
// nothing here ever opens a socket.
//
// The token endpoint always answers with an error, deliberately: a
// successful exchange would let MSAL cache a valid access token and serve
// the second draw from cache without ever calling the assertion callback
// again, which would defeat the point of this test. Failing the exchange
// every time forces a fresh assertion (and so a fresh callback invocation)
// on every draw.
type fakeEntraTransport struct{}

func jsonResponse(req *http.Request, status int, body map[string]any) *http.Response {
	b, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(b)),
		Request:    req,
	}
}

func (f *fakeEntraTransport) Do(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet {
		return jsonResponse(req, http.StatusOK, map[string]any{
			"token_endpoint":                        "https://login.microsoftonline.com/" + fakeTenantID + "/oauth2/v2.0/token",
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "private_key_jwt"},
			"issuer":                                "https://login.microsoftonline.com/" + fakeTenantID + "/v2.0",
			"authorization_endpoint":                "https://login.microsoftonline.com/" + fakeTenantID + "/oauth2/v2.0/authorize",
		}), nil
	}

	return jsonResponse(req, http.StatusBadRequest, map[string]any{
		"error":             "invalid_client",
		"error_description": "AADSTS5002710: Invalid JWT token: header is malformed.",
	}), nil
}

// TestTheAssertionCallbackObservesTheLiveCallContext exercises the real
// oidcx/azure.Credential chain (not an injected constructor, which would
// bypass exactly the code path under test) and proves the assertion callback
// receives the context of the call it serves, not the context of whichever
// call first built the credential.
//
// It runs entirely offline: a fake transport answers both the tenant OIDC
// metadata GET and the token POST, and DisableInstanceDiscovery removes the
// separate instance-discovery call. Nothing here reaches a real host.
func TestTheAssertionCallbackObservesTheLiveCallContext(t *testing.T) {
	stub := &stubTokenSource{}
	cfg := azurex.NewConfig(nil)
	cfg.TenantID = fakeTenantID
	cfg.ClientID = "22222222-2222-2222-2222-222222222222"

	cred, err := azurex.Credential(brokerClient{src: stub}, cfg, &azidentity.ClientAssertionCredentialOptions{
		ClientOptions:            azcore.ClientOptions{Transport: &fakeEntraTransport{}},
		DisableInstanceDiscovery: true,
	})
	require.NoError(t, err)

	ctxA, cancelA := context.WithTimeout(context.Background(), 2*time.Second)
	_, _ = cred.GetToken(ctxA, policy.TokenRequestOptions{Scopes: cfg.Scopes()})
	cancelA()

	ctxB, cancelB := context.WithTimeout(context.Background(), 2*time.Second)
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
