// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package config

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/platform-engineering-labs/formae/pkg/plugin"
	azurex "github.com/platform-engineering-labs/oox/oidcx/azure"
)

func TestFromTargetConfig(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		want := "sub-1"

		got, err := FromTargetConfig(json.RawMessage(`{"SubscriptionId":" sub-1 "}`), nil)

		require.NoError(t, err)
		require.Equal(t, want, got.SubscriptionId)
	})

	t.Run("nil", func(t *testing.T) {
		got, err := FromTargetConfig(nil, nil)

		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("malformed", func(t *testing.T) {
		got, err := FromTargetConfig(json.RawMessage(`{"SubscriptionId":`), nil)

		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("missing subscription", func(t *testing.T) {
		got, err := FromTargetConfig(json.RawMessage(`{}`), nil)

		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("empty subscription", func(t *testing.T) {
		got, err := FromTargetConfig(json.RawMessage(`{"SubscriptionId":"   "}`), nil)

		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("wrong subscription type", func(t *testing.T) {
		got, err := FromTargetConfig(json.RawMessage(`{"SubscriptionId":123}`), nil)

		require.Error(t, err)
		require.Nil(t, got)
	})
}

// validOidcAuthJSON is a well-formed OidcAuth block, valid enough to reach the
// credential seam: coordinates that parse as UUIDs, whatever the broker
// backing them can or can't do.
const validOidcAuthJSON = `{"Type":"Oidc","TenantId":"11111111-1111-1111-1111-111111111111","ClientId":"22222222-2222-2222-2222-222222222222"}`

// brokerlessSource simulates a plugin instance whose broker pairing is
// missing or unreachable: every mint fails with plugin.ErrNoOidcBroker,
// exactly as the real SDK-installed token source does outside an operation.
type brokerlessSource struct{}

func (brokerlessSource) IdentityToken(context.Context, string) (string, error) {
	return "", plugin.ErrNoOidcBroker
}

// spyDefaultAzureCredential swaps in a counting stand-in for
// newDefaultAzureCredential for the duration of the test, so a test can
// assert the ambient-credential chain was never reached rather than trusting
// the surrounding control flow by inspection.
func spyDefaultAzureCredential(t *testing.T) *int {
	t.Helper()
	calls := 0
	original := newDefaultAzureCredential
	newDefaultAzureCredential = func() (azcore.TokenCredential, error) {
		calls++
		return original()
	}
	t.Cleanup(func() { newDefaultAzureCredential = original })
	return &calls
}

func TestOidcAuthWithoutBrokerFailsClosed(t *testing.T) {
	calls := spyDefaultAzureCredential(t)

	t.Run("no deps at all", func(t *testing.T) {
		c := &Config{SubscriptionId: "sub-1", Auth: json.RawMessage(validOidcAuthJSON)}

		cred, err := c.ToAzureCredential(context.Background())

		require.Error(t, err)
		assert.Nil(t, cred)
		assert.Contains(t, err.Error(), "OIDC token source")
	})

	t.Run("deps present but broker missing", func(t *testing.T) {
		// The credential itself is only a registered callback: constructing
		// it never mints anything, so it succeeds even though the broker
		// behind it cannot serve a token. What must never happen, on this
		// path or the one above, is a fall-through to ambient credentials.
		c := &Config{
			SubscriptionId: "sub-1",
			Auth:           json.RawMessage(validOidcAuthJSON),
			oidc:           NewOidcDeps(brokerlessSource{}),
		}

		cred, err := c.ToAzureCredential(context.Background())

		require.NoError(t, err)
		assert.NotNil(t, cred)

		// The broker's absence surfaces through the exact adapter
		// ToAzureCredential wired the credential to: this is what a real
		// token refresh would receive as its assertion callback's error.
		// This only checks the adapter's pass-through, though - it does not
		// drive a real GetToken through the full MSAL exchange (see
		// TestTheAssertionCallbackObservesTheLiveCallContext for that). The
		// load-bearing assertion for "no ambient fallback" on this subtest
		// is the calls spy checked once below, after both subtests.
		_, tokenErr := brokerClient{src: brokerlessSource{}}.Token(context.Background(), azurex.Audience)
		assert.ErrorIs(t, tokenErr, plugin.ErrNoOidcBroker)
	})

	assert.Equal(t, 0, *calls, "no ambient credential may ever be constructed on an Oidc auth path")
}

func TestAbsentAuthKeepsExistingBehaviour(t *testing.T) {
	c := &Config{SubscriptionId: "sub-1"}

	cred, err := c.ToAzureCredential(context.Background())

	require.NoError(t, err)
	assert.IsType(t, &azidentity.DefaultAzureCredential{}, cred)
}

func TestAnOldSubscriptionOnlyConfigStillParses(t *testing.T) {
	cfg, err := FromTargetConfig(json.RawMessage(`{"SubscriptionId":"sub-1"}`), nil)
	require.NoError(t, err)
	require.Equal(t, "sub-1", cfg.SubscriptionId)

	cred, err := cfg.ToAzureCredential(context.Background())

	require.NoError(t, err)
	assert.NotNil(t, cred)
}

func TestUnknownAuthTypeIsRejected(t *testing.T) {
	c := &Config{SubscriptionId: "sub-1", Auth: json.RawMessage(`{"Type":"Wat"}`)}

	cred, err := c.ToAzureCredential(context.Background())

	require.Error(t, err)
	assert.Nil(t, cred)
	assert.Contains(t, err.Error(), "unknown Auth type")
}

func TestMalformedCoordinatesFailBeforeAnyAzureCall(t *testing.T) {
	deps := NewOidcDeps(brokerlessSource{})
	deps.construct = func(plugin.OidcTokenSource, azurex.Config) (azcore.TokenCredential, error) {
		t.Fatal("no credential may be constructed for malformed coordinates")
		return nil, nil
	}

	c := &Config{
		SubscriptionId: "sub-1",
		Auth:           json.RawMessage(`{"Type":"Oidc","TenantId":"11111111-1111-1111-1111-111111111111","ClientId":"not-a-uuid"}`),
		oidc:           deps,
	}

	cred, err := c.ToAzureCredential(context.Background())

	require.Error(t, err)
	assert.Nil(t, cred)
	assert.Contains(t, err.Error(), "ClientId")
}
