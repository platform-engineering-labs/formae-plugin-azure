// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package client

import (
	"context"
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
	clientCache = map[string]*Client{}
	t.Cleanup(func() {
		newCredential = orig
		clientCache = map[string]*Client{}
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
