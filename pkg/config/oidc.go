// © 2026 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"context"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/platform-engineering-labs/formae/pkg/plugin"
	azurex "github.com/platform-engineering-labs/oox/oidcx/azure"
)

// AuthTypeOidc is the discriminator value the Pkl schema renders on an
// OidcAuth block, matching its `Type` field.
const AuthTypeOidc = "Oidc"

// OidcDeps is owned by the Plugin instance, never process-global: ownership
// is what scopes the credential cache to one plugin instance, and a global
// could hand installation A's credential to installation B, whose deps point
// at a different broker.
//
// A Config with nil deps fails closed on Oidc auth: it never falls back to
// ambient credentials, because in a hosted installation "ambient" is
// whatever happens to be lying around in the agent's own environment.
type OidcDeps struct {
	// Source mints the OIDC identity tokens exchanged for Azure credentials.
	Source plugin.OidcTokenSource

	// creds caches the constructed credential itself, keyed by tenant and
	// client id only - not by scopes. Unlike GCP,
	// azidentity.ClientAssertionCredential takes scopes per GetToken call
	// and is not bound to a scope set, so keying by scopes would build
	// redundant credentials for nothing.
	//
	// Caching the credential object is safe here in a way it is not for
	// GCP: GetToken(ctx) carries the live call context all the way to the
	// assertion callback (verified from source), so one credential can serve
	// every operation without ever replaying a stopped actor's context.
	creds sync.Map

	// construct builds one Azure credential for a (tenant, client) pair. A
	// seam for tests; production wiring is defaultConstruct.
	construct func(src plugin.OidcTokenSource, cfg azurex.Config) (azcore.TokenCredential, error)
}

// NewOidcDeps builds the OidcDeps a Plugin instance owns, wired to exchange
// identity tokens for Azure credentials for real.
func NewOidcDeps(src plugin.OidcTokenSource) *OidcDeps {
	return &OidcDeps{Source: src, construct: defaultConstruct}
}

// brokerClient adapts the plugin SDK's token source to the oidcx.Client the
// oidcx/azure exchange expects.
type brokerClient struct{ src plugin.OidcTokenSource }

func (b brokerClient) Token(ctx context.Context, audience string) (string, error) {
	return b.src.IdentityToken(ctx, audience)
}

// defaultConstruct builds the real oidcx/azure credential, backed by the
// broker's token source. Production wiring passes nil options: azurex.Credential's
// options parameter exists so tests can inject a transport and disable
// instance discovery, neither of which a real plugin instance needs.
func defaultConstruct(src plugin.OidcTokenSource, cfg azurex.Config) (azcore.TokenCredential, error) {
	return azurex.Credential(brokerClient{src: src}, cfg, nil)
}

// credentialFor returns the cached credential for tenantID and clientID,
// constructing it on first use.
func (d *OidcDeps) credentialFor(tenantID, clientID string) (azcore.TokenCredential, error) {
	key := tenantID + "\x00" + clientID
	if cached, ok := d.creds.Load(key); ok {
		return cached.(azcore.TokenCredential), nil
	}

	construct := d.construct
	if construct == nil {
		construct = defaultConstruct
	}

	cfg := azurex.NewConfig(nil)
	cfg.TenantID = tenantID
	cfg.ClientID = clientID

	cred, err := construct(d.Source, cfg)
	if err != nil {
		return nil, err
	}

	actual, _ := d.creds.LoadOrStore(key, cred)
	return actual.(azcore.TokenCredential), nil
}
