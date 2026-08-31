// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/uuid"
)

// Config holds Azure-specific configuration extracted from a Target.
type Config struct {
	SubscriptionId string

	// Auth is the target's authentication strategy, as rendered by the Pkl
	// schema. Absent means the historical behaviour: the ambient default
	// credential chain (environment variables, managed identity, `az
	// login`, etc).
	Auth json.RawMessage

	// oidc carries the plugin instance's OIDC deps: the token source and the
	// per-instance credential cache. Never serialized. Nil means this
	// instance has none wired, so an Oidc auth block fails closed rather
	// than falling back to ambient credentials.
	oidc *OidcDeps
}

// rawTargetConfig is the JSON shape a target config unmarshals into.
type rawTargetConfig struct {
	SubscriptionId string          `json:"SubscriptionId"`
	Auth           json.RawMessage `json:"Auth,omitempty"`
}

// FromTargetConfig extracts Azure configuration from target config JSON.
//
// deps is a required argument, not something attached afterwards: a Config
// that reaches ToAzureCredential without it cannot authenticate an Oidc
// target, so requiring it here turns a forgotten call site into a compile
// error rather than a config that silently fails closed at runtime. Pass nil
// from a caller that genuinely has no OIDC token source wired.
func FromTargetConfig(targetConfig json.RawMessage, deps *OidcDeps) (*Config, error) {
	if targetConfig == nil {
		return nil, fmt.Errorf("azure target config is required")
	}

	var raw rawTargetConfig
	if err := json.Unmarshal(targetConfig, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse Azure target config: %w", err)
	}

	subscriptionID := strings.TrimSpace(raw.SubscriptionId)
	if subscriptionID == "" {
		return nil, fmt.Errorf("azure target config requires non-empty SubscriptionId")
	}

	return &Config{
		SubscriptionId: subscriptionID,
		Auth:           raw.Auth,
		oidc:           deps,
	}, nil
}

// authDiscriminator is the shape every Auth block variant shares.
type authDiscriminator struct {
	Type string `json:"Type"`
}

// effectiveAuth reports the auth type this config resolves to, and the raw
// block that backs it. An absent block means the default chain, which is
// what every target used before this block existed.
//
// An unknown Type is an error rather than a fall-through: silently treating
// an auth block nobody understands as "use ambient credentials" is how a
// hosted agent ends up acting as itself instead of as the customer.
func (c *Config) effectiveAuth() (string, json.RawMessage, error) {
	if len(c.Auth) == 0 || string(c.Auth) == "null" {
		return "", nil, nil
	}

	var disc authDiscriminator
	if err := json.Unmarshal(c.Auth, &disc); err != nil {
		return "", nil, fmt.Errorf("config: malformed Auth block: %w", err)
	}
	if disc.Type == "" {
		return "", nil, errors.New("config: Auth block is missing its Type discriminator")
	}
	if disc.Type != AuthTypeOidc {
		return "", nil, fmt.Errorf("config: unknown Auth type %q", disc.Type)
	}

	return disc.Type, c.Auth, nil
}

// oidcAuthBlock is the JSON shape of an OidcAuth block, as rendered by the
// Pkl schema.
type oidcAuthBlock struct {
	TenantId string `json:"TenantId"`
	ClientId string `json:"ClientId"`
}

// newDefaultAzureCredential builds the ambient-credential chain used when a
// target carries no Auth block. A seam so a test can assert it is never
// reached on an Oidc-auth path, rather than trusting the surrounding control
// flow by inspection.
var newDefaultAzureCredential = func() (azcore.TokenCredential, error) {
	return azidentity.NewDefaultAzureCredential(nil)
}

// ToAzureCredential resolves this config's effective auth into Azure
// credentials.
//
// This is the single credential seam, so it is also where an Oidc auth
// block's coordinates are validated: a malformed TenantId or ClientId fails
// here, before any credential is constructed and before any Azure call is
// made.
//
// With no auth block, credentials come from the default chain exactly as
// before this block existed: environment variables, managed identity, `az
// login`, etc.
func (c *Config) ToAzureCredential(ctx context.Context) (azcore.TokenCredential, error) {
	authType, raw, err := c.effectiveAuth()
	if err != nil {
		return nil, err
	}
	if authType == "" {
		return newDefaultAzureCredential()
	}

	var auth oidcAuthBlock
	if err := json.Unmarshal(raw, &auth); err != nil {
		return nil, fmt.Errorf("config: malformed Oidc auth block: %w", err)
	}
	if _, err := uuid.Parse(auth.TenantId); err != nil {
		return nil, fmt.Errorf("config: Oidc auth TenantId must be a UUID: %w", err)
	}
	if _, err := uuid.Parse(auth.ClientId); err != nil {
		return nil, fmt.Errorf("config: Oidc auth ClientId must be a UUID: %w", err)
	}

	if c.oidc == nil || c.oidc.Source == nil {
		return nil, errors.New("config: Oidc auth requires an OIDC token source, but this plugin instance has none wired " +
			"(failing closed rather than falling back to ambient credentials)")
	}

	return c.oidc.credentialFor(auth.TenantId, auth.ClientId)
}
