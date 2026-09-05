// © 2026 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/platform-engineering-labs/formae/pkg/model"
)

// excluded reports what discovery would do with this resource: run every filter
// that applies to the type and see whether any of them matches.
func excluded(t *testing.T, resourceType, properties string) bool {
	t.Helper()
	filters := model.FiltersForType((&Plugin{}).DiscoveryFilters(), resourceType)
	for i := range filters {
		if filters[i].Excludes(json.RawMessage(properties)) {
			return true
		}
	}
	return false
}

func TestOwnershipMarkerExcludesATaggedResource(t *testing.T) {
	identity := `{"name":"fai-t-i","tags":{"formae-owned":"true"}}`

	assert.True(t, excluded(t, "AZURE::ManagedIdentity::UserAssignedIdentity", identity))
}

func TestOwnershipMarkerLeavesEveryOtherResourceAlone(t *testing.T) {
	assert.False(t, excluded(t, "AZURE::ManagedIdentity::UserAssignedIdentity", `{"name":"someone-elses","tags":{"app":"formae-agent"}}`))
	assert.False(t, excluded(t, "AZURE::ManagedIdentity::UserAssignedIdentity", `{"name":"untagged"}`))
	assert.False(t, excluded(t, "AZURE::ManagedIdentity::UserAssignedIdentity", `{"name":"n","tags":{"formae-owned":"false"}}`))
}

// The federated credential has no tags property at all, so it is identified by
// what connect actually mints: its fixed name, the formae issuer, and a subject
// in formae's namespace. All three must hold.
func TestFederatedCredentialIsExcludedOnNameIssuerAndSubject(t *testing.T) {
	ours := `{"name":"formae-ai","issuer":"https://oidc.cloud.formae.ai","subject":"fai:t/i","audiences":["api://AzureADTokenExchange"]}`

	assert.True(t, excluded(t, "AZURE::ManagedIdentity::FederatedIdentityCredential", ours))
}

func TestFederatedCredentialOnTheFormaeIssuerIsNotEnoughOnItsOwn(t *testing.T) {
	// A customer may legitimately point their own credential at the same
	// issuer; hiding it would take their resource out of their inventory.
	otherSubject := `{"name":"formae-ai","issuer":"https://oidc.cloud.formae.ai","subject":"their-own-workload"}`
	otherName := `{"name":"their-credential","issuer":"https://oidc.cloud.formae.ai","subject":"fai:t/i"}`
	otherIssuer := `{"name":"formae-ai","issuer":"https://token.actions.githubusercontent.com","subject":"fai:t/i"}`

	assert.False(t, excluded(t, "AZURE::ManagedIdentity::FederatedIdentityCredential", otherSubject))
	assert.False(t, excluded(t, "AZURE::ManagedIdentity::FederatedIdentityCredential", otherName))
	assert.False(t, excluded(t, "AZURE::ManagedIdentity::FederatedIdentityCredential", otherIssuer))
}
