// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
)

// Shared helpers for the six AZURE::Logic::IntegrationAccount* child resources
// (schema, map, partner, agreement, certificate, assembly).
//
// All six sit at the same place in the ARM tree —
// Microsoft.Logic/integrationAccounts/{account}/{kind}/{name} — take the same
// three-part identity, and carry a body ARM either does not return at all or
// normalises beyond recognition. Keeping the identity plumbing and the
// business-identity conversion here stops the six of them drifting apart.
//
// Nothing in this file is LRO-aware on purpose: armlogic has no BeginX verb for
// any of these types. Every create, update and delete is synchronous, so none of
// the resources in this group has a Status() that does real work.

// logicChildProps is the identity head every integration-account child carries.
// Each child's own props struct embeds it, so a rename cannot desynchronise
// them.
type logicChildProps struct {
	Name                   string `json:"name"`
	ResourceGroupName      string `json:"resourceGroupName"`
	IntegrationAccountName string `json:"integrationAccountName"`
}

// validate checks the identity triple, falling back to the resource label when
// no explicit name was given (the house convention for every Azure resource
// here).
func (p *logicChildProps) validate(fallbackName string) error {
	if p.ResourceGroupName == "" {
		return fmt.Errorf("resourceGroupName is required")
	}
	if p.IntegrationAccountName == "" {
		return fmt.Errorf("integrationAccountName is required")
	}
	if p.Name == "" {
		p.Name = fallbackName
	}
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	return nil
}

// logicChildIDParts splits an integration-account child's ARM ID.
//
// armExactIDParts rather than armIDParts: the type chain must be exactly
// integrationAccounts/{childType}, so an ID naming some other child kind — a
// session, say, or a batch configuration — is rejected here instead of being
// silently accepted and then 404ing against the wrong client.
func logicChildIDParts(resourceID, childType string) (rgName, accountName, name string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "integrationAccounts", childType)
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

// logicChildBaseProps seeds the read-back property map with the identity triple.
// Both parents come from the native ID rather than the response body: ARM does
// not echo either on a child.
func logicChildBaseProps(rgName, accountName string, id, name *string) map[string]any {
	props := map[string]any{
		"resourceGroupName":      rgName,
		"integrationAccountName": accountName,
	}
	if id != nil {
		props["id"] = *id
	}
	if name != nil {
		props["name"] = *name
	}
	return props
}

// logicBusinessIdentity mirrors the BusinessIdentity nested class declared in
// both logicintegrationaccountpartner.pkl and
// logicintegrationaccountagreement.pkl.
type logicBusinessIdentity struct {
	Qualifier string `json:"qualifier"`
	Value     string `json:"value"`
}

// logicBusinessIdentityToARM converts one identity. A nil result means the
// caller supplied nothing, so the field is left out of the request body rather
// than sent as an empty object.
func logicBusinessIdentityToARM(identity *logicBusinessIdentity) *armlogic.BusinessIdentity {
	if identity == nil || identity.Qualifier == "" || identity.Value == "" {
		return nil
	}
	return &armlogic.BusinessIdentity{
		Qualifier: to.Ptr(identity.Qualifier),
		Value:     to.Ptr(identity.Value),
	}
}

// logicBusinessIdentityProps is the read-path inverse. Returns nil when there is
// nothing to report, so an absent identity is omitted rather than reported as an
// empty object.
func logicBusinessIdentityProps(identity *armlogic.BusinessIdentity) map[string]any {
	if identity == nil {
		return nil
	}
	out := map[string]any{}
	if identity.Qualifier != nil {
		out["qualifier"] = *identity.Qualifier
	}
	if identity.Value != nil {
		out["value"] = *identity.Value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// logicBusinessIdentitiesToARM converts a partner's identity list. Order is
// preserved: ARM stores the list as given.
func logicBusinessIdentitiesToARM(identities []logicBusinessIdentity) []*armlogic.BusinessIdentity {
	if len(identities) == 0 {
		return nil
	}
	out := make([]*armlogic.BusinessIdentity, 0, len(identities))
	for _, identity := range identities {
		converted := logicBusinessIdentityToARM(&identity)
		if converted == nil {
			continue
		}
		out = append(out, converted)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// logicBusinessIdentitiesProps is the read-path inverse, preserving order for
// the same reason.
func logicBusinessIdentitiesProps(identities []*armlogic.BusinessIdentity) []map[string]any {
	if len(identities) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(identities))
	for _, identity := range identities {
		entry := logicBusinessIdentityProps(identity)
		if entry == nil {
			continue
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// logicJSONDocument parses a caller-supplied JSON string into the given target,
// so a malformed or wrongly-shaped document fails before any ARM call rather
// than as an opaque 400.
//
// Used for the two fields this namespace carries as JSON text because no PKL
// class of a workable size describes them: a workflow's definition and an
// agreement's protocol settings.
func logicJSONDocument(field, document string, target any) error {
	if document == "" {
		return fmt.Errorf("%s is required", field)
	}
	if err := json.Unmarshal([]byte(document), target); err != nil {
		return fmt.Errorf("%s is not valid JSON: %w", field, err)
	}
	return nil
}
