// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypePolicyDefinition = "AZURE::Authorization::PolicyDefinition"

// policyDefinitionsAPI is the subset of *armpolicy.DefinitionsClient used here.
// Everything is synchronous and CreateOrUpdate is also the update verb.
//
// Only the subscription-scoped verbs are used. The management-group variants
// (CreateOrUpdateAtManagementGroup and friends) and the built-in listings are
// deliberately absent: built-ins are read-only, so this provider cannot manage them.
type policyDefinitionsAPI interface {
	CreateOrUpdate(ctx context.Context, policyDefinitionName string, parameters armpolicy.Definition, options *armpolicy.DefinitionsClientCreateOrUpdateOptions) (armpolicy.DefinitionsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, policyDefinitionName string, options *armpolicy.DefinitionsClientGetOptions) (armpolicy.DefinitionsClientGetResponse, error)
	Delete(ctx context.Context, policyDefinitionName string, options *armpolicy.DefinitionsClientDeleteOptions) (armpolicy.DefinitionsClientDeleteResponse, error)
	NewListPager(options *armpolicy.DefinitionsClientListOptions) *runtime.Pager[armpolicy.DefinitionsClientListResponse]
}

func init() {
	registry.Register(ResourceTypePolicyDefinition, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PolicyDefinition{api: c.PolicyDefinitionsClient, config: cfg}
	})
}

// PolicyDefinition is the provisioner for custom Azure Policy definitions
// (Microsoft.Authorization/policyDefinitions) at subscription scope.
type PolicyDefinition struct {
	api    policyDefinitionsAPI
	config *config.Config
}

// policyDefinitionProps mirrors
// schema/pkl/authorization/policydefinition.pkl.
type policyDefinitionProps struct {
	Name        string  `json:"name"`
	DisplayName string  `json:"displayName"`
	Description *string `json:"description"`
	Mode        *string `json:"mode"`
	PolicyRule  string  `json:"policyRule"`
}

const policyDefinitionSegment = "/providers/microsoft.authorization/policydefinitions/"

// policyDefinitionIDParts recovers the definition name. Like role definitions, the
// ID is scope-prefixed rather than resource-group shaped, so armIDParts does not
// apply — but the client is already bound to a subscription, so only the name is
// needed.
func policyDefinitionIDParts(resourceID string) (name string, err error) {
	idx := strings.Index(strings.ToLower(resourceID), policyDefinitionSegment)
	if idx < 0 {
		return "", fmt.Errorf("not a policy definition resource ID: %s", resourceID)
	}
	name = resourceID[idx+len(policyDefinitionSegment):]
	if name == "" {
		return "", fmt.Errorf("not a policy definition resource ID: %s", resourceID)
	}
	return name, nil
}

// canonicalJSON re-encodes a JSON document compactly with sorted keys.
//
// The policy language is arbitrarily nested JSON, so policyRule crosses the wire as
// a string. ARM echoes the rule with its own spacing, and Go's map encoding sorts
// keys, so both directions are put through this before they are compared — without
// it a rule that differs from ARM's formatting only in whitespace or key order would
// read as drift on every sync.
func canonicalJSON(document string) (string, any, error) {
	var parsed any
	if err := json.Unmarshal([]byte(document), &parsed); err != nil {
		return "", nil, fmt.Errorf("policyRule is not valid JSON: %w", err)
	}
	encoded, err := json.Marshal(parsed)
	if err != nil {
		return "", nil, fmt.Errorf("failed to re-encode policyRule: %w", err)
	}
	return string(encoded), parsed, nil
}

func (p *PolicyDefinition) buildPropertiesFromResult(definition *armpolicy.Definition) map[string]any {
	props := make(map[string]any)

	if definition.ID != nil {
		props["id"] = *definition.ID
	}
	if definition.Name != nil {
		props["name"] = *definition.Name
	}

	d := definition.Properties
	if d == nil {
		return props
	}

	if d.DisplayName != nil {
		props["displayName"] = *d.DisplayName
	}
	if d.Description != nil && *d.Description != "" {
		props["description"] = *d.Description
	}
	if d.Mode != nil {
		props["mode"] = *d.Mode
	}
	if d.PolicyType != nil {
		props["policyType"] = string(*d.PolicyType)
	}
	if d.PolicyRule != nil {
		if encoded, err := json.Marshal(d.PolicyRule); err == nil {
			props["policyRule"] = string(encoded)
		}
	}
	// parameters and metadata are arbitrary JSON the schema does not model, and
	// version/versions are service state. None is read back: a value the schema
	// cannot express would drift forever.
	return props
}

// policyDefinitionParams builds the request body shared by create and update.
func policyDefinitionParams(props policyDefinitionProps, policyRule any) armpolicy.Definition {
	definition := armpolicy.Definition{
		Properties: &armpolicy.DefinitionProperties{
			DisplayName: to.Ptr(props.DisplayName),
			Description: props.Description,
			PolicyRule:  policyRule,
			// ARM only accepts Custom here: built-in definitions are read-only, so a
			// definition this provider writes is always custom.
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
		},
	}
	if props.Mode != nil && *props.Mode != "" {
		definition.Properties.Mode = props.Mode
	}
	return definition
}

func (p *PolicyDefinition) parseProps(payload json.RawMessage, label string) (policyDefinitionProps, string, any, error) {
	var props policyDefinitionProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.DisplayName == "" {
		return props, "", nil, fmt.Errorf("displayName is required")
	}
	if props.PolicyRule == "" {
		return props, "", nil, fmt.Errorf("policyRule is required")
	}
	_, rule, err := canonicalJSON(props.PolicyRule)
	if err != nil {
		return props, "", nil, err
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return props, "", nil, fmt.Errorf("name is required")
	}
	return props, name, rule, nil
}

func (p *PolicyDefinition) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, rule, err := p.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdate(ctx, name, policyDefinitionParams(props, rule), nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.Definition))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (p *PolicyDefinition) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	name, err := policyDefinitionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.Definition))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypePolicyDefinition,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: it is the API's only write verb.
func (p *PolicyDefinition) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	name, err := policyDefinitionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, rule, err := p.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdate(ctx, name, policyDefinitionParams(props, rule), nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.Definition))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           request.NativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (p *PolicyDefinition) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	name, err := policyDefinitionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := p.api.Delete(ctx, name, nil); err != nil && !isDeleteSuccessError(err) {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Status can only ever be asked about an operation that already finished: every
// write here is synchronous.
func (p *PolicyDefinition) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates the subscription's definitions, filtered to custom ones: the
// listing also carries every built-in and static definition, none of which this
// provider can manage.
func (p *PolicyDefinition) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	var nativeIDs []string
	pager := p.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list policy definitions: %w", err)
		}
		for _, definition := range page.Value {
			if definition == nil || definition.ID == nil {
				continue
			}
			if d := definition.Properties; d == nil || d.PolicyType == nil || *d.PolicyType != armpolicy.PolicyTypeCustom {
				continue
			}
			nativeIDs = append(nativeIDs, *definition.ID)
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
