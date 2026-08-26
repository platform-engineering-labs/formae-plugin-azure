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

const ResourceTypePolicySetDefinition = "AZURE::Authorization::PolicySetDefinition"

// policySetDefinitionsAPI is the subset of *armpolicy.SetDefinitionsClient used
// here. Everything is synchronous, CreateOrUpdate is also the update verb, and only
// the subscription-scoped verbs are used — as with policy definitions, the
// management-group variants and the built-in listings are out of scope.
type policySetDefinitionsAPI interface {
	CreateOrUpdate(ctx context.Context, policySetDefinitionName string, parameters armpolicy.SetDefinition, options *armpolicy.SetDefinitionsClientCreateOrUpdateOptions) (armpolicy.SetDefinitionsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, policySetDefinitionName string, options *armpolicy.SetDefinitionsClientGetOptions) (armpolicy.SetDefinitionsClientGetResponse, error)
	Delete(ctx context.Context, policySetDefinitionName string, options *armpolicy.SetDefinitionsClientDeleteOptions) (armpolicy.SetDefinitionsClientDeleteResponse, error)
	NewListPager(options *armpolicy.SetDefinitionsClientListOptions) *runtime.Pager[armpolicy.SetDefinitionsClientListResponse]
}

func init() {
	registry.Register(ResourceTypePolicySetDefinition, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PolicySetDefinition{api: c.PolicySetDefinitionsClient, config: cfg}
	})
}

// PolicySetDefinition is the provisioner for custom Azure Policy initiatives
// (Microsoft.Authorization/policySetDefinitions) at subscription scope.
type PolicySetDefinition struct {
	api    policySetDefinitionsAPI
	config *config.Config
}

// policySetDefinitionProps mirrors
// schema/pkl/authorization/policysetdefinition.pkl.
type policySetDefinitionProps struct {
	Name                   string                          `json:"name"`
	DisplayName            string                          `json:"displayName"`
	Description            *string                         `json:"description"`
	PolicyDefinitions      []policySetDefinitionRefProps   `json:"policyDefinitions"`
	PolicyDefinitionGroups []policySetDefinitionGroupProps `json:"policyDefinitionGroups"`
}

type policySetDefinitionRefProps struct {
	PolicyDefinitionID          string   `json:"policyDefinitionId"`
	PolicyDefinitionReferenceID *string  `json:"policyDefinitionReferenceId"`
	GroupNames                  []string `json:"groupNames"`
}

type policySetDefinitionGroupProps struct {
	Name        string  `json:"name"`
	DisplayName *string `json:"displayName"`
	Description *string `json:"description"`
	Category    *string `json:"category"`
}

const policySetDefinitionSegment = "/providers/microsoft.authorization/policysetdefinitions/"

// policySetDefinitionIDParts recovers the initiative name. The client is already
// bound to a subscription, so only the name is needed — but the ID is scope-prefixed
// rather than resource-group shaped, so armIDParts does not apply.
func policySetDefinitionIDParts(resourceID string) (name string, err error) {
	idx := strings.Index(strings.ToLower(resourceID), policySetDefinitionSegment)
	if idx < 0 {
		return "", fmt.Errorf("not a policy set definition resource ID: %s", resourceID)
	}
	name = resourceID[idx+len(policySetDefinitionSegment):]
	if name == "" {
		return "", fmt.Errorf("not a policy set definition resource ID: %s", resourceID)
	}
	return name, nil
}

func (p *PolicySetDefinition) buildPropertiesFromResult(definition *armpolicy.SetDefinition) map[string]any {
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
	if d.PolicyType != nil {
		props["policyType"] = string(*d.PolicyType)
	}

	references := make([]map[string]any, 0, len(d.PolicyDefinitions))
	for _, reference := range d.PolicyDefinitions {
		if reference == nil {
			continue
		}
		entry := make(map[string]any)
		if reference.PolicyDefinitionID != nil {
			entry["policyDefinitionId"] = *reference.PolicyDefinitionID
		}
		if reference.PolicyDefinitionReferenceID != nil && *reference.PolicyDefinitionReferenceID != "" {
			entry["policyDefinitionReferenceId"] = *reference.PolicyDefinitionReferenceID
		}
		if names := stringsFromPointers(reference.GroupNames); names != nil {
			entry["groupNames"] = names
		}
		// Per-inclusion parameters and the three definition-version fields are
		// unmodelled or service state.
		references = append(references, entry)
	}
	if len(references) > 0 {
		props["policyDefinitions"] = references
	}

	groups := make([]map[string]any, 0, len(d.PolicyDefinitionGroups))
	for _, group := range d.PolicyDefinitionGroups {
		if group == nil || group.Name == nil {
			continue
		}
		entry := map[string]any{"name": *group.Name}
		if group.DisplayName != nil && *group.DisplayName != "" {
			entry["displayName"] = *group.DisplayName
		}
		if group.Description != nil && *group.Description != "" {
			entry["description"] = *group.Description
		}
		if group.Category != nil && *group.Category != "" {
			entry["category"] = *group.Category
		}
		// additionalMetadataId points at a resource the schema does not model.
		groups = append(groups, entry)
	}
	if len(groups) > 0 {
		props["policyDefinitionGroups"] = groups
	}

	// parameters and metadata are arbitrary JSON the schema does not model;
	// version/versions and systemData are service state. None is read back.
	return props
}

// policySetDefinitionParams builds the request body shared by create and update.
func policySetDefinitionParams(props policySetDefinitionProps) armpolicy.SetDefinition {
	references := make([]*armpolicy.DefinitionReference, 0, len(props.PolicyDefinitions))
	for _, reference := range props.PolicyDefinitions {
		references = append(references, &armpolicy.DefinitionReference{
			PolicyDefinitionID:          to.Ptr(reference.PolicyDefinitionID),
			PolicyDefinitionReferenceID: reference.PolicyDefinitionReferenceID,
			GroupNames:                  stringPointers(reference.GroupNames),
		})
	}

	definition := armpolicy.SetDefinition{
		Properties: &armpolicy.SetDefinitionProperties{
			DisplayName:       to.Ptr(props.DisplayName),
			Description:       props.Description,
			PolicyDefinitions: references,
			// ARM only accepts Custom here: built-in initiatives are read-only.
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
		},
	}

	if len(props.PolicyDefinitionGroups) > 0 {
		groups := make([]*armpolicy.DefinitionGroup, 0, len(props.PolicyDefinitionGroups))
		for _, group := range props.PolicyDefinitionGroups {
			groups = append(groups, &armpolicy.DefinitionGroup{
				Name:        to.Ptr(group.Name),
				DisplayName: group.DisplayName,
				Description: group.Description,
				Category:    group.Category,
			})
		}
		definition.Properties.PolicyDefinitionGroups = groups
	}

	return definition
}

func (p *PolicySetDefinition) parseProps(payload json.RawMessage, label string) (policySetDefinitionProps, string, error) {
	var props policySetDefinitionProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.DisplayName == "" {
		return props, "", fmt.Errorf("displayName is required")
	}
	if len(props.PolicyDefinitions) == 0 {
		return props, "", fmt.Errorf("policyDefinitions is required")
	}
	for _, reference := range props.PolicyDefinitions {
		if reference.PolicyDefinitionID == "" {
			return props, "", fmt.Errorf("policyDefinitions[].policyDefinitionId is required")
		}
	}

	// A group name on an inclusion has to match a declared group, or ARM rejects the
	// whole initiative. Caught here because the service reports it as a generic
	// invalid-request at PUT time.
	declared := make(map[string]bool, len(props.PolicyDefinitionGroups))
	for _, group := range props.PolicyDefinitionGroups {
		if group.Name == "" {
			return props, "", fmt.Errorf("policyDefinitionGroups[].name is required")
		}
		declared[group.Name] = true
	}
	for _, reference := range props.PolicyDefinitions {
		for _, name := range reference.GroupNames {
			if !declared[name] {
				return props, "", fmt.Errorf("policyDefinitions[].groupNames references undeclared group %q; declare it in policyDefinitionGroups", name)
			}
		}
	}

	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return props, "", fmt.Errorf("name is required")
	}
	return props, name, nil
}

func (p *PolicySetDefinition) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := p.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdate(ctx, name, policySetDefinitionParams(props), nil)
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
	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.SetDefinition))
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

func (p *PolicySetDefinition) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	name, err := policySetDefinitionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.SetDefinition))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypePolicySetDefinition,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: it is the API's only write verb.
func (p *PolicySetDefinition) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	name, err := policySetDefinitionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := p.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	result, err := p.api.CreateOrUpdate(ctx, name, policySetDefinitionParams(props), nil)
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

	propsJSON, err := json.Marshal(p.buildPropertiesFromResult(&result.SetDefinition))
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

func (p *PolicySetDefinition) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	name, err := policySetDefinitionIDParts(request.NativeID)
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
func (p *PolicySetDefinition) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates the subscription's initiatives, filtered to custom ones: the
// listing also carries every built-in and static initiative, none of which this
// provider can manage.
func (p *PolicySetDefinition) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	var nativeIDs []string
	pager := p.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list policy set definitions: %w", err)
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
