// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeStorageManagementPolicy = "AZURE::Storage::ManagementPolicy"

// managementPoliciesAPI is the armstorage surface used here; all operations are
// synchronous. There is no List: ARM models the policy as a singleton child.
type managementPoliciesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, accountName string, managementPolicyName armstorage.ManagementPolicyName, properties armstorage.ManagementPolicy, options *armstorage.ManagementPoliciesClientCreateOrUpdateOptions) (armstorage.ManagementPoliciesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, accountName string, managementPolicyName armstorage.ManagementPolicyName, options *armstorage.ManagementPoliciesClientGetOptions) (armstorage.ManagementPoliciesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, accountName string, managementPolicyName armstorage.ManagementPolicyName, options *armstorage.ManagementPoliciesClientDeleteOptions) (armstorage.ManagementPoliciesClientDeleteResponse, error)
}

func init() {
	registry.Register(ResourceTypeStorageManagementPolicy, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &StorageManagementPolicy{api: c.StorageManagementPoliciesClient, config: cfg}
	})
}

// StorageManagementPolicy provisions the blob lifecycle policy of a storage
// account (`Microsoft.Storage/storageAccounts/<account>/managementPolicies/default`).
// The ARM name is always `default`, so the resource has no name property.
type StorageManagementPolicy struct {
	api    managementPoliciesAPI
	config *config.Config
}

// storageManagementPolicyProps mirrors schema/pkl/storage/managementpolicy.pkl.
type storageManagementPolicyProps struct {
	ResourceGroupName  string                      `json:"resourceGroupName"`
	StorageAccountName string                      `json:"storageAccountName"`
	Rules              []managementPolicyRuleProps `json:"rules"`
}

type managementPolicyRuleProps struct {
	Name       string                          `json:"name"`
	Enabled    *bool                           `json:"enabled"`
	Definition managementPolicyDefinitionProps `json:"definition"`
}

type managementPolicyDefinitionProps struct {
	Actions managementPolicyActionsProps `json:"actions"`
	Filters managementPolicyFiltersProps `json:"filters"`
}

type managementPolicyActionsProps struct {
	BaseBlob managementPolicyBaseBlobProps `json:"baseBlob"`
}

type managementPolicyBaseBlobProps struct {
	TierToCool    *daysAfterModificationProps `json:"tierToCool"`
	TierToArchive *daysAfterModificationProps `json:"tierToArchive"`
	Delete        *daysAfterModificationProps `json:"deleteAfter"`
}

type daysAfterModificationProps struct {
	DaysAfterModificationGreaterThan int `json:"daysAfterModificationGreaterThan"`
}

type managementPolicyFiltersProps struct {
	BlobTypes   []string `json:"blobTypes"`
	PrefixMatch []string `json:"prefixMatch"`
}

func daysToARM(d *daysAfterModificationProps) *armstorage.DateAfterModification {
	if d == nil {
		return nil
	}
	days := float32(d.DaysAfterModificationGreaterThan)
	return &armstorage.DateAfterModification{DaysAfterModificationGreaterThan: &days}
}

func daysFromARM(d *armstorage.DateAfterModification) *daysAfterModificationProps {
	if d == nil || d.DaysAfterModificationGreaterThan == nil {
		return nil
	}
	return &daysAfterModificationProps{DaysAfterModificationGreaterThan: int(*d.DaysAfterModificationGreaterThan)}
}

// managementPolicyFromProps builds the ARM body. Every rule is type Lifecycle —
// ARM has no other rule type today, so it is not exposed in the schema.
func managementPolicyFromProps(props storageManagementPolicyProps) armstorage.ManagementPolicy {
	rules := make([]*armstorage.ManagementPolicyRule, 0, len(props.Rules))
	for _, r := range props.Rules {
		ruleType := armstorage.RuleTypeLifecycle
		enabled := true
		if r.Enabled != nil {
			enabled = *r.Enabled
		}
		name := r.Name

		filters := &armstorage.ManagementPolicyFilter{}
		for _, bt := range r.Definition.Filters.BlobTypes {
			blobType := bt
			filters.BlobTypes = append(filters.BlobTypes, &blobType)
		}
		for _, pm := range r.Definition.Filters.PrefixMatch {
			prefix := pm
			filters.PrefixMatch = append(filters.PrefixMatch, &prefix)
		}

		rules = append(rules, &armstorage.ManagementPolicyRule{
			Name:    &name,
			Enabled: &enabled,
			Type:    &ruleType,
			Definition: &armstorage.ManagementPolicyDefinition{
				Actions: &armstorage.ManagementPolicyAction{
					BaseBlob: &armstorage.ManagementPolicyBaseBlob{
						TierToCool:    daysToARM(r.Definition.Actions.BaseBlob.TierToCool),
						TierToArchive: daysToARM(r.Definition.Actions.BaseBlob.TierToArchive),
						Delete:        daysToARM(r.Definition.Actions.BaseBlob.Delete),
					},
				},
				Filters: filters,
			},
		})
	}

	return armstorage.ManagementPolicy{
		Properties: &armstorage.ManagementPolicyProperties{
			Policy: &armstorage.ManagementPolicySchema{Rules: rules},
		},
	}
}

func serializeStorageManagementPolicyProperties(result armstorage.ManagementPolicy, rgName, accountName string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName":  rgName,
		"storageAccountName": accountName,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	rules := make([]map[string]any, 0)
	if result.Properties != nil && result.Properties.Policy != nil {
		for _, r := range result.Properties.Policy.Rules {
			if r == nil {
				continue
			}
			rule := map[string]any{}
			if r.Name != nil {
				rule["name"] = *r.Name
			}
			if r.Enabled != nil {
				rule["enabled"] = *r.Enabled
			}

			baseBlob := map[string]any{}
			filters := map[string]any{}
			if r.Definition != nil {
				if r.Definition.Actions != nil && r.Definition.Actions.BaseBlob != nil {
					bb := r.Definition.Actions.BaseBlob
					if d := daysFromARM(bb.TierToCool); d != nil {
						baseBlob["tierToCool"] = map[string]any{"daysAfterModificationGreaterThan": d.DaysAfterModificationGreaterThan}
					}
					if d := daysFromARM(bb.TierToArchive); d != nil {
						baseBlob["tierToArchive"] = map[string]any{"daysAfterModificationGreaterThan": d.DaysAfterModificationGreaterThan}
					}
					if d := daysFromARM(bb.Delete); d != nil {
						baseBlob["deleteAfter"] = map[string]any{"daysAfterModificationGreaterThan": d.DaysAfterModificationGreaterThan}
					}
				}
				if r.Definition.Filters != nil {
					blobTypes := make([]string, 0, len(r.Definition.Filters.BlobTypes))
					for _, bt := range r.Definition.Filters.BlobTypes {
						if bt != nil {
							blobTypes = append(blobTypes, *bt)
						}
					}
					if len(blobTypes) > 0 {
						filters["blobTypes"] = blobTypes
					}
					prefixes := make([]string, 0, len(r.Definition.Filters.PrefixMatch))
					for _, pm := range r.Definition.Filters.PrefixMatch {
						if pm != nil {
							prefixes = append(prefixes, *pm)
						}
					}
					if len(prefixes) > 0 {
						filters["prefixMatch"] = prefixes
					}
				}
			}
			rule["definition"] = map[string]any{
				"actions": map[string]any{"baseBlob": baseBlob},
				"filters": filters,
			}
			rules = append(rules, rule)
		}
	}
	props["rules"] = rules

	return json.Marshal(props)
}

func (m *StorageManagementPolicy) parseNativeID(nativeID string) (rgName, accountName string, err error) {
	rgName, names, err := armIDParts(nativeID, "storageaccounts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["storageaccounts"], nil
}

func (m *StorageManagementPolicy) upsert(ctx context.Context, payload json.RawMessage) (armstorage.ManagementPolicy, string, string, error) {
	var props storageManagementPolicyProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armstorage.ManagementPolicy{}, "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return armstorage.ManagementPolicy{}, "", "", fmt.Errorf("resourceGroupName is required")
	}
	if props.StorageAccountName == "" {
		return armstorage.ManagementPolicy{}, "", "", fmt.Errorf("storageAccountName is required")
	}
	if len(props.Rules) == 0 {
		return armstorage.ManagementPolicy{}, "", "", fmt.Errorf("at least one rule is required")
	}

	result, err := m.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.StorageAccountName,
		armstorage.ManagementPolicyNameDefault, managementPolicyFromProps(props), nil)
	if err != nil {
		return armstorage.ManagementPolicy{}, props.ResourceGroupName, props.StorageAccountName, err
	}
	return result.ManagementPolicy, props.ResourceGroupName, props.StorageAccountName, nil
}

func (m *StorageManagementPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	policy, rgName, accountName, err := m.upsert(ctx, request.Properties)
	if err != nil {
		if rgName == "" || accountName == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeStorageManagementPolicyProperties(policy, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ManagementPolicy properties: %w", err)
	}

	nativeID := ""
	if policy.ID != nil {
		nativeID = *policy.ID
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

func (m *StorageManagementPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, err := m.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, accountName, armstorage.ManagementPolicyNameDefault, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeStorageManagementPolicyProperties(result.ManagementPolicy, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ManagementPolicy properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeStorageManagementPolicy,
		Properties:   string(propsJSON),
	}, nil
}

// Update is the same CreateOrUpdate call: ARM replaces the whole rule set.
func (m *StorageManagementPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	policy, rgName, accountName, err := m.upsert(ctx, request.DesiredProperties)
	if err != nil {
		if rgName == "" || accountName == "" {
			return nil, err
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeStorageManagementPolicyProperties(policy, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ManagementPolicy properties after update: %w", err)
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

func (m *StorageManagementPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, err := m.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := m.api.Delete(ctx, rgName, accountName, armstorage.ManagementPolicyNameDefault, nil); err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
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

// ManagementPolicy writes are synchronous, so Status just re-reads.
func (m *StorageManagementPolicy) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, accountName, err := m.parseNativeID(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	result, err := m.api.Get(ctx, rgName, accountName, armstorage.ManagementPolicyNameDefault, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to get ManagementPolicy status: %w", err)
	}

	propsJSON, err := serializeStorageManagementPolicyProperties(result.ManagementPolicy, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ManagementPolicy properties: %w", err)
	}
	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

// List has no ARM list operation to call: the policy is a singleton per account,
// so discovery probes the one `default` policy and reports it only if it exists.
func (m *StorageManagementPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["storageAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	result, err := m.api.Get(ctx, rgName, accountName, armstorage.ManagementPolicyNameDefault, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.ListResult{}, nil
		}
		return nil, fmt.Errorf("failed to list ManagementPolicies: %w", err)
	}
	if result.ID == nil {
		return &resource.ListResult{}, nil
	}
	return &resource.ListResult{NativeIDs: []string{*result.ID}}, nil
}
