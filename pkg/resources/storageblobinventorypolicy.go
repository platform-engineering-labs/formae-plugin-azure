// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeStorageBlobInventoryPolicy = "AZURE::Storage::BlobInventoryPolicy"

// storageBlobInventoryPoliciesAPI is the armstorage surface used here. All three
// verbs are synchronous, and NewListPager is not used: the policy is a singleton
// named `default`, so discovery probes it with Get.
type storageBlobInventoryPoliciesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, accountName string, blobInventoryPolicyName armstorage.BlobInventoryPolicyName, properties armstorage.BlobInventoryPolicy, options *armstorage.BlobInventoryPoliciesClientCreateOrUpdateOptions) (armstorage.BlobInventoryPoliciesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, accountName string, blobInventoryPolicyName armstorage.BlobInventoryPolicyName, options *armstorage.BlobInventoryPoliciesClientGetOptions) (armstorage.BlobInventoryPoliciesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, accountName string, blobInventoryPolicyName armstorage.BlobInventoryPolicyName, options *armstorage.BlobInventoryPoliciesClientDeleteOptions) (armstorage.BlobInventoryPoliciesClientDeleteResponse, error)
}

func init() {
	registry.Register(ResourceTypeStorageBlobInventoryPolicy, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &StorageBlobInventoryPolicy{api: c.StorageBlobInventoryPoliciesClient, config: cfg}
	})
}

// StorageBlobInventoryPolicy provisions the blob inventory policy of a storage
// account (`Microsoft.Storage/storageAccounts/<account>/inventoryPolicies/default`).
// The ARM name is always `default`, so the resource has no name property.
type StorageBlobInventoryPolicy struct {
	api    storageBlobInventoryPoliciesAPI
	config *config.Config
}

// storageBlobInventoryPolicyProps mirrors
// schema/pkl/storage/storageblobinventorypolicy.pkl.
type storageBlobInventoryPolicyProps struct {
	ResourceGroupName  string                    `json:"resourceGroupName"`
	StorageAccountName string                    `json:"storageAccountName"`
	Enabled            *bool                     `json:"enabled"`
	Rules              []blobInventoryPolicyRule `json:"rules"`
}

type blobInventoryPolicyRule struct {
	Name        string                        `json:"name"`
	Destination string                        `json:"destination"`
	Enabled     *bool                         `json:"enabled"`
	Definition  blobInventoryPolicyDefinition `json:"definition"`
}

type blobInventoryPolicyDefinition struct {
	Format       string                      `json:"format"`
	ObjectType   string                      `json:"objectType"`
	Schedule     string                      `json:"schedule"`
	SchemaFields []string                    `json:"schemaFields"`
	Filters      *blobInventoryPolicyFilters `json:"filters"`
}

type blobInventoryPolicyFilters struct {
	BlobTypes           []string `json:"blobTypes"`
	PrefixMatch         []string `json:"prefixMatch"`
	ExcludePrefix       []string `json:"excludePrefix"`
	IncludeBlobVersions *bool    `json:"includeBlobVersions"`
	IncludeSnapshots    *bool    `json:"includeSnapshots"`
	IncludeDeleted      *bool    `json:"includeDeleted"`
}

// blobInventoryPolicyFromProps builds the ARM body. The policy type is always
// `Inventory` — ARM accepts no other value — so it is set here rather than in the
// schema.
func blobInventoryPolicyFromProps(props storageBlobInventoryPolicyProps) armstorage.BlobInventoryPolicy {
	rules := make([]*armstorage.BlobInventoryPolicyRule, 0, len(props.Rules))
	for _, r := range props.Rules {
		def := &armstorage.BlobInventoryPolicyDefinition{
			Format:       to.Ptr(armstorage.Format(r.Definition.Format)),
			ObjectType:   to.Ptr(armstorage.ObjectType(r.Definition.ObjectType)),
			Schedule:     to.Ptr(armstorage.Schedule(r.Definition.Schedule)),
			SchemaFields: stringPointers(r.Definition.SchemaFields),
		}
		if f := r.Definition.Filters; f != nil {
			filters := &armstorage.BlobInventoryPolicyFilter{
				BlobTypes:     stringPointers(f.BlobTypes),
				PrefixMatch:   stringPointers(f.PrefixMatch),
				ExcludePrefix: stringPointers(f.ExcludePrefix),
			}
			if f.IncludeBlobVersions != nil {
				filters.IncludeBlobVersions = to.Ptr(*f.IncludeBlobVersions)
			}
			if f.IncludeSnapshots != nil {
				filters.IncludeSnapshots = to.Ptr(*f.IncludeSnapshots)
			}
			if f.IncludeDeleted != nil {
				filters.IncludeDeleted = to.Ptr(*f.IncludeDeleted)
			}
			def.Filters = filters
		}

		rules = append(rules, &armstorage.BlobInventoryPolicyRule{
			Name:        to.Ptr(r.Name),
			Destination: to.Ptr(r.Destination),
			Enabled:     to.Ptr(r.Enabled == nil || *r.Enabled),
			Definition:  def,
		})
	}

	return armstorage.BlobInventoryPolicy{
		Properties: &armstorage.BlobInventoryPolicyProperties{
			Policy: &armstorage.BlobInventoryPolicySchema{
				Enabled: to.Ptr(props.Enabled == nil || *props.Enabled),
				Type:    to.Ptr(armstorage.InventoryRuleTypeInventory),
				Rules:   rules,
			},
		},
	}
}

func serializeStorageBlobInventoryPolicyProperties(result armstorage.BlobInventoryPolicy, rgName, accountName string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName":  rgName,
		"storageAccountName": accountName,
		"enabled":            true,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	rules := make([]map[string]any, 0)
	if result.Properties != nil && result.Properties.Policy != nil {
		policy := result.Properties.Policy
		if policy.Enabled != nil {
			props["enabled"] = *policy.Enabled
		}
		for _, r := range policy.Rules {
			if r == nil {
				continue
			}
			rule := map[string]any{"enabled": true}
			if r.Name != nil {
				rule["name"] = *r.Name
			}
			if r.Destination != nil {
				rule["destination"] = *r.Destination
			}
			if r.Enabled != nil {
				rule["enabled"] = *r.Enabled
			}
			if r.Definition != nil {
				rule["definition"] = serializeBlobInventoryDefinition(r.Definition)
			}
			rules = append(rules, rule)
		}
	}
	props["rules"] = rules

	return json.Marshal(props)
}

func serializeBlobInventoryDefinition(def *armstorage.BlobInventoryPolicyDefinition) map[string]any {
	out := map[string]any{}
	if def.Format != nil {
		out["format"] = string(*def.Format)
	}
	if def.ObjectType != nil {
		out["objectType"] = string(*def.ObjectType)
	}
	if def.Schedule != nil {
		out["schedule"] = string(*def.Schedule)
	}
	if fields := stringsFromPointers(def.SchemaFields); len(fields) > 0 {
		out["schemaFields"] = fields
	}
	if def.Filters == nil {
		return out
	}

	filters := map[string]any{}
	if v := stringsFromPointers(def.Filters.BlobTypes); len(v) > 0 {
		filters["blobTypes"] = v
	}
	if v := stringsFromPointers(def.Filters.PrefixMatch); len(v) > 0 {
		filters["prefixMatch"] = v
	}
	if v := stringsFromPointers(def.Filters.ExcludePrefix); len(v) > 0 {
		filters["excludePrefix"] = v
	}
	// The three include-flags have no schema default, so a false ARM echoes for a
	// flag the caller never set would read as drift; only a true is meaningful.
	if def.Filters.IncludeBlobVersions != nil && *def.Filters.IncludeBlobVersions {
		filters["includeBlobVersions"] = true
	}
	if def.Filters.IncludeSnapshots != nil && *def.Filters.IncludeSnapshots {
		filters["includeSnapshots"] = true
	}
	if def.Filters.IncludeDeleted != nil && *def.Filters.IncludeDeleted {
		filters["includeDeleted"] = true
	}
	if len(filters) > 0 {
		out["filters"] = filters
	}
	return out
}

func (p *StorageBlobInventoryPolicy) parseNativeID(nativeID string) (rgName, accountName string, err error) {
	rgName, names, err := armIDParts(nativeID, "storageaccounts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["storageaccounts"], nil
}

func (p *StorageBlobInventoryPolicy) upsert(ctx context.Context, payload json.RawMessage) (armstorage.BlobInventoryPolicy, string, string, error) {
	var props storageBlobInventoryPolicyProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armstorage.BlobInventoryPolicy{}, "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return armstorage.BlobInventoryPolicy{}, "", "", fmt.Errorf("resourceGroupName is required")
	}
	if props.StorageAccountName == "" {
		return armstorage.BlobInventoryPolicy{}, "", "", fmt.Errorf("storageAccountName is required")
	}
	if len(props.Rules) == 0 {
		return armstorage.BlobInventoryPolicy{}, "", "", fmt.Errorf("at least one rule is required")
	}

	result, err := p.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.StorageAccountName,
		armstorage.BlobInventoryPolicyNameDefault, blobInventoryPolicyFromProps(props), nil)
	if err != nil {
		return armstorage.BlobInventoryPolicy{}, props.ResourceGroupName, props.StorageAccountName, err
	}
	return result.BlobInventoryPolicy, props.ResourceGroupName, props.StorageAccountName, nil
}

func (p *StorageBlobInventoryPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	policy, rgName, accountName, err := p.upsert(ctx, request.Properties)
	if err != nil {
		if rgName == "" || accountName == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := serializeStorageBlobInventoryPolicyProperties(policy, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize BlobInventoryPolicy properties: %w", err)
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

func (p *StorageBlobInventoryPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, err := p.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := p.api.Get(ctx, rgName, accountName, armstorage.BlobInventoryPolicyNameDefault, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeStorageBlobInventoryPolicyProperties(result.BlobInventoryPolicy, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize BlobInventoryPolicy properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeStorageBlobInventoryPolicy,
		Properties:   string(propsJSON),
	}, nil
}

// Update is the same CreateOrUpdate call: ARM replaces the whole rule set.
func (p *StorageBlobInventoryPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	policy, rgName, accountName, err := p.upsert(ctx, request.DesiredProperties)
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
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := serializeStorageBlobInventoryPolicyProperties(policy, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize BlobInventoryPolicy properties after update: %w", err)
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

func (p *StorageBlobInventoryPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, err := p.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := p.api.Delete(ctx, rgName, accountName, armstorage.BlobInventoryPolicyNameDefault, nil); err != nil {
		if isDeleteSuccessError(err) {
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
				StatusMessage:   err.Error(),
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

// Inventory-policy writes are synchronous, so Status just re-reads.
func (p *StorageBlobInventoryPolicy) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, accountName, err := p.parseNativeID(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   err.Error(),
			},
		}, err
	}

	result, err := p.api.Get(ctx, rgName, accountName, armstorage.BlobInventoryPolicyNameDefault, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, fmt.Errorf("failed to get BlobInventoryPolicy status: %w", err)
	}

	propsJSON, err := serializeStorageBlobInventoryPolicyProperties(result.BlobInventoryPolicy, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize BlobInventoryPolicy properties: %w", err)
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

// List probes the one `default` policy: the ARM list operation exists but returns
// the same singleton, and an account with no policy must list as empty rather than
// error, or discovery of every account without an inventory policy fails.
func (p *StorageBlobInventoryPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["storageAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	result, err := p.api.Get(ctx, rgName, accountName, armstorage.BlobInventoryPolicyNameDefault, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.ListResult{}, nil
		}
		return nil, fmt.Errorf("failed to list BlobInventoryPolicies: %w", err)
	}
	if result.ID == nil {
		return &resource.ListResult{}, nil
	}
	return &resource.ListResult{NativeIDs: []string{*result.ID}}, nil
}
