// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeKeyVaultAccessPolicy = "AZURE::KeyVault::AccessPolicy"

// vaultAccessPolicyAPI is the armkeyvault.VaultsClient surface used here. Both
// operations are synchronous.
//
// This is a second, narrower view of the same client AZURE::KeyVault::Vault uses;
// it is declared separately rather than widening that resource's vaultsAPI so the
// two resources can evolve independently.
type vaultAccessPolicyAPI interface {
	Get(ctx context.Context, resourceGroupName string, vaultName string, options *armkeyvault.VaultsClientGetOptions) (armkeyvault.VaultsClientGetResponse, error)
	UpdateAccessPolicy(ctx context.Context, resourceGroupName string, vaultName string, operationKind armkeyvault.AccessPolicyUpdateKind, parameters armkeyvault.VaultAccessPolicyParameters, options *armkeyvault.VaultsClientUpdateAccessPolicyOptions) (armkeyvault.VaultsClientUpdateAccessPolicyResponse, error)
}

func init() {
	registry.Register(ResourceTypeKeyVaultAccessPolicy, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &KeyVaultAccessPolicy{api: c.VaultsClient, config: cfg}
	})
}

// KeyVaultAccessPolicy provisions one entry of a Key Vault's access policy list.
//
// An access policy is not a first-class ARM resource with its own PUT: it is a
// mutation of the parent vault through
// `POST .../vaults/{vault}/accessPolicies/{add|replace|remove}`. `replace` would
// overwrite the vault's whole list, so this resource only ever uses `add` and
// `remove`, which touch a single entry and leave every other policy alone.
//
// The identity is the object id. ARM guarantees it is unique within a vault's
// policy list, so `<vault id>/accessPolicies/<objectId>` is a stable NativeID even
// though ARM never mints that id itself.
//
// Note that a vault with `enableRbacAuthorization = true` ignores access policies
// entirely: the entry is stored and read back, but grants nothing. Declare this
// resource only against a vault in access-policy mode.
type KeyVaultAccessPolicy struct {
	api    vaultAccessPolicyAPI
	config *config.Config
}

// keyVaultAccessPolicyProps mirrors schema/pkl/keyvault/accesspolicy.pkl.
type keyVaultAccessPolicyProps struct {
	ResourceGroupName string                           `json:"resourceGroupName"`
	VaultName         string                           `json:"vaultName"`
	TenantID          string                           `json:"tenantId"`
	ObjectID          string                           `json:"objectId"`
	Permissions       *keyVaultAccessPolicyPermissions `json:"permissions"`
}

type keyVaultAccessPolicyPermissions struct {
	Keys         []string `json:"keys"`
	Secrets      []string `json:"secrets"`
	Certificates []string `json:"certificates"`
	Storage      []string `json:"storage"`
}

func accessPolicyNativeID(subscriptionID, rgName, vaultName, objectID string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.KeyVault/vaults/%s/accessPolicies/%s",
		subscriptionID, rgName, vaultName, objectID)
}

func accessPolicyIDParts(resourceID string) (rgName, vaultName, objectID string, err error) {
	rgName, names, err := armIDParts(resourceID, "vaults", "accesspolicies")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["vaults"], names["accesspolicies"], nil
}

// toAccessPolicyEntry validates and builds the single ARM entry this resource owns.
func (p keyVaultAccessPolicyProps) toAccessPolicyEntry() (*armkeyvault.AccessPolicyEntry, error) {
	if p.TenantID == "" {
		return nil, fmt.Errorf("tenantId is required")
	}
	if p.ObjectID == "" {
		return nil, fmt.Errorf("objectId is required")
	}
	if p.Permissions == nil {
		return nil, fmt.Errorf("permissions is required")
	}
	entry := &armkeyvault.AccessPolicyEntry{
		TenantID: stringPtr(p.TenantID),
		ObjectID: stringPtr(p.ObjectID),
		Permissions: &armkeyvault.Permissions{
			Keys:         keyVaultPermPtrs[armkeyvault.KeyPermissions](p.Permissions.Keys),
			Secrets:      keyVaultPermPtrs[armkeyvault.SecretPermissions](p.Permissions.Secrets),
			Certificates: keyVaultPermPtrs[armkeyvault.CertificatePermissions](p.Permissions.Certificates),
			Storage:      keyVaultPermPtrs[armkeyvault.StoragePermissions](p.Permissions.Storage),
		},
	}
	return entry, nil
}

// permissionStrings converts one ARM permission category, returning nil for an
// empty one so a category the caller never declared is omitted from the read
// rather than surfacing as an empty list that reads as drift.
func permissionStrings[T ~string](values []*T) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != nil {
			out = append(out, string(*v))
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func serializeAccessPolicyProperties(entry armkeyvault.AccessPolicyEntry, rgName, vaultName, nativeID string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName": rgName,
		"vaultName":         vaultName,
		"id":                nativeID,
	}
	if entry.TenantID != nil {
		props["tenantId"] = *entry.TenantID
	}
	if entry.ObjectID != nil {
		props["objectId"] = *entry.ObjectID
	}

	permissions := map[string]any{}
	if entry.Permissions != nil {
		if v := permissionStrings(entry.Permissions.Keys); v != nil {
			permissions["keys"] = v
		}
		if v := permissionStrings(entry.Permissions.Secrets); v != nil {
			permissions["secrets"] = v
		}
		if v := permissionStrings(entry.Permissions.Certificates); v != nil {
			permissions["certificates"] = v
		}
		if v := permissionStrings(entry.Permissions.Storage); v != nil {
			permissions["storage"] = v
		}
	}
	props["permissions"] = permissions

	return json.Marshal(props)
}

// applyAccessPolicy sends one add or remove for this resource's single entry.
func (a *KeyVaultAccessPolicy) applyAccessPolicy(ctx context.Context, kind armkeyvault.AccessPolicyUpdateKind, rgName, vaultName string, entry *armkeyvault.AccessPolicyEntry) error {
	params := armkeyvault.VaultAccessPolicyParameters{
		Properties: &armkeyvault.VaultAccessPolicyProperties{
			AccessPolicies: []*armkeyvault.AccessPolicyEntry{entry},
		},
	}
	_, err := a.api.UpdateAccessPolicy(ctx, rgName, vaultName, kind, params, nil)
	return err
}

// findAccessPolicy returns the vault's entry for objectID, or false when the
// vault has no policy for that identity.
func findAccessPolicy(vault armkeyvault.Vault, objectID string) (armkeyvault.AccessPolicyEntry, bool) {
	if vault.Properties == nil {
		return armkeyvault.AccessPolicyEntry{}, false
	}
	for _, ap := range vault.Properties.AccessPolicies {
		if ap == nil || ap.ObjectID == nil {
			continue
		}
		if strings.EqualFold(*ap.ObjectID, objectID) {
			return *ap, true
		}
	}
	return armkeyvault.AccessPolicyEntry{}, false
}

func (a *KeyVaultAccessPolicy) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props keyVaultAccessPolicyProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.VaultName == "" {
		return nil, fmt.Errorf("vaultName is required")
	}
	entry, err := props.toAccessPolicyEntry()
	if err != nil {
		return nil, err
	}

	if err := a.applyAccessPolicy(ctx, armkeyvault.AccessPolicyUpdateKindAdd, props.ResourceGroupName, props.VaultName, entry); err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	nativeID := accessPolicyNativeID(a.config.SubscriptionId, props.ResourceGroupName, props.VaultName, props.ObjectID)
	propsJSON, err := serializeAccessPolicyProperties(*entry, props.ResourceGroupName, props.VaultName, nativeID)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AccessPolicy properties: %w", err)
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

func (a *KeyVaultAccessPolicy) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, vaultName, objectID, err := accessPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, vaultName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	entry, ok := findAccessPolicy(result.Vault, objectID)
	if !ok {
		// The vault is there but carries no policy for this identity, so the
		// resource itself is gone. Reporting NotFound is what lets a sync
		// tombstone it instead of reporting an empty policy as drift.
		return &resource.ReadResult{ErrorCode: resource.OperationErrorCodeNotFound}, nil
	}

	propsJSON, err := serializeAccessPolicyProperties(entry, rgName, vaultName, request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AccessPolicy properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeKeyVaultAccessPolicy,
		Properties:   string(propsJSON),
	}, nil
}

// Update replaces this one entry with remove-then-add.
//
// A bare `add` is not enough: for an object id that is already present ARM folds
// the incoming permission arrays into the stored ones, so a permission dropped
// from desired state would survive the update and read back as drift. `replace`
// is not used either - its blast radius on the vault's other policies is not
// worth relying on for a resource that owns exactly one entry.
//
// The remove sends the entry EXACTLY as the vault currently holds it, read back
// first, rather than the desired permissions or an empty set. That way the step
// clears the old entry whether ARM treats a remove as "drop the entry with this
// object id" or as "subtract these permissions". Its error is ignored on purpose:
// its only job is to clear a possibly-absent entry, and any real problem (missing
// rights, vault gone) resurfaces on the add, which is the call that establishes
// desired state.
func (a *KeyVaultAccessPolicy) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, vaultName, objectID, err := accessPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props keyVaultAccessPolicyProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ObjectID == "" {
		props.ObjectID = objectID
	}
	entry, err := props.toAccessPolicyEntry()
	if err != nil {
		return nil, err
	}

	if vault, getErr := a.api.Get(ctx, rgName, vaultName, nil); getErr == nil {
		if stored, ok := findAccessPolicy(vault.Vault, objectID); ok {
			//nolint:errcheck // see the doc comment: the remove is a best-effort clear.
			_ = a.applyAccessPolicy(ctx, armkeyvault.AccessPolicyUpdateKindRemove, rgName, vaultName, &stored)
		}
	}

	if err := a.applyAccessPolicy(ctx, armkeyvault.AccessPolicyUpdateKindAdd, rgName, vaultName, entry); err != nil {
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

	propsJSON, err := serializeAccessPolicyProperties(*entry, rgName, vaultName, request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AccessPolicy properties: %w", err)
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

// Delete removes just this entry. A vault that is already gone means the policy
// is gone too, so NotFound is success.
func (a *KeyVaultAccessPolicy) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, vaultName, objectID, err := accessPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Read the entry back before removing it and send it verbatim: the remove then
	// clears it whether ARM matches on the object id alone or subtracts the listed
	// permissions. A missing vault, or a vault with no entry for this identity,
	// already satisfies the delete.
	vault, err := a.api.Get(ctx, rgName, vaultName, nil)
	if err != nil {
		if isDeleteSuccessError(err) {
			return accessPolicyDeleteSuccess(request.NativeID), nil
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
	entry, ok := findAccessPolicy(vault.Vault, objectID)
	if !ok {
		return accessPolicyDeleteSuccess(request.NativeID), nil
	}

	if err := a.applyAccessPolicy(ctx, armkeyvault.AccessPolicyUpdateKindRemove, rgName, vaultName, &entry); err != nil {
		if isDeleteSuccessError(err) {
			return accessPolicyDeleteSuccess(request.NativeID), nil
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

	return accessPolicyDeleteSuccess(request.NativeID), nil
}

func accessPolicyDeleteSuccess(nativeID string) *resource.DeleteResult {
	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        nativeID,
		},
	}
}

// Access policy writes are synchronous, so Status is a no-op.
func (a *KeyVaultAccessPolicy) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List has no ARM list operation to call: the policies live inside the vault, so
// discovery reads the parent and reports one native id per entry.
func (a *KeyVaultAccessPolicy) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	vaultName := request.AdditionalProperties["vaultName"]
	if rgName == "" || vaultName == "" {
		return &resource.ListResult{}, nil
	}

	result, err := a.api.Get(ctx, rgName, vaultName, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.ListResult{}, nil
		}
		return nil, fmt.Errorf("failed to list key vault access policies: %w", err)
	}
	if result.Properties == nil {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	for _, ap := range result.Properties.AccessPolicies {
		if ap == nil || ap.ObjectID == nil {
			continue
		}
		nativeIDs = append(nativeIDs, accessPolicyNativeID(a.config.SubscriptionId, rgName, vaultName, *ap.ObjectID))
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
