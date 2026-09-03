// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeManagedHsm = "AZURE::KeyVault::ManagedHsm"

// managedHsmsAPI is the subset of *armkeyvault.ManagedHsmsClient used here.
// Create, update and delete are LROs; provisioning a pool takes 20-30 minutes.
type managedHsmsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, name string, parameters armkeyvault.ManagedHsm, options *armkeyvault.ManagedHsmsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, name string, options *armkeyvault.ManagedHsmsClientGetOptions) (armkeyvault.ManagedHsmsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, name string, options *armkeyvault.ManagedHsmsClientBeginDeleteOptions) (*runtime.Poller[armkeyvault.ManagedHsmsClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armkeyvault.ManagedHsmsClientListByResourceGroupOptions) *runtime.Pager[armkeyvault.ManagedHsmsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armkeyvault.ManagedHsmsClientListBySubscriptionOptions) *runtime.Pager[armkeyvault.ManagedHsmsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeManagedHsm, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ManagedHsm{
			api:      c.ManagedHsmsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ManagedHsm provisions single-tenant HSM pools
// (`Microsoft.KeyVault/managedHSMs/<name>`).
//
// Two things about this resource differ from an ordinary Key Vault. Soft delete
// is permanently on and cannot be disabled, with a 7-day minimum retention, so a
// deleted pool holds its name until it is purged or the retention expires. And a
// pool bills from the moment it is created, at roughly $3.20/hour, which is why
// the `managed-hsm` fixture is on .github/conformance-pr-skip.txt and this
// handler's coverage is the mocked test rather than a live lifecycle.
type ManagedHsm struct {
	api      managedHsmsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// managedHsmProps mirrors schema/pkl/keyvault/managedhsm.pkl.
type managedHsmProps struct {
	Name                      string         `json:"name"`
	ResourceGroupName         string         `json:"resourceGroupName"`
	Location                  string         `json:"location"`
	TenantID                  string         `json:"tenantId"`
	SKU                       *managedHsmSKU `json:"sku"`
	InitialAdminObjectIDs     []string       `json:"initialAdminObjectIds"`
	EnableSoftDelete          *bool          `json:"enableSoftDelete"`
	SoftDeleteRetentionInDays *int32         `json:"softDeleteRetentionInDays"`
	EnablePurgeProtection     *bool          `json:"enablePurgeProtection"`
	PublicNetworkAccess       string         `json:"publicNetworkAccess"`
}

type managedHsmSKU struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

func managedHsmIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "managedhsms")
	if err != nil {
		return "", "", err
	}
	return rgName, names["managedhsms"], nil
}

// toManagedHsmParams validates the fields ARM requires and builds the SDK body;
// tags are applied by the caller.
func (p managedHsmProps) toManagedHsmParams() (armkeyvault.ManagedHsm, error) {
	var params armkeyvault.ManagedHsm

	if p.Location == "" {
		return params, fmt.Errorf("location is required")
	}
	if p.TenantID == "" {
		return params, fmt.Errorf("tenantId is required")
	}
	if p.SKU == nil || p.SKU.Name == "" {
		return params, fmt.Errorf("sku.name is required")
	}
	// ARM rejects a pool with no administrator: without one nobody could ever
	// activate the security domain, so the pool would be unusable.
	if len(p.InitialAdminObjectIDs) == 0 {
		return params, fmt.Errorf("initialAdminObjectIds requires at least one object id")
	}

	family := armkeyvault.ManagedHsmSKUFamilyB
	if p.SKU.Family != "" {
		family = armkeyvault.ManagedHsmSKUFamily(p.SKU.Family)
	}

	params = armkeyvault.ManagedHsm{
		Location: stringPtr(p.Location),
		SKU: &armkeyvault.ManagedHsmSKU{
			Family: to.Ptr(family),
			Name:   to.Ptr(armkeyvault.ManagedHsmSKUName(p.SKU.Name)),
		},
		Properties: &armkeyvault.ManagedHsmProperties{
			TenantID:                  stringPtr(p.TenantID),
			InitialAdminObjectIDs:     stringPointers(p.InitialAdminObjectIDs),
			EnableSoftDelete:          p.EnableSoftDelete,
			SoftDeleteRetentionInDays: p.SoftDeleteRetentionInDays,
			EnablePurgeProtection:     p.EnablePurgeProtection,
		},
	}
	if p.PublicNetworkAccess != "" {
		params.Properties.PublicNetworkAccess = to.Ptr(armkeyvault.PublicNetworkAccess(p.PublicNetworkAccess))
	}
	return params, nil
}

func serializeManagedHsmProperties(result armkeyvault.ManagedHsm, rgName, name string) (json.RawMessage, error) {
	props := map[string]any{"resourceGroupName": rgName}

	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = name
	}
	if result.Location != nil {
		props["location"] = normalizeAzureLocation(*result.Location)
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.SKU != nil {
		sku := map[string]any{}
		if result.SKU.Family != nil {
			sku["family"] = string(*result.SKU.Family)
		}
		if result.SKU.Name != nil {
			sku["name"] = string(*result.SKU.Name)
		}
		props["sku"] = sku
	}

	if p := result.Properties; p != nil {
		if p.TenantID != nil {
			props["tenantId"] = *p.TenantID
		}
		if admins := stringsFromPointers(p.InitialAdminObjectIDs); admins != nil {
			props["initialAdminObjectIds"] = admins
		}
		if p.EnableSoftDelete != nil {
			props["enableSoftDelete"] = *p.EnableSoftDelete
		}
		if p.SoftDeleteRetentionInDays != nil {
			props["softDeleteRetentionInDays"] = *p.SoftDeleteRetentionInDays
		}
		if p.EnablePurgeProtection != nil {
			props["enablePurgeProtection"] = *p.EnablePurgeProtection
		}
		if p.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = canonicalizeEnum(string(*p.PublicNetworkAccess), "Enabled", "Disabled")
		}
		if p.HsmURI != nil {
			props["hsmUri"] = *p.HsmURI
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

// upsertParams parses the payload once for both Create and Update.
func managedHsmUpsertParams(payload json.RawMessage) (armkeyvault.ManagedHsm, managedHsmProps, error) {
	var props managedHsmProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armkeyvault.ManagedHsm{}, props, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	params, err := props.toManagedHsmParams()
	if err != nil {
		return armkeyvault.ManagedHsm{}, props, err
	}
	if tags := formaeTagsToAzureTags(payload); tags != nil {
		params.Tags = tags
	}
	return params, props, nil
}

func (m *ManagedHsm) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	params, props, err := managedHsmUpsertParams(request.Properties)
	if err != nil {
		return nil, err
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	poller, err := m.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.KeyVault/managedHSMs/%s",
		m.config.SubscriptionId, props.ResourceGroupName, name)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       operationErrorCode(err),
					StatusMessage:   err.Error(),
				},
			}, nil
		}
		propsJSON, err := serializeManagedHsmProperties(result.ManagedHsm, props.ResourceGroupName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ManagedHsm properties: %w", err)
		}
		nativeID := expectedID
		if result.ID != nil {
			nativeID = *result.ID
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpCreate, token, expectedID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        expectedID,
		},
	}, nil
}

func (m *ManagedHsm) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := managedHsmIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeManagedHsmProperties(result.ManagedHsm, rgName, name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ManagedHsm properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeManagedHsm,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-PUTs the pool. Only tags and the mutable properties change; sku,
// location, tenantId and the initial administrators are createOnly in the schema.
func (m *ManagedHsm) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := managedHsmIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params, _, err := managedHsmUpsertParams(request.DesiredProperties)
	if err != nil {
		return nil, err
	}

	poller, err := m.api.BeginCreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
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

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
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
		propsJSON, err := serializeManagedHsmProperties(result.ManagedHsm, rgName, name)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ManagedHsm properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpUpdate, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Delete soft-deletes the pool. It deliberately does NOT purge afterwards: a
// purge destroys the security domain and every key in it irrecoverably, and
// unlike a Key Vault key that is a decision no reconcile should make on its own.
// The name therefore stays reserved for the retention period.
func (m *ManagedHsm) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := managedHsmIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := m.api.BeginDelete(ctx, rgName, name, nil)
	if err != nil {
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
		}, fmt.Errorf("failed to delete ManagedHsm: %w", err)
	}

	if poller.Done() {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpDelete, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (m *ManagedHsm) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
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

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return m.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return m.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   fmt.Sprintf("unknown LRO operation type: %s", reqID.OperationType),
			},
		}, fmt.Errorf("unknown LRO operation type: %s", reqID.OperationType)
	}
}

func (m *ManagedHsm) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse], error) {
			return resumePoller[armkeyvault.ManagedHsmsClientCreateOrUpdateResponse](m.pipeline, token)
		},
		func(_ context.Context, result armkeyvault.ManagedHsmsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			nativeID := reqID.NativeID
			if result.ID != nil {
				nativeID = *result.ID
			}
			rgName, name, err := managedHsmIDParts(nativeID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeManagedHsmProperties(result.ManagedHsm, rgName, name)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize ManagedHsm properties: %w", err)
			}
			return nativeID, propsJSON, nil
		})
}

func (m *ManagedHsm) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armkeyvault.ManagedHsmsClientDeleteResponse], error) {
			return resumePoller[armkeyvault.ManagedHsmsClientDeleteResponse](m.pipeline, token)
		}, nil)
}

func (m *ManagedHsm) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := m.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list managed HSMs in resource group %s: %w", rgName, err)
			}
			for _, hsm := range page.Value {
				if hsm != nil && hsm.ID != nil {
					nativeIDs = append(nativeIDs, *hsm.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := m.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list managed HSMs: %w", err)
		}
		for _, hsm := range page.Value {
			if hsm != nil && hsm.ID != nil {
				nativeIDs = append(nativeIDs, *hsm.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
