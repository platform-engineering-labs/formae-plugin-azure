// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeStorageBlobContainerLegalHold = "AZURE::Storage::BlobContainerLegalHold"

// legalHoldIDSuffix completes the synthesised native ID. ARM has no resource for
// a legal hold — only the two verbs — so there is no ARM ID to use. The container
// ID plus this suffix is stable, unique, and parses as an ARM ID, which is what
// the identifier contract needs.
const legalHoldIDSuffix = "/legalHolds/default"

// blobContainerLegalHoldAPI is the legal-hold verb subset of
// *armstorage.BlobContainersClient, plus the container Get that stands in for the
// missing legal-hold Get. Every verb is synchronous.
type blobContainerLegalHoldAPI interface {
	SetLegalHold(ctx context.Context, resourceGroupName, accountName, containerName string, legalHold armstorage.LegalHold, options *armstorage.BlobContainersClientSetLegalHoldOptions) (armstorage.BlobContainersClientSetLegalHoldResponse, error)
	ClearLegalHold(ctx context.Context, resourceGroupName, accountName, containerName string, legalHold armstorage.LegalHold, options *armstorage.BlobContainersClientClearLegalHoldOptions) (armstorage.BlobContainersClientClearLegalHoldResponse, error)
	Get(ctx context.Context, resourceGroupName, accountName, containerName string, options *armstorage.BlobContainersClientGetOptions) (armstorage.BlobContainersClientGetResponse, error)
}

func init() {
	registry.Register(ResourceTypeStorageBlobContainerLegalHold, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &StorageBlobContainerLegalHold{api: c.BlobContainersClient, config: cfg}
	})
}

// StorageBlobContainerLegalHold provisions the legal hold on a blob container.
//
// ARM models this as two verbs and no resource: `setLegalHold` adds tags,
// `clearLegalHold` removes them, and the current tag set is only readable off the
// parent container. Create sets the declared tags, update reconciles the tag set
// with one call of each verb, and delete clears whatever is there.
type StorageBlobContainerLegalHold struct {
	api    blobContainerLegalHoldAPI
	config *config.Config
}

// storageBlobContainerLegalHoldProps mirrors
// schema/pkl/storage/storageblobcontainerlegalhold.pkl.
type storageBlobContainerLegalHoldProps struct {
	ResourceGroupName             string   `json:"resourceGroupName"`
	StorageAccountName            string   `json:"storageAccountName"`
	ContainerName                 string   `json:"containerName"`
	LegalHoldTags                 []string `json:"legalHoldTags"`
	AllowProtectedAppendWritesAll *bool    `json:"allowProtectedAppendWritesAll"`
}

// legalHoldNativeID synthesises the identifier from the container's ARM ID.
func legalHoldNativeID(subscriptionID, rgName, accountName, containerName string) string {
	return fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/blobServices/default/containers/%s%s",
		subscriptionID, rgName, accountName, containerName, legalHoldIDSuffix)
}

func storageBlobContainerLegalHoldIDParts(resourceID string) (rgName, accountName, containerName string, err error) {
	rgName, names, err := armIDParts(resourceID, "storageaccounts", "containers")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["storageaccounts"], names["containers"], nil
}

// normalizeLegalHoldTags lower-cases and sorts a tag set. ARM lower-cases every
// tag on the way in and returns them in its own order, so comparing raw slices
// would report drift on a set that actually matches.
func normalizeLegalHoldTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := make(map[string]bool, len(tags))
	for _, t := range tags {
		lowered := strings.ToLower(strings.TrimSpace(t))
		if lowered == "" || seen[lowered] {
			continue
		}
		seen[lowered] = true
		out = append(out, lowered)
	}
	sort.Strings(out)
	return out
}

// currentLegalHoldTags reads the tag set off the parent container: the legal hold
// has no Get of its own.
func (l *StorageBlobContainerLegalHold) currentLegalHoldTags(ctx context.Context, rgName, accountName, containerName string) ([]string, bool, error) {
	result, err := l.api.Get(ctx, rgName, accountName, containerName, nil)
	if err != nil {
		return nil, false, err
	}
	if result.ContainerProperties == nil || result.ContainerProperties.LegalHold == nil {
		return nil, false, nil
	}
	hold := result.ContainerProperties.LegalHold
	tags := make([]string, 0, len(hold.Tags))
	for _, t := range hold.Tags {
		if t != nil && t.Tag != nil {
			tags = append(tags, *t.Tag)
		}
	}
	appendAll := hold.ProtectedAppendWritesHistory != nil &&
		hold.ProtectedAppendWritesHistory.AllowProtectedAppendWritesAll != nil &&
		*hold.ProtectedAppendWritesHistory.AllowProtectedAppendWritesAll
	return normalizeLegalHoldTags(tags), appendAll, nil
}

func serializeStorageBlobContainerLegalHoldProperties(nativeID, rgName, accountName, containerName string, tags []string, appendAll bool) (json.RawMessage, error) {
	props := map[string]any{
		"id":                 nativeID,
		"resourceGroupName":  rgName,
		"storageAccountName": accountName,
		"containerName":      containerName,
		"legalHoldTags":      normalizeLegalHoldTags(tags),
		"hasLegalHold":       len(tags) > 0,
	}
	// No schema default: a false for a flag the caller never set would read as
	// drift.
	if appendAll {
		props["allowProtectedAppendWritesAll"] = true
	}
	return json.Marshal(props)
}

func (l *StorageBlobContainerLegalHold) parseProps(payload json.RawMessage, nativeID string) (storageBlobContainerLegalHoldProps, error) {
	var props storageBlobContainerLegalHoldProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if nativeID != "" {
		rgName, accountName, containerName, err := storageBlobContainerLegalHoldIDParts(nativeID)
		if err != nil {
			return props, err
		}
		props.ResourceGroupName, props.StorageAccountName, props.ContainerName = rgName, accountName, containerName
	}
	if props.ResourceGroupName == "" {
		return props, fmt.Errorf("resourceGroupName is required")
	}
	if props.StorageAccountName == "" {
		return props, fmt.Errorf("storageAccountName is required")
	}
	if props.ContainerName == "" {
		return props, fmt.Errorf("containerName is required")
	}
	props.LegalHoldTags = normalizeLegalHoldTags(props.LegalHoldTags)
	if len(props.LegalHoldTags) == 0 {
		return props, fmt.Errorf("at least one legal hold tag is required")
	}
	return props, nil
}

func legalHoldBody(tags []string, appendAll *bool) armstorage.LegalHold {
	body := armstorage.LegalHold{Tags: stringPointers(tags)}
	if appendAll != nil {
		body.AllowProtectedAppendWritesAll = to.Ptr(*appendAll)
	}
	return body
}

func (l *StorageBlobContainerLegalHold) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, err := l.parseProps(request.Properties, "")
	if err != nil {
		return nil, err
	}

	result, err := l.api.SetLegalHold(ctx, props.ResourceGroupName, props.StorageAccountName, props.ContainerName,
		legalHoldBody(props.LegalHoldTags, props.AllowProtectedAppendWritesAll), nil)
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

	nativeID := legalHoldNativeID(l.config.SubscriptionId, props.ResourceGroupName, props.StorageAccountName, props.ContainerName)
	propsJSON, err := serializeStorageBlobContainerLegalHoldProperties(nativeID,
		props.ResourceGroupName, props.StorageAccountName, props.ContainerName,
		stringsFromPointers(result.Tags),
		props.AllowProtectedAppendWritesAll != nil && *props.AllowProtectedAppendWritesAll)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize LegalHold properties: %w", err)
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

func (l *StorageBlobContainerLegalHold) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, containerName, err := storageBlobContainerLegalHoldIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	tags, appendAll, err := l.currentLegalHoldTags(ctx, rgName, accountName, containerName)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	// A container with no tags carries no legal hold: report it gone rather than as
	// a hold with an empty, schema-invalid tag list.
	if len(tags) == 0 {
		return &resource.ReadResult{ErrorCode: resource.OperationErrorCodeNotFound}, nil
	}

	propsJSON, err := serializeStorageBlobContainerLegalHoldProperties(request.NativeID, rgName, accountName, containerName, tags, appendAll)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize LegalHold properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeStorageBlobContainerLegalHold,
		Properties:   string(propsJSON),
	}, nil
}

// Update reconciles the tag set: one setLegalHold for the tags that should be
// there, then one clearLegalHold for the tags that should not. ARM has no
// replace verb.
func (l *StorageBlobContainerLegalHold) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	props, err := l.parseProps(request.DesiredProperties, request.NativeID)
	if err != nil {
		return nil, err
	}

	existing, _, err := l.currentLegalHoldTags(ctx, props.ResourceGroupName, props.StorageAccountName, props.ContainerName)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   fmt.Sprintf("failed to read the container's current legal hold tags: %v", err),
			},
		}, nil
	}

	// setLegalHold is additive and idempotent, so the whole desired set can go in
	// one call regardless of what is already there.
	if _, err := l.api.SetLegalHold(ctx, props.ResourceGroupName, props.StorageAccountName, props.ContainerName,
		legalHoldBody(props.LegalHoldTags, props.AllowProtectedAppendWritesAll), nil); err != nil {
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

	if stale := legalHoldTagsToClear(existing, props.LegalHoldTags); len(stale) > 0 {
		if _, err := l.api.ClearLegalHold(ctx, props.ResourceGroupName, props.StorageAccountName, props.ContainerName,
			legalHoldBody(stale, nil), nil); err != nil {
			return &resource.UpdateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       operationErrorCode(err),
					StatusMessage:   fmt.Sprintf("failed to clear the legal hold tags %v that are no longer declared: %v", stale, err),
				},
			}, nil
		}
	}

	propsJSON, err := serializeStorageBlobContainerLegalHoldProperties(request.NativeID,
		props.ResourceGroupName, props.StorageAccountName, props.ContainerName, props.LegalHoldTags,
		props.AllowProtectedAppendWritesAll != nil && *props.AllowProtectedAppendWritesAll)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize LegalHold properties after update: %w", err)
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

// legalHoldTagsToClear returns the tags present but no longer wanted.
func legalHoldTagsToClear(existing, desired []string) []string {
	wanted := make(map[string]bool, len(desired))
	for _, t := range desired {
		wanted[t] = true
	}
	var stale []string
	for _, t := range existing {
		if !wanted[t] {
			stale = append(stale, t)
		}
	}
	return stale
}

// Delete clears every tag the container carries. With no tags left ARM sets
// hasLegalHold false, which is what "no legal hold" means.
func (l *StorageBlobContainerLegalHold) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, containerName, err := storageBlobContainerLegalHoldIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	existing, _, err := l.currentLegalHoldTags(ctx, rgName, accountName, containerName)
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
				StatusMessage:   fmt.Sprintf("failed to read the container's legal hold tags before clearing them: %v", err),
			},
		}, nil
	}

	if len(existing) > 0 {
		if _, err := l.api.ClearLegalHold(ctx, rgName, accountName, containerName, legalHoldBody(existing, nil), nil); err != nil {
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
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Legal-hold writes are synchronous, so Status just re-reads the container.
func (l *StorageBlobContainerLegalHold) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, accountName, containerName, err := storageBlobContainerLegalHoldIDParts(request.NativeID)
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

	tags, appendAll, err := l.currentLegalHoldTags(ctx, rgName, accountName, containerName)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, fmt.Errorf("failed to get LegalHold status: %w", err)
	}

	propsJSON, err := serializeStorageBlobContainerLegalHoldProperties(request.NativeID, rgName, accountName, containerName, tags, appendAll)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize LegalHold properties: %w", err)
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           request.NativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

// List probes the parent container: a hold exists exactly when the container
// carries at least one tag.
func (l *StorageBlobContainerLegalHold) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["storageAccountName"]
	containerName := request.AdditionalProperties["containerName"]
	if rgName == "" || accountName == "" || containerName == "" {
		return &resource.ListResult{}, nil
	}

	tags, _, err := l.currentLegalHoldTags(ctx, rgName, accountName, containerName)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.ListResult{}, nil
		}
		return nil, fmt.Errorf("failed to list LegalHolds on container %s: %w", containerName, err)
	}
	if len(tags) == 0 {
		return &resource.ListResult{}, nil
	}
	return &resource.ListResult{
		NativeIDs: []string{legalHoldNativeID(l.config.SubscriptionId, rgName, accountName, containerName)},
	}, nil
}
