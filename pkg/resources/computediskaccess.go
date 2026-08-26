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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeComputeDiskAccess = "AZURE::Compute::DiskAccess"

// computeDiskAccessesAPI is the armcompute surface used here. All three mutating
// calls are LROs, and the update body (DiskAccessUpdate) carries tags and nothing
// else — this resource has no other settable configuration.
type computeDiskAccessesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, diskAccessName string, diskAccess armcompute.DiskAccess, options *armcompute.DiskAccessesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcompute.DiskAccessesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, diskAccessName string, options *armcompute.DiskAccessesClientGetOptions) (armcompute.DiskAccessesClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, diskAccessName string, diskAccess armcompute.DiskAccessUpdate, options *armcompute.DiskAccessesClientBeginUpdateOptions) (*runtime.Poller[armcompute.DiskAccessesClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, diskAccessName string, options *armcompute.DiskAccessesClientBeginDeleteOptions) (*runtime.Poller[armcompute.DiskAccessesClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armcompute.DiskAccessesClientListByResourceGroupOptions) *runtime.Pager[armcompute.DiskAccessesClientListByResourceGroupResponse]
	NewListPager(options *armcompute.DiskAccessesClientListOptions) *runtime.Pager[armcompute.DiskAccessesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeComputeDiskAccess, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ComputeDiskAccess{
			api:      c.DiskAccessesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ComputeDiskAccess is the provisioner for disk access resources
// (Microsoft.Compute/diskAccesses) — the private-link target a disk or snapshot
// needs before it can use networkAccessPolicy AllowPrivate.
type ComputeDiskAccess struct {
	api      computeDiskAccessesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// computeDiskAccessProps mirrors schema/pkl/compute/diskaccess.pkl.
type computeDiskAccessProps struct {
	Name              string `json:"name"`
	Location          string `json:"location"`
	ResourceGroupName string `json:"resourceGroupName"`
}

func computeDiskAccessIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "diskaccesses")
	if err != nil {
		return "", "", err
	}
	return rgName, names["diskaccesses"], nil
}

func (d *ComputeDiskAccess) buildPropertiesFromResult(access *armcompute.DiskAccess, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if access.ID != nil {
		props["id"] = *access.ID
	}
	if access.Name != nil {
		props["name"] = *access.Name
	}
	if access.Location != nil {
		props["location"] = normalizeAzureLocation(*access.Location)
	}

	// The properties block holds nothing this resource owns: privateEndpointConnections
	// are separate resources with their own lifecycle, and provisioningState and
	// timeCreated are service state that would read back as drift.

	if tags := azureTagsToFormaeTags(access.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (d *ComputeDiskAccess) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props computeDiskAccessProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params := armcompute.DiskAccess{Location: to.Ptr(props.Location)}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := d.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/diskAccesses/%s",
		d.config.SubscriptionId, props.ResourceGroupName, name)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}
		nativeID, propsJSON, err := d.completeFromDiskAccess(&result.DiskAccess)
		if err != nil {
			return nil, err
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (d *ComputeDiskAccess) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := computeDiskAccessIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := d.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DiskAccess, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeComputeDiskAccess,
		Properties:   string(propsJSON),
	}, nil
}

// Update can only ever change tags: DiskAccessUpdate has no other field, and the
// schema marks location createOnly to match.
func (d *ComputeDiskAccess) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := computeDiskAccessIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	params := armcompute.DiskAccessUpdate{Tags: formaeTagsToAzureTags(request.DesiredProperties)}

	poller, err := d.api.BeginUpdate(ctx, rgName, name, params, nil)
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

	if poller.Done() {
		result, err := poller.Result(ctx)
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
		propsJSON, err := json.Marshal(d.buildPropertiesFromResult(&result.DiskAccess, rgName))
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (d *ComputeDiskAccess) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := computeDiskAccessIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := d.api.BeginDelete(ctx, rgName, name, nil)
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
			},
		}, nil
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (d *ComputeDiskAccess) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armcompute.DiskAccessesClientCreateOrUpdateResponse], error) {
				return resumePoller[armcompute.DiskAccessesClientCreateOrUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armcompute.DiskAccessesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromDiskAccess(&result.DiskAccess)
			})
	case lroOpUpdate:
		// Resumed as an Update response, matching the BeginUpdate poller that handed
		// out this token.
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armcompute.DiskAccessesClientUpdateResponse], error) {
				return resumePoller[armcompute.DiskAccessesClientUpdateResponse](d.pipeline, token)
			},
			func(_ context.Context, result armcompute.DiskAccessesClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return d.completeFromDiskAccess(&result.DiskAccess)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcompute.DiskAccessesClientDeleteResponse], error) {
				return resumePoller[armcompute.DiskAccessesClientDeleteResponse](d.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (d *ComputeDiskAccess) completeFromDiskAccess(access *armcompute.DiskAccess) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if access.ID != nil {
		nativeID = *access.ID
		if rg, _, err := computeDiskAccessIDParts(*access.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(d.buildPropertiesFromResult(access, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (d *ComputeDiskAccess) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := d.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list disk accesses: %w", err)
			}
			for _, access := range page.Value {
				if access.ID != nil {
					nativeIDs = append(nativeIDs, *access.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := d.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list disk accesses: %w", err)
		}
		for _, access := range page.Value {
			if access.ID != nil {
				nativeIDs = append(nativeIDs, *access.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
