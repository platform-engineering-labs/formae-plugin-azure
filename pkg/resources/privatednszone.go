// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypePrivateDnsZone = "Azure::Network::PrivateDnsZone"

type privateDnsZonesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, privateZoneName string, parameters armprivatedns.PrivateZone, options *armprivatedns.PrivateZonesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armprivatedns.PrivateZonesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, privateZoneName string, options *armprivatedns.PrivateZonesClientGetOptions) (armprivatedns.PrivateZonesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, privateZoneName string, options *armprivatedns.PrivateZonesClientBeginDeleteOptions) (*runtime.Poller[armprivatedns.PrivateZonesClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armprivatedns.PrivateZonesClientListByResourceGroupOptions) *runtime.Pager[armprivatedns.PrivateZonesClientListByResourceGroupResponse]
	NewListPager(options *armprivatedns.PrivateZonesClientListOptions) *runtime.Pager[armprivatedns.PrivateZonesClientListResponse]
}

func init() {
	registry.Register(ResourceTypePrivateDnsZone, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PrivateDnsZone{
			api:      c.PrivateDnsZonesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// PrivateDnsZone is the provisioner for Azure Private DNS Zones.
type PrivateDnsZone struct {
	api      privateDnsZonesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func serializePrivateDnsZoneProperties(result armprivatedns.PrivateZone, rgName, zoneName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = zoneName
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func (z *PrivateDnsZone) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}
	zoneName, ok := props["name"].(string)
	if !ok || zoneName == "" {
		zoneName = request.Label
	}

	params := armprivatedns.PrivateZone{
		Location: stringPtr(location),
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := z.api.BeginCreateOrUpdate(ctx, rgName, zoneName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/privateDnsZones/%s",
		z.config.SubscriptionId, rgName, zoneName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := serializePrivateDnsZoneProperties(result.PrivateZone, rgName, zoneName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PrivateDnsZone properties: %w", err)
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
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

func (z *PrivateDnsZone) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	parts := splitResourceID(request.NativeID)
	rgName := parts["resourcegroups"]
	zoneName := parts["privatednszones"]
	if rgName == "" || zoneName == "" {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or zone name from %s", request.NativeID)
	}
	result, err := z.api.Get(ctx, rgName, zoneName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: mapAzureErrorToOperationErrorCode(err)}, nil
	}
	propsJSON, err := serializePrivateDnsZoneProperties(result.PrivateZone, rgName, zoneName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PrivateDnsZone properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypePrivateDnsZone,
		Properties:   string(propsJSON),
	}, nil
}

func (z *PrivateDnsZone) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	parts := splitResourceID(request.NativeID)
	rgName := parts["resourcegroups"]
	zoneName := parts["privatednszones"]
	if rgName == "" || zoneName == "" {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or zone name from %s", request.NativeID)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params := armprivatedns.PrivateZone{
		Location: stringPtr(location),
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := z.api.BeginCreateOrUpdate(ctx, rgName, zoneName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
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
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := serializePrivateDnsZoneProperties(result.PrivateZone, rgName, zoneName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize PrivateDnsZone properties: %w", err)
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
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

// isZoneDeleteEventualConsistencyError returns true when Azure rejects a
// PrivateDnsZone delete because the platform's view of the zone still has
// virtualNetworkLinks attached, even though the link's own delete LRO has
// completed and a Get on the link returns 404. The zone-side propagation lag
// is tens of seconds. Detect on either the typed status code (412 / 409 /
// 400) or substrings of the error message.
func isZoneDeleteEventualConsistencyError(err error) bool {
	if err == nil {
		return false
	}
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case 400, 409, 412:
			// Azure variously uses 400 BadRequest, 409 Conflict, or 412
			// PreconditionFailed for "still has dependents" — accept any.
			msg := respErr.Error()
			if strings.Contains(msg, "VirtualNetworkLink") ||
				strings.Contains(msg, "virtualNetworkLink") ||
				strings.Contains(msg, "still has") ||
				strings.Contains(msg, "active") {
				return true
			}
		}
	}
	// Fall back to substring match on the raw error string.
	s := err.Error()
	return strings.Contains(s, "VirtualNetworkLink") ||
		strings.Contains(s, "ZoneStillHasVirtualNetworkLinks") ||
		strings.Contains(s, "PreconditionFailed")
}

func (z *PrivateDnsZone) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	parts := splitResourceID(request.NativeID)
	rgName := parts["resourcegroups"]
	zoneName := parts["privatednszones"]
	if rgName == "" || zoneName == "" {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or zone name from %s", request.NativeID)
	}

	// Retry BeginDelete on eventual-consistency conflicts: after a recent
	// virtualNetworkLink delete, Azure's zone-side view of "no more links"
	// can lag by 30-60 seconds, even though the link's LRO has reported Done
	// and a direct Get on the link returns 404.
	const (
		maxRetries = 12 // up to ~60s total
		retryDelay = 5 * time.Second
	)
	var (
		poller *runtime.Poller[armprivatedns.PrivateZonesClientDeleteResponse]
		err    error
	)
	for attempt := 0; attempt <= maxRetries; attempt++ {
		poller, err = z.api.BeginDelete(ctx, rgName, zoneName, nil)
		if err == nil {
			break
		}
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
		if !isZoneDeleteEventualConsistencyError(err) || attempt == maxRetries {
			fmt.Fprintf(os.Stderr, "PrivateDnsZone Delete: BeginDelete error after %d attempt(s): %v\n", attempt+1, err)
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
					StatusMessage:   err.Error(),
				},
			}, fmt.Errorf("failed to start PrivateDnsZone deletion: %w", err)
		}
		select {
		case <-ctx.Done():
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
					StatusMessage:   ctx.Err().Error(),
				},
			}, ctx.Err()
		case <-time.After(retryDelay):
		}
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

func (z *PrivateDnsZone) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return z.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return z.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (z *PrivateDnsZone) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}
	poller, err := resumePoller[armprivatedns.PrivateZonesClientCreateOrUpdateResponse](z.pipeline, reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller: %w", err)
	}
	if poller.Done() {
		return z.handleCreateOrUpdateComplete(ctx, request, poller, operation)
	}
	if _, err = poller.Poll(ctx); err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}
	if poller.Done() {
		return z.handleCreateOrUpdateComplete(ctx, request, poller, operation)
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (z *PrivateDnsZone) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, poller *runtime.Poller[armprivatedns.PrivateZonesClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}
	parts := splitResourceID(*result.ID)
	rgName := parts["resourcegroups"]
	propsJSON, err := serializePrivateDnsZoneProperties(result.PrivateZone, rgName, *result.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PrivateDnsZone properties: %w", err)
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          operation,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (z *PrivateDnsZone) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := resumePoller[armprivatedns.PrivateZonesClientDeleteResponse](z.pipeline, reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller: %w", err)
	}
	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil && !isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}
	if _, err = poller.Poll(ctx); err != nil {
		if isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}
	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil && !isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (z *PrivateDnsZone) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]
	var nativeIDs []string
	if resourceGroupName != "" {
		pager := z.api.NewListByResourceGroupPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list private dns zones: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	} else {
		pager := z.api.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list private dns zones: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
