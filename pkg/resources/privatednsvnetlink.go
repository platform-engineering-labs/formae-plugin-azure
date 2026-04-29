// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypePrivateDnsZoneVNetLink = "Azure::Network::PrivateDnsZoneVirtualNetworkLink"

type privateDnsVNetLinksAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, privateZoneName string, virtualNetworkLinkName string, parameters armprivatedns.VirtualNetworkLink, options *armprivatedns.VirtualNetworkLinksClientBeginCreateOrUpdateOptions) (*runtime.Poller[armprivatedns.VirtualNetworkLinksClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, privateZoneName string, virtualNetworkLinkName string, options *armprivatedns.VirtualNetworkLinksClientGetOptions) (armprivatedns.VirtualNetworkLinksClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, privateZoneName string, virtualNetworkLinkName string, options *armprivatedns.VirtualNetworkLinksClientBeginDeleteOptions) (*runtime.Poller[armprivatedns.VirtualNetworkLinksClientDeleteResponse], error)
	NewListPager(resourceGroupName string, privateZoneName string, options *armprivatedns.VirtualNetworkLinksClientListOptions) *runtime.Pager[armprivatedns.VirtualNetworkLinksClientListResponse]
}

func init() {
	registry.Register(ResourceTypePrivateDnsZoneVNetLink, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PrivateDnsZoneVNetLink{
			api:      c.PrivateDnsVNetLinksClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// PrivateDnsZoneVNetLink is the provisioner for the link between a private DNS zone and a VNet.
type PrivateDnsZoneVNetLink struct {
	api      privateDnsVNetLinksAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func serializePrivateDnsVNetLinkProperties(result armprivatedns.VirtualNetworkLink, rgName, zoneName, linkName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["privateZoneName"] = zoneName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = linkName
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Properties != nil {
		if result.Properties.RegistrationEnabled != nil {
			props["registrationEnabled"] = *result.Properties.RegistrationEnabled
		}
		if result.Properties.VirtualNetwork != nil && result.Properties.VirtualNetwork.ID != nil {
			props["virtualNetworkId"] = *result.Properties.VirtualNetwork.ID
		}
	}
	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func (l *PrivateDnsZoneVNetLink) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	zoneName, ok := props["privateZoneName"].(string)
	if !ok || zoneName == "" {
		return nil, fmt.Errorf("privateZoneName is required")
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}
	linkName, ok := props["name"].(string)
	if !ok || linkName == "" {
		linkName = request.Label
	}
	vnetID, ok := props["virtualNetworkId"].(string)
	if !ok || vnetID == "" {
		return nil, fmt.Errorf("virtualNetworkId is required")
	}

	params := armprivatedns.VirtualNetworkLink{
		Location: stringPtr(location),
		Properties: &armprivatedns.VirtualNetworkLinkProperties{
			VirtualNetwork: &armprivatedns.SubResource{ID: stringPtr(vnetID)},
		},
	}
	if reg, ok := props["registrationEnabled"].(bool); ok {
		params.Properties.RegistrationEnabled = &reg
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := l.api.BeginCreateOrUpdate(ctx, rgName, zoneName, linkName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/privateDnsZones/%s/virtualNetworkLinks/%s",
		l.config.SubscriptionId, rgName, zoneName, linkName)

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
		propsJSON, err := serializePrivateDnsVNetLinkProperties(result.VirtualNetworkLink, rgName, zoneName, linkName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VirtualNetworkLink properties: %w", err)
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

// vnetLinkPathParts splits a VirtualNetworkLink ARM ID into rg, zone, link
// segments. ARM key casing is `privateDnsZones` and `virtualNetworkLinks`,
// which `splitResourceID` lowercases.
func vnetLinkPathParts(nativeID string) (rg, zone, link string, err error) {
	parts := splitResourceID(nativeID)
	rg = parts["resourcegroups"]
	zone = parts["privatednszones"]
	link = parts["virtualnetworklinks"]
	if rg == "" || zone == "" || link == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: cannot extract resourceGroup/zone/link from %s", nativeID)
	}
	return rg, zone, link, nil
}

func (l *PrivateDnsZoneVNetLink) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, zoneName, linkName, err := vnetLinkPathParts(request.NativeID)
	if err != nil {
		return nil, err
	}
	result, err := l.api.Get(ctx, rgName, zoneName, linkName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: mapAzureErrorToOperationErrorCode(err)}, nil
	}
	propsJSON, err := serializePrivateDnsVNetLinkProperties(result.VirtualNetworkLink, rgName, zoneName, linkName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VirtualNetworkLink properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypePrivateDnsZoneVNetLink,
		Properties:   string(propsJSON),
	}, nil
}

func (l *PrivateDnsZoneVNetLink) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, zoneName, linkName, err := vnetLinkPathParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}
	vnetID, ok := props["virtualNetworkId"].(string)
	if !ok || vnetID == "" {
		return nil, fmt.Errorf("virtualNetworkId is required")
	}

	params := armprivatedns.VirtualNetworkLink{
		Location: stringPtr(location),
		Properties: &armprivatedns.VirtualNetworkLinkProperties{
			VirtualNetwork: &armprivatedns.SubResource{ID: stringPtr(vnetID)},
		},
	}
	if reg, ok := props["registrationEnabled"].(bool); ok {
		params.Properties.RegistrationEnabled = &reg
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := l.api.BeginCreateOrUpdate(ctx, rgName, zoneName, linkName, params, nil)
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
		propsJSON, err := serializePrivateDnsVNetLinkProperties(result.VirtualNetworkLink, rgName, zoneName, linkName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize VirtualNetworkLink properties: %w", err)
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

func (l *PrivateDnsZoneVNetLink) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, zoneName, linkName, err := vnetLinkPathParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := l.api.BeginDelete(ctx, rgName, zoneName, linkName, nil)
	if err != nil {
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
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
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start VirtualNetworkLink deletion: %w", err)
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

func (l *PrivateDnsZoneVNetLink) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return l.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return l.statusDelete(ctx, request, &reqID)
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

func (l *PrivateDnsZoneVNetLink) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}
	poller, err := resumePoller[armprivatedns.VirtualNetworkLinksClientCreateOrUpdateResponse](l.pipeline, reqID.ResumeToken)
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
		return l.handleCreateOrUpdateComplete(ctx, request, poller, operation)
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
		return l.handleCreateOrUpdateComplete(ctx, request, poller, operation)
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

func (l *PrivateDnsZoneVNetLink) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, poller *runtime.Poller[armprivatedns.VirtualNetworkLinksClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
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
	zoneName := parts["privatednszones"]
	propsJSON, err := serializePrivateDnsVNetLinkProperties(result.VirtualNetworkLink, rgName, zoneName, *result.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VirtualNetworkLink properties: %w", err)
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

// verifyLinkGone synchronously waits until a Get for the link returns NotFound,
// then waits an extra propagation buffer before returning Success. Azure's
// link-delete LRO reports Done before the parent zone observes the link as gone,
// so issuing the zone delete immediately after fails with a conflict. We block
// inside this single Status call (bounded) rather than asking formae to poll
// Status again, because the executor's poll cadence backs off heavily and would
// drag a 30s wait out to many minutes.
//
// Always returns Success: the link's LRO already reported Done, so this is
// best-effort verification — if Azure stays inconsistent past the budget, the
// zone delete will retry on its next sync cycle anyway.
func (l *PrivateDnsZoneVNetLink) verifyLinkGone(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) *resource.StatusResult {
	success := &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}

	rgName, zoneName, linkName, err := vnetLinkPathParts(reqID.NativeID)
	if err != nil {
		return success
	}

	const (
		pollInterval = 2 * time.Second
		maxAttempts  = 15 // up to 30s total
		zoneBuffer   = 3 * time.Second
	)
	for i := 0; i < maxAttempts; i++ {
		if _, err := l.api.Get(ctx, rgName, zoneName, linkName, nil); err != nil && isDeleteSuccessError(err) {
			// Link is 404. Give the parent zone a moment to observe the
			// removal before reporting Success — Azure's zone-side view of
			// "no more links" lags the link-side 404 by a few seconds.
			select {
			case <-ctx.Done():
			case <-time.After(zoneBuffer):
			}
			return success
		}
		select {
		case <-ctx.Done():
			return success
		case <-time.After(pollInterval):
		}
	}
	return success
}

func (l *PrivateDnsZoneVNetLink) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := resumePoller[armprivatedns.VirtualNetworkLinksClientDeleteResponse](l.pipeline, reqID.ResumeToken)
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
		return l.verifyLinkGone(ctx, request, reqID), nil
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
		return l.verifyLinkGone(ctx, request, reqID), nil
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

func (l *PrivateDnsZoneVNetLink) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]
	zoneName := request.AdditionalProperties["privateZoneName"]
	if resourceGroupName == "" || zoneName == "" {
		return &resource.ListResult{}, nil
	}
	pager := l.api.NewListPager(resourceGroupName, zoneName, nil)
	var nativeIDs []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list virtual network links: %w", err)
		}
		for _, x := range page.Value {
			if x != nil && x.ID != nil {
				nativeIDs = append(nativeIDs, *x.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
