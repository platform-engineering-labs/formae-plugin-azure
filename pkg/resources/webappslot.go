// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeWebAppSlot = "AZURE::Web::WebAppSlot"

// webAppSlotsAPI is the slot method family of *armappservice.WebAppsClient.
//
// ARM models a deployment slot as a child of the site, so every call carries both
// the parent site name and the slot name. Create/update is a long-running
// operation; DeleteSlot and the config call are synchronous.
type webAppSlotsAPI interface {
	BeginCreateOrUpdateSlot(ctx context.Context, resourceGroupName string, name string, slot string, siteEnvelope armappservice.Site, options *armappservice.WebAppsClientBeginCreateOrUpdateSlotOptions) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateSlotResponse], error)
	GetSlot(ctx context.Context, resourceGroupName string, name string, slot string, options *armappservice.WebAppsClientGetSlotOptions) (armappservice.WebAppsClientGetSlotResponse, error)
	DeleteSlot(ctx context.Context, resourceGroupName string, name string, slot string, options *armappservice.WebAppsClientDeleteSlotOptions) (armappservice.WebAppsClientDeleteSlotResponse, error)
	GetConfigurationSlot(ctx context.Context, resourceGroupName string, name string, slot string, options *armappservice.WebAppsClientGetConfigurationSlotOptions) (armappservice.WebAppsClientGetConfigurationSlotResponse, error)
	NewListSlotsPager(resourceGroupName string, name string, options *armappservice.WebAppsClientListSlotsOptions) *runtime.Pager[armappservice.WebAppsClientListSlotsResponse]
}

func init() {
	registry.Register(ResourceTypeWebAppSlot, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &WebAppSlot{
			api:      c.AppServiceWebAppsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// WebAppSlot is the provisioner for App Service deployment slots
// (Microsoft.Web/sites/{site}/slots/{slot}). It is a child of AZURE::Web::WebApp.
//
// Like the parent site, the slot GET returns an EMPTY siteConfig, so Read makes a
// second call to .../config/web on the slot. `appSettings` is write-only for the
// same reason as on the parent — see webapp.go.
type WebAppSlot struct {
	api      webAppSlotsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func webAppSlotIDParts(resourceID string) (rgName, siteName, slotName string, err error) {
	rgName, names, err := armIDParts(resourceID, "sites", "slots")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["sites"], names["slots"], nil
}

// serializeWebAppSlotProperties converts an ARM slot site plus its separately
// fetched config into formae property format.
//
// It does not reuse serializeWebSiteProperties because the slot schema is a strict
// subset: emitting a field the slot schema does not declare (identity,
// publicNetworkAccess, virtualNetworkSubnetId) would put properties in state that
// no forma can express.
func serializeWebAppSlotProperties(site armappservice.Site, siteConfig *armappservice.SiteConfig, rgName, siteName, slotName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["siteName"] = siteName
	props["name"] = slotName
	if site.Location != nil {
		props["location"] = normalizeAzureLocation(*site.Location)
	}
	if site.ID != nil {
		props["id"] = *site.ID
	}
	if site.Kind != nil && *site.Kind != "" {
		props["kind"] = *site.Kind
	}

	if p := site.Properties; p != nil {
		if p.ServerFarmID != nil {
			props["serverFarmId"] = *p.ServerFarmID
		}
		if p.HTTPSOnly != nil {
			props["httpsOnly"] = *p.HTTPSOnly
		}
		if p.DefaultHostName != nil {
			props["defaultHostName"] = *p.DefaultHostName
		}
	}

	if cfg := webSiteConfigToProps(siteConfig, false); cfg != nil {
		props["siteConfig"] = cfg
	}
	if tags := azureTagsToFormaeTags(site.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// readSlotConfig fetches the slot's .../config/web. A NotFound is tolerated: the
// slot exists but carries no config resource yet, so the block is omitted.
func (s *WebAppSlot) readSlotConfig(ctx context.Context, rgName, siteName, slotName string) (*armappservice.SiteConfig, error) {
	cfgResult, err := s.api.GetConfigurationSlot(ctx, rgName, siteName, slotName, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return nil, nil
		}
		return nil, err
	}
	return cfgResult.Properties, nil
}

// slotScope pulls the resource group, parent site and slot name out of a property
// map. Slots are addressed by three path segments, so all three have to be present
// before any write can be attempted.
func slotScope(props map[string]any, label string) (rgName, siteName, slotName, location string, err error) {
	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return "", "", "", "", fmt.Errorf("resourceGroupName is required")
	}
	siteName, ok = resolvableString(props["siteName"])
	if !ok {
		return "", "", "", "", fmt.Errorf("siteName is required")
	}
	location, ok = props["location"].(string)
	if !ok || location == "" {
		return "", "", "", "", fmt.Errorf("location is required")
	}
	slotName, ok = props["name"].(string)
	if !ok || slotName == "" {
		slotName = label
	}
	if slotName == "" {
		return "", "", "", "", fmt.Errorf("name is required")
	}
	return rgName, siteName, slotName, location, nil
}

func (s *WebAppSlot) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, siteName, slotName, location, err := slotScope(props, request.Label)
	if err != nil {
		return nil, err
	}

	params, err := buildWebSiteParams(props, location, false)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := s.api.BeginCreateOrUpdateSlot(ctx, rgName, siteName, slotName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/sites/%s/slots/%s",
		s.config.SubscriptionId, rgName, siteName, slotName)

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
		siteConfig, err := s.readSlotConfig(ctx, rgName, siteName, slotName)
		if err != nil {
			return nil, fmt.Errorf("failed to read WebAppSlot site config: %w", err)
		}
		propsJSON, err := json.Marshal(serializeWebAppSlotProperties(result.Site, siteConfig, rgName, siteName, slotName))
		if err != nil {
			return nil, fmt.Errorf("failed to serialize WebAppSlot properties: %w", err)
		}
		nativeID := expectedNativeID
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

func (s *WebAppSlot) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, siteName, slotName, err := webAppSlotIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup, site or slot name from %s: %w", request.NativeID, err)
	}

	result, err := s.api.GetSlot(ctx, rgName, siteName, slotName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	siteConfig, err := s.readSlotConfig(ctx, rgName, siteName, slotName)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := json.Marshal(serializeWebAppSlotProperties(result.Site, siteConfig, rgName, siteName, slotName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize WebAppSlot properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeWebAppSlot,
		Properties:   string(propsJSON),
	}, nil
}

func (s *WebAppSlot) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, siteName, slotName, err := webAppSlotIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup, site or slot name from %s: %w", request.NativeID, err)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params, err := buildWebSiteParams(props, location, false)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := s.api.BeginCreateOrUpdateSlot(ctx, rgName, siteName, slotName, params, nil)
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
		siteConfig, err := s.readSlotConfig(ctx, rgName, siteName, slotName)
		if err != nil {
			return nil, fmt.Errorf("failed to read WebAppSlot site config: %w", err)
		}
		propsJSON, err := json.Marshal(serializeWebAppSlotProperties(result.Site, siteConfig, rgName, siteName, slotName))
		if err != nil {
			return nil, fmt.Errorf("failed to serialize WebAppSlot properties: %w", err)
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

// Delete is synchronous: ARM deletes a slot inline. A 404 is success so the
// operation is idempotent.
func (s *WebAppSlot) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, siteName, slotName, err := webAppSlotIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup, site or slot name from %s: %w", request.NativeID, err)
	}

	if _, err := s.api.DeleteSlot(ctx, rgName, siteName, slotName, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status resumes a create or update poller. DeleteSlot is synchronous and never
// returns a request ID, so there is no delete branch.
func (s *WebAppSlot) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateSlotResponse], error) {
				return resumePoller[armappservice.WebAppsClientCreateOrUpdateSlotResponse](s.pipeline, token)
			},
			func(pollCtx context.Context, result armappservice.WebAppsClientCreateOrUpdateSlotResponse, _ resource.Operation) (string, json.RawMessage, error) {
				if result.ID == nil {
					return "", nil, fmt.Errorf("WebAppSlot create/update returned no resource ID")
				}
				rgName, siteName, slotName, err := webAppSlotIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				siteConfig, err := s.readSlotConfig(pollCtx, rgName, siteName, slotName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to read WebAppSlot site config: %w", err)
				}
				propsJSON, err := json.Marshal(serializeWebAppSlotProperties(result.Site, siteConfig, rgName, siteName, slotName))
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize WebAppSlot properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unexpected operation type: %s", reqID.OperationType)
	}
}

// List enumerates the slots of one parent app. ARM has no subscription-wide slot
// listing, so discovery depends on the parent chain handing down both the resource
// group and the site name.
func (s *WebAppSlot) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	siteName := request.AdditionalProperties["siteName"]

	var nativeIDs []string
	pager := s.api.NewListSlotsPager(rgName, siteName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list deployment slots for site %s: %w", siteName, err)
		}
		for _, slot := range page.Value {
			if slot != nil && slot.ID != nil {
				nativeIDs = append(nativeIDs, *slot.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
