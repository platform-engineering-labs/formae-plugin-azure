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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v5"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeFunctionApp = "AZURE::Web::FunctionApp"

// defaultFunctionAppKind is what a function app gets when the forma does not pin a
// kind. ARM stores function apps under Microsoft.Web/sites and tells them apart
// from web apps by this field alone, so it can never be empty.
const defaultFunctionAppKind = "functionapp"

func init() {
	registry.Register(ResourceTypeFunctionApp, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &FunctionApp{
			api:      c.AppServiceWebAppsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// FunctionApp is the provisioner for Azure Functions apps — Microsoft.Web/sites
// with a `functionapp` kind.
//
// It shares the ARM type, the client and most of the marshalling with
// AZURE::Web::WebApp (see webapp.go for the two ARM quirks that shape both: the
// empty siteConfig on the site GET, and write-only app settings). It stays a
// distinct formae type because the function-specific surface is what makes a
// function app one: the pinned kind, functionAppScaleLimit, and the mandatory
// storage-account app settings.
//
// Discovery is partitioned by kind: this type enumerates only sites whose kind
// carries "functionapp", WebApp only the ones that do not, so no site is reported
// twice.
type FunctionApp struct {
	api      webSitesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// functionAppKind resolves the kind to send. An explicit kind that does not carry
// "functionapp" is rejected rather than silently corrected: it would create a plain
// web app under a formae resource that claims to be a function app, and the next
// discovery pass would not even see it as this type.
func functionAppKind(props map[string]any) (string, error) {
	kind, _ := props["kind"].(string)
	if kind == "" {
		return defaultFunctionAppKind, nil
	}
	if !strings.Contains(strings.ToLower(kind), defaultFunctionAppKind) {
		return "", fmt.Errorf("kind %q is not a function app kind: it must contain %q", kind, defaultFunctionAppKind)
	}
	return kind, nil
}

// buildFunctionAppParams builds the site body for a function app: the shared site
// marshalling plus the pinned kind.
func buildFunctionAppParams(props map[string]any, location string) (armappservice.Site, error) {
	kind, err := functionAppKind(props)
	if err != nil {
		return armappservice.Site{}, err
	}
	params, err := buildWebSiteParams(props, location, true)
	if err != nil {
		return params, err
	}
	params.Kind = stringPtr(kind)
	return params, nil
}

func (f *FunctionApp) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	siteName, ok := props["name"].(string)
	if !ok || siteName == "" {
		siteName = request.Label
	}
	if siteName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := buildFunctionAppParams(props, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := f.api.BeginCreateOrUpdate(ctx, rgName, siteName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/sites/%s",
		f.config.SubscriptionId, rgName, siteName)

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
		siteConfig, err := webReadSiteConfig(ctx, f.api, rgName, siteName)
		if err != nil {
			return nil, fmt.Errorf("failed to read FunctionApp site config: %w", err)
		}
		propsJSON, err := json.Marshal(serializeWebSiteProperties(result.Site, siteConfig, rgName, siteName, true))
		if err != nil {
			return nil, fmt.Errorf("failed to serialize FunctionApp properties: %w", err)
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

func (f *FunctionApp) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, siteName, err := webAppIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or site name from %s: %w", request.NativeID, err)
	}

	result, err := f.api.Get(ctx, rgName, siteName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	siteConfig, err := webReadSiteConfig(ctx, f.api, rgName, siteName)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := json.Marshal(serializeWebSiteProperties(result.Site, siteConfig, rgName, siteName, true))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize FunctionApp properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeFunctionApp,
		Properties:   string(propsJSON),
	}, nil
}

func (f *FunctionApp) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, siteName, err := webAppIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or site name from %s: %w", request.NativeID, err)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params, err := buildFunctionAppParams(props, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := f.api.BeginCreateOrUpdate(ctx, rgName, siteName, params, nil)
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
		siteConfig, err := webReadSiteConfig(ctx, f.api, rgName, siteName)
		if err != nil {
			return nil, fmt.Errorf("failed to read FunctionApp site config: %w", err)
		}
		propsJSON, err := json.Marshal(serializeWebSiteProperties(result.Site, siteConfig, rgName, siteName, true))
		if err != nil {
			return nil, fmt.Errorf("failed to serialize FunctionApp properties: %w", err)
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

// Delete is synchronous: ARM deletes a site inline. A 404 is success so the
// operation is idempotent.
func (f *FunctionApp) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, siteName, err := webAppIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or site name from %s: %w", request.NativeID, err)
	}

	if _, err := f.api.Delete(ctx, rgName, siteName, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status resumes a create or update poller. Delete is synchronous and never
// returns a request ID, so there is no delete branch.
func (f *FunctionApp) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
			func(token string) (*runtime.Poller[armappservice.WebAppsClientCreateOrUpdateResponse], error) {
				return resumePoller[armappservice.WebAppsClientCreateOrUpdateResponse](f.pipeline, token)
			},
			func(pollCtx context.Context, result armappservice.WebAppsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				if result.ID == nil {
					return "", nil, fmt.Errorf("FunctionApp create/update returned no resource ID")
				}
				rgName, siteName, err := webAppIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				siteConfig, err := webReadSiteConfig(pollCtx, f.api, rgName, siteName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to read FunctionApp site config: %w", err)
				}
				propsJSON, err := json.Marshal(serializeWebSiteProperties(result.Site, siteConfig, rgName, siteName, true))
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize FunctionApp properties: %w", err)
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

// List enumerates only the sites whose kind carries "functionapp";
// AZURE::Web::WebApp enumerates the complement.
func (f *FunctionApp) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	return webListSites(ctx, f.api, request.AdditionalProperties["resourceGroupName"], true)
}
