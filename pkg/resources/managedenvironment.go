// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeManagedEnvironment = "AZURE::App::ManagedEnvironment"

type managedEnvironmentsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, environmentName string, environmentEnvelope armappcontainers.ManagedEnvironment, options *armappcontainers.ManagedEnvironmentsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armappcontainers.ManagedEnvironmentsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, environmentName string, options *armappcontainers.ManagedEnvironmentsClientGetOptions) (armappcontainers.ManagedEnvironmentsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, environmentName string, options *armappcontainers.ManagedEnvironmentsClientBeginDeleteOptions) (*runtime.Poller[armappcontainers.ManagedEnvironmentsClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armappcontainers.ManagedEnvironmentsClientListByResourceGroupOptions) *runtime.Pager[armappcontainers.ManagedEnvironmentsClientListByResourceGroupResponse]
	NewListBySubscriptionPager(options *armappcontainers.ManagedEnvironmentsClientListBySubscriptionOptions) *runtime.Pager[armappcontainers.ManagedEnvironmentsClientListBySubscriptionResponse]
}

func init() {
	registry.Register(ResourceTypeManagedEnvironment, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ManagedEnvironment{
			api:      c.ManagedEnvironmentsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ManagedEnvironment is the provisioner for Azure Container Apps managed
// environments (Microsoft.App/managedEnvironments). The default consumption-only
// environment needs no log-analytics; appLogsConfiguration is optional and its
// nested logAnalyticsConfiguration.sharedKey is write-only (Azure never returns
// it), so it is accepted on write but never serialized back — see
// testdata/managed-environment.pkl.
type ManagedEnvironment struct {
	api      managedEnvironmentsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func managedEnvironmentIDParts(resourceID string) (rgName, envName string, err error) {
	rgName, names, err := armIDParts(resourceID, "managedEnvironments")
	if err != nil {
		return "", "", err
	}
	return rgName, names["managedEnvironments"], nil
}

// buildManagedEnvironmentParams converts the formae property map into an
// armappcontainers.ManagedEnvironment for BeginCreateOrUpdate. Shared by Create
// and Update so the body shape stays identical across operations.
func (env *ManagedEnvironment) buildManagedEnvironmentParams(props map[string]any, location string) (armappcontainers.ManagedEnvironment, error) {
	params := armappcontainers.ManagedEnvironment{
		Location:   stringPtr(location),
		Properties: &armappcontainers.ManagedEnvironmentProperties{},
	}

	if zr, ok := props["zoneRedundant"].(bool); ok {
		params.Properties.ZoneRedundant = &zr
	}

	if alcRaw, ok := props["appLogsConfiguration"].(map[string]any); ok {
		alc := &armappcontainers.AppLogsConfiguration{}
		if dest, ok := alcRaw["destination"].(string); ok && dest != "" {
			alc.Destination = stringPtr(dest)
		}
		if laRaw, ok := alcRaw["logAnalyticsConfiguration"].(map[string]any); ok {
			la := &armappcontainers.LogAnalyticsConfiguration{}
			if cid, ok := laRaw["customerId"].(string); ok && cid != "" {
				la.CustomerID = stringPtr(cid)
			}
			// sharedKey is write-only. Accept a plain string or an opaque wrapper;
			// never serialize it back (Azure never returns it).
			if key, ok := opaqueString(laRaw["sharedKey"]); ok {
				la.SharedKey = stringPtr(key)
			}
			alc.LogAnalyticsConfiguration = la
		}
		params.Properties.AppLogsConfiguration = alc
	}

	return params, nil
}

// serializeManagedEnvironmentProperties converts an Azure ManagedEnvironment to
// Formae property format. The write-only logAnalytics sharedKey is intentionally
// omitted so re-apply compares equal to the desired forma (zero drift).
func serializeManagedEnvironmentProperties(result armappcontainers.ManagedEnvironment, rgName, envName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = envName
	}
	if result.Location != nil {
		props["location"] = *result.Location
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if p := result.Properties; p != nil {
		if p.ZoneRedundant != nil {
			props["zoneRedundant"] = *p.ZoneRedundant
		}
		if p.DefaultDomain != nil {
			props["defaultDomain"] = *p.DefaultDomain
		}
		if p.StaticIP != nil {
			props["staticIp"] = *p.StaticIP
		}
		if alc := p.AppLogsConfiguration; alc != nil {
			m := make(map[string]any)
			if alc.Destination != nil {
				m["destination"] = *alc.Destination
			}
			if la := alc.LogAnalyticsConfiguration; la != nil {
				lm := make(map[string]any)
				if la.CustomerID != nil {
					lm["customerId"] = *la.CustomerID
				}
				// sharedKey is write-only and never read back — do not serialize.
				if len(lm) > 0 {
					m["logAnalyticsConfiguration"] = lm
				}
			}
			if len(m) > 0 {
				props["appLogsConfiguration"] = m
			}
		}
	}

	if tags := azureTagsToFormaeTags(result.Tags); tags != nil {
		props["Tags"] = tags
	}

	return json.Marshal(props)
}

func (env *ManagedEnvironment) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	envName, ok := props["name"].(string)
	if !ok || envName == "" {
		envName = request.Label
	}

	params, err := env.buildManagedEnvironmentParams(props, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := env.api.BeginCreateOrUpdate(ctx, rgName, envName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s",
		env.config.SubscriptionId, rgName, envName)

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
		propsJSON, err := serializeManagedEnvironmentProperties(result.ManagedEnvironment, rgName, envName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ManagedEnvironment properties: %w", err)
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

func (env *ManagedEnvironment) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, envName, err := managedEnvironmentIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or managedEnvironment name from %s: %w", request.NativeID, err)
	}

	result, err := env.api.Get(ctx, rgName, envName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeManagedEnvironmentProperties(result.ManagedEnvironment, rgName, envName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ManagedEnvironment properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeManagedEnvironment,
		Properties:   string(propsJSON),
	}, nil
}

func (env *ManagedEnvironment) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, envName, err := managedEnvironmentIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or managedEnvironment name from %s: %w", request.NativeID, err)
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params, err := env.buildManagedEnvironmentParams(props, location)
	if err != nil {
		return nil, err
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := env.api.BeginCreateOrUpdate(ctx, rgName, envName, params, nil)
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
		propsJSON, err := serializeManagedEnvironmentProperties(result.ManagedEnvironment, rgName, envName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ManagedEnvironment properties: %w", err)
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

func (env *ManagedEnvironment) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, envName, err := managedEnvironmentIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID: cannot extract resourceGroup or managedEnvironment name from %s: %w", request.NativeID, err)
	}

	poller, err := env.api.BeginDelete(ctx, rgName, envName, nil)
	if err != nil {
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
		}, fmt.Errorf("failed to start ManagedEnvironment deletion: %w", err)
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

func (env *ManagedEnvironment) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
		return env.statusCreateOrUpdate(ctx, request, &reqID)
	case lroOpDelete:
		return env.statusDelete(ctx, request, &reqID)
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

func (env *ManagedEnvironment) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == lroOpUpdate {
		operation = resource.OperationUpdate
	}

	return statusLRO(ctx, request, reqID, operation,
		func(token string) (*runtime.Poller[armappcontainers.ManagedEnvironmentsClientCreateOrUpdateResponse], error) {
			return resumePoller[armappcontainers.ManagedEnvironmentsClientCreateOrUpdateResponse](env.pipeline, token)
		},
		func(_ context.Context, result armappcontainers.ManagedEnvironmentsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
			rgName, envName, err := managedEnvironmentIDParts(*result.ID)
			if err != nil {
				return "", nil, err
			}
			propsJSON, err := serializeManagedEnvironmentProperties(result.ManagedEnvironment, rgName, envName)
			if err != nil {
				return "", nil, fmt.Errorf("failed to serialize ManagedEnvironment properties: %w", err)
			}
			return *result.ID, propsJSON, nil
		})
}

func (env *ManagedEnvironment) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	return statusDeleteLRO(ctx, request, reqID,
		func(token string) (*runtime.Poller[armappcontainers.ManagedEnvironmentsClientDeleteResponse], error) {
			return resumePoller[armappcontainers.ManagedEnvironmentsClientDeleteResponse](env.pipeline, token)
		}, nil)
}

func (env *ManagedEnvironment) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if resourceGroupName != "" {
		pager := env.api.NewListByResourceGroupPager(resourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list managed environments: %w", err)
			}
			for _, x := range page.Value {
				if x != nil && x.ID != nil {
					nativeIDs = append(nativeIDs, *x.ID)
				}
			}
		}
	} else {
		pager := env.api.NewListBySubscriptionPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list managed environments: %w", err)
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
