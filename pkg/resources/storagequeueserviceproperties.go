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

const ResourceTypeStorageQueueServiceProperties = "AZURE::Storage::QueueServiceProperties"

// storageQueueServicesAPI is the armstorage surface used here. There is no
// create, no delete and no pager: the queue service is a singleton named
// `default` that ARM creates with the account and never removes, leaving only
// get/set of its properties. Both are synchronous.
type storageQueueServicesAPI interface {
	GetServiceProperties(ctx context.Context, resourceGroupName, accountName string, options *armstorage.QueueServicesClientGetServicePropertiesOptions) (armstorage.QueueServicesClientGetServicePropertiesResponse, error)
	SetServiceProperties(ctx context.Context, resourceGroupName, accountName string, parameters armstorage.QueueServiceProperties, options *armstorage.QueueServicesClientSetServicePropertiesOptions) (armstorage.QueueServicesClientSetServicePropertiesResponse, error)
}

func init() {
	registry.Register(ResourceTypeStorageQueueServiceProperties, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &StorageQueueServiceProperties{api: c.StorageQueueServicesClient, config: cfg}
	})
}

// StorageQueueServiceProperties provisions the service-level settings of a
// storage account's Queue service
// (`Microsoft.Storage/storageAccounts/<account>/queueServices/default`).
//
// The singleton is not creatable or deletable, so create and update both map onto
// setServiceProperties, and delete maps onto setting the properties back to empty
// — the state an account has before anyone configures its queue service.
type StorageQueueServiceProperties struct {
	api    storageQueueServicesAPI
	config *config.Config
}

// storageQueueServicePropertiesProps mirrors
// schema/pkl/storage/storagequeueserviceproperties.pkl.
type storageQueueServicePropertiesProps struct {
	ResourceGroupName  string                 `json:"resourceGroupName"`
	StorageAccountName string                 `json:"storageAccountName"`
	CorsRules          []queueServiceCorsRule `json:"corsRules"`
}

type queueServiceCorsRule struct {
	AllowedOrigins  []string `json:"allowedOrigins"`
	AllowedMethods  []string `json:"allowedMethods"`
	AllowedHeaders  []string `json:"allowedHeaders"`
	ExposedHeaders  []string `json:"exposedHeaders"`
	MaxAgeInSeconds int32    `json:"maxAgeInSeconds"`
}

func queueServicePropertiesFromProps(props storageQueueServicePropertiesProps) armstorage.QueueServiceProperties {
	// An empty rule list is meaningful: ARM reads it as "delete all CORS rules".
	rules := make([]*armstorage.CorsRule, 0, len(props.CorsRules))
	for _, r := range props.CorsRules {
		methods := make([]*armstorage.CorsRuleAllowedMethodsItem, 0, len(r.AllowedMethods))
		for _, m := range r.AllowedMethods {
			methods = append(methods, to.Ptr(armstorage.CorsRuleAllowedMethodsItem(m)))
		}
		rules = append(rules, &armstorage.CorsRule{
			AllowedOrigins:  stringPointers(r.AllowedOrigins),
			AllowedMethods:  methods,
			AllowedHeaders:  stringPointers(r.AllowedHeaders),
			ExposedHeaders:  stringPointers(r.ExposedHeaders),
			MaxAgeInSeconds: to.Ptr(r.MaxAgeInSeconds),
		})
	}

	return armstorage.QueueServiceProperties{
		QueueServiceProperties: &armstorage.QueueServicePropertiesProperties{
			Cors: &armstorage.CorsRules{CorsRules: rules},
		},
	}
}

func serializeStorageQueueServicePropertiesProperties(result armstorage.QueueServiceProperties, rgName, accountName string) (json.RawMessage, error) {
	props := map[string]any{
		"resourceGroupName":  rgName,
		"storageAccountName": accountName,
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if result.QueueServiceProperties == nil || result.QueueServiceProperties.Cors == nil {
		return json.Marshal(props)
	}

	rules := make([]map[string]any, 0, len(result.QueueServiceProperties.Cors.CorsRules))
	for _, r := range result.QueueServiceProperties.Cors.CorsRules {
		if r == nil {
			continue
		}
		methods := make([]string, 0, len(r.AllowedMethods))
		for _, m := range r.AllowedMethods {
			if m != nil {
				methods = append(methods, string(*m))
			}
		}
		rule := map[string]any{
			"allowedOrigins": stringsFromPointers(r.AllowedOrigins),
			"allowedMethods": methods,
			"allowedHeaders": stringsFromPointers(r.AllowedHeaders),
			"exposedHeaders": stringsFromPointers(r.ExposedHeaders),
		}
		if r.MaxAgeInSeconds != nil {
			rule["maxAgeInSeconds"] = *r.MaxAgeInSeconds
		}
		rules = append(rules, rule)
	}
	// corsRules has no schema default, so an empty list is reported as absence
	// rather than as an empty listing the caller never declared.
	if len(rules) > 0 {
		props["corsRules"] = rules
	}

	return json.Marshal(props)
}

func (q *StorageQueueServiceProperties) parseNativeID(nativeID string) (rgName, accountName string, err error) {
	rgName, names, err := armIDParts(nativeID, "storageaccounts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["storageaccounts"], nil
}

func (q *StorageQueueServiceProperties) upsert(ctx context.Context, payload json.RawMessage, nativeID string) (armstorage.QueueServiceProperties, string, string, error) {
	var props storageQueueServicePropertiesProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armstorage.QueueServiceProperties{}, "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if nativeID != "" {
		rgName, accountName, err := q.parseNativeID(nativeID)
		if err != nil {
			return armstorage.QueueServiceProperties{}, "", "", err
		}
		props.ResourceGroupName, props.StorageAccountName = rgName, accountName
	}
	if props.ResourceGroupName == "" {
		return armstorage.QueueServiceProperties{}, "", "", fmt.Errorf("resourceGroupName is required")
	}
	if props.StorageAccountName == "" {
		return armstorage.QueueServiceProperties{}, "", "", fmt.Errorf("storageAccountName is required")
	}
	if len(props.CorsRules) > 5 {
		return armstorage.QueueServiceProperties{}, props.ResourceGroupName, props.StorageAccountName,
			fmt.Errorf("at most 5 CORS rules are allowed, got %d", len(props.CorsRules))
	}

	result, err := q.api.SetServiceProperties(ctx, props.ResourceGroupName, props.StorageAccountName,
		queueServicePropertiesFromProps(props), nil)
	if err != nil {
		return armstorage.QueueServiceProperties{}, props.ResourceGroupName, props.StorageAccountName, err
	}
	return result.QueueServiceProperties, props.ResourceGroupName, props.StorageAccountName, nil
}

func (q *StorageQueueServiceProperties) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	svc, rgName, accountName, err := q.upsert(ctx, request.Properties, "")
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

	propsJSON, err := serializeStorageQueueServicePropertiesProperties(svc, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize QueueServiceProperties properties: %w", err)
	}

	nativeID := ""
	if svc.ID != nil {
		nativeID = *svc.ID
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

func (q *StorageQueueServiceProperties) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, err := q.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := q.api.GetServiceProperties(ctx, rgName, accountName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeStorageQueueServicePropertiesProperties(result.QueueServiceProperties, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize QueueServiceProperties properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeStorageQueueServiceProperties,
		Properties:   string(propsJSON),
	}, nil
}

// Update is the same setServiceProperties call: ARM replaces the whole CORS set.
func (q *StorageQueueServiceProperties) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	svc, rgName, accountName, err := q.upsert(ctx, request.DesiredProperties, request.NativeID)
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

	propsJSON, err := serializeStorageQueueServicePropertiesProperties(svc, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize QueueServiceProperties properties after update: %w", err)
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

// Delete resets the properties to empty. ARM cannot remove the queue service — it
// lives and dies with the storage account — so "deleted" means "configured back
// to nothing", which for this resource is an empty CORS rule set.
func (q *StorageQueueServiceProperties) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, err := q.parseNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	empty := armstorage.QueueServiceProperties{
		QueueServiceProperties: &armstorage.QueueServicePropertiesProperties{
			Cors: &armstorage.CorsRules{CorsRules: []*armstorage.CorsRule{}},
		},
	}
	if _, err := q.api.SetServiceProperties(ctx, rgName, accountName, empty, nil); err != nil {
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

// setServiceProperties is synchronous, so Status just re-reads.
func (q *StorageQueueServiceProperties) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, accountName, err := q.parseNativeID(request.NativeID)
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

	result, err := q.api.GetServiceProperties(ctx, rgName, accountName, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, fmt.Errorf("failed to get QueueServiceProperties status: %w", err)
	}

	propsJSON, err := serializeStorageQueueServicePropertiesProperties(result.QueueServiceProperties, rgName, accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize QueueServiceProperties properties: %w", err)
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

// List probes the singleton. Every storage account has a queue service, so a
// scoped list always reports exactly one — and an account whose queue service
// cannot be read (a Premium file-only account, say) reports none rather than
// failing the whole discovery pass.
func (q *StorageQueueServiceProperties) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["storageAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	result, err := q.api.GetServiceProperties(ctx, rgName, accountName, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.ListResult{}, nil
		}
		return nil, fmt.Errorf("failed to list QueueServiceProperties: %w", err)
	}
	if result.ID == nil {
		return &resource.ListResult{}, nil
	}
	return &resource.ListResult{NativeIDs: []string{*result.ID}}, nil
}
