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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeApiManagementNamedValue = "AZURE::ApiManagement::NamedValue"

// apiManagementNamedValuesAPI is the armapimanagement surface used here.
//
// The named value is the one entity in this group whose writes are LROs — ARM
// has to reach Key Vault before a vault-backed value is usable — so create and
// update return pollers. Delete is synchronous.
//
// ListValue is deliberately absent: `value` is write-only in the schema, so
// nothing reads it back.
type apiManagementNamedValuesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, parameters armapimanagement.NamedValueCreateContract, options *armapimanagement.NamedValueClientBeginCreateOrUpdateOptions) (*runtime.Poller[armapimanagement.NamedValueClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, options *armapimanagement.NamedValueClientGetOptions) (armapimanagement.NamedValueClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, ifMatch string, parameters armapimanagement.NamedValueUpdateParameters, options *armapimanagement.NamedValueClientBeginUpdateOptions) (*runtime.Poller[armapimanagement.NamedValueClientUpdateResponse], error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, ifMatch string, options *armapimanagement.NamedValueClientDeleteOptions) (armapimanagement.NamedValueClientDeleteResponse, error)
	NewListByServicePager(resourceGroupName string, serviceName string, options *armapimanagement.NamedValueClientListByServiceOptions) *runtime.Pager[armapimanagement.NamedValueClientListByServiceResponse]
}

func init() {
	registry.Register(ResourceTypeApiManagementNamedValue, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &ApiManagementNamedValue{
			api:      c.ApiManagementNamedValueClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// ApiManagementNamedValue is the provisioner for named values
// (Microsoft.ApiManagement/service/namedValues) — the store a policy
// interpolates as {{displayName}}.
type ApiManagementNamedValue struct {
	api      apiManagementNamedValuesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// apiManagementNamedValueProps mirrors
// schema/pkl/apimanagement/apimanagementnamedvalue.pkl.
type apiManagementNamedValueProps struct {
	Name                     string   `json:"name"`
	ResourceGroupName        string   `json:"resourceGroupName"`
	ServiceName              string   `json:"serviceName"`
	DisplayName              string   `json:"displayName"`
	Value                    string   `json:"value"`
	Secret                   *bool    `json:"secret"`
	Tags                     []string `json:"tags"`
	KeyVaultSecretIdentifier string   `json:"keyVaultSecretIdentifier"`
	KeyVaultIdentityClientID string   `json:"keyVaultIdentityClientId"`
}

func apiManagementNamedValueIDParts(resourceID string) (rgName, serviceName, namedValueID string, err error) {
	rgName, names, err := armExactIDParts(resourceID, "service", "namedValues")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names[0], names[1], nil
}

// keyVaultCreateProperties builds ARM's nested keyVault block from the two
// flattened schema fields, or nil when the value is inline.
func (n *apiManagementNamedValueProps) keyVaultCreateProperties() *armapimanagement.KeyVaultContractCreateProperties {
	if n.KeyVaultSecretIdentifier == "" {
		return nil
	}
	kv := &armapimanagement.KeyVaultContractCreateProperties{
		SecretIdentifier: to.Ptr(n.KeyVaultSecretIdentifier),
	}
	if n.KeyVaultIdentityClientID != "" {
		kv.IdentityClientID = to.Ptr(n.KeyVaultIdentityClientID)
	}
	return kv
}

// buildPropertiesFromResult reports only what the schema declares.
//
// `value` is never reported: it is write-only, and ARM's answer for it is
// unreliable — absent for a secret, absent for a vault-backed value, and
// present only sometimes for a plain one. Reporting it would show drift on
// every sync. `keyVault.lastStatus` is dropped for the same reason: it is the
// service's own refresh bookkeeping.
func (n *ApiManagementNamedValue) buildPropertiesFromResult(nv *armapimanagement.NamedValueContract, rgName, serviceName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"serviceName":       serviceName,
	}
	if nv.ID != nil {
		props["id"] = *nv.ID
	}
	if nv.Name != nil {
		props["name"] = *nv.Name
	}
	if np := nv.Properties; np != nil {
		if np.DisplayName != nil {
			props["displayName"] = *np.DisplayName
		}
		if np.Secret != nil {
			props["secret"] = *np.Secret
		}
		if tags := stringsFromPointers(np.Tags); len(tags) > 0 {
			props["tags"] = tags
		}
		if np.KeyVault != nil {
			if np.KeyVault.SecretIdentifier != nil {
				props["keyVaultSecretIdentifier"] = *np.KeyVault.SecretIdentifier
			}
			if np.KeyVault.IdentityClientID != nil {
				props["keyVaultIdentityClientId"] = *np.KeyVault.IdentityClientID
			}
		}
	}
	return props
}

func (n *ApiManagementNamedValue) expectedNativeID(rgName, serviceName, name string) string {
	return fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/namedValues/%s",
		n.config.SubscriptionId, rgName, serviceName, name)
}

func (n *ApiManagementNamedValue) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props apiManagementNamedValueProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	if props.DisplayName == "" {
		return nil, fmt.Errorf("displayName is required")
	}
	if props.Value == "" && props.KeyVaultSecretIdentifier == "" {
		return nil, fmt.Errorf("either value or keyVaultSecretIdentifier is required")
	}
	if props.Value != "" && props.KeyVaultSecretIdentifier != "" {
		return nil, fmt.Errorf("value and keyVaultSecretIdentifier are mutually exclusive")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	createProps := &armapimanagement.NamedValueCreateContractProperties{
		DisplayName: to.Ptr(props.DisplayName),
		Secret:      props.Secret,
		Tags:        stringPointers(props.Tags),
		KeyVault:    props.keyVaultCreateProperties(),
	}
	if props.Value != "" {
		createProps.Value = to.Ptr(props.Value)
	}

	poller, err := n.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, props.ServiceName, name,
		armapimanagement.NamedValueCreateContract{Properties: createProps}, nil)
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

	expectedID := n.expectedNativeID(props.ResourceGroupName, props.ServiceName, name)

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
		nativeID := expectedID
		if result.ID != nil {
			nativeID = *result.ID
		}
		propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&result.NamedValueContract,
			props.ResourceGroupName, props.ServiceName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (n *ApiManagementNamedValue) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serviceName, namedValueID, err := apiManagementNamedValueIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := n.api.Get(ctx, rgName, serviceName, namedValueID, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&result.NamedValueContract, rgName, serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeApiManagementNamedValue,
		Properties:   string(propsJSON),
	}, nil
}

func (n *ApiManagementNamedValue) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serviceName, namedValueID, err := apiManagementNamedValueIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props apiManagementNamedValueProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armapimanagement.NamedValueUpdateParameterProperties{
		Secret:   props.Secret,
		Tags:     stringPointers(props.Tags),
		KeyVault: props.keyVaultCreateProperties(),
	}
	if props.DisplayName != "" {
		updateProps.DisplayName = to.Ptr(props.DisplayName)
	}
	if props.Value != "" {
		updateProps.Value = to.Ptr(props.Value)
	}

	poller, err := n.api.BeginUpdate(ctx, rgName, serviceName, namedValueID, apimIfMatchAny,
		armapimanagement.NamedValueUpdateParameters{Properties: updateProps}, nil)
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
		propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&result.NamedValueContract, rgName, serviceName))
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

// Delete is synchronous — only the writes are LROs.
func (n *ApiManagementNamedValue) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serviceName, namedValueID, err := apiManagementNamedValueIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := n.api.Delete(ctx, rgName, serviceName, namedValueID, apimIfMatchAny, nil); err != nil &&
		!isDeleteSuccessError(err) {
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

func (n *ApiManagementNamedValue) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armapimanagement.NamedValueClientCreateOrUpdateResponse], error) {
				return resumePoller[armapimanagement.NamedValueClientCreateOrUpdateResponse](n.pipeline, token)
			},
			func(_ context.Context, result armapimanagement.NamedValueClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return n.completeLRO(result.NamedValueContract, reqID.NativeID)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armapimanagement.NamedValueClientUpdateResponse], error) {
				return resumePoller[armapimanagement.NamedValueClientUpdateResponse](n.pipeline, token)
			},
			func(_ context.Context, result armapimanagement.NamedValueClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return n.completeLRO(result.NamedValueContract, reqID.NativeID)
			})
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown LRO operation type: %s", reqID.OperationType)
	}
}

// completeLRO turns a finished poller result into the (nativeID, properties)
// pair statusLRO wants. The scope comes out of the ID rather than being carried
// through the resume token.
func (n *ApiManagementNamedValue) completeLRO(nv armapimanagement.NamedValueContract, fallbackID string) (string, json.RawMessage, error) {
	nativeID := fallbackID
	if nv.ID != nil {
		nativeID = *nv.ID
	}
	rgName, serviceName, _, err := apiManagementNamedValueIDParts(nativeID)
	if err != nil {
		return "", nil, err
	}
	propsJSON, err := json.Marshal(n.buildPropertiesFromResult(&nv, rgName, serviceName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List needs both the resource group and the service name: ARM has no
// subscription-wide listing of named values.
func (n *ApiManagementNamedValue) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serviceName := request.AdditionalProperties["serviceName"]
	if rgName == "" || serviceName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := n.api.NewListByServicePager(rgName, serviceName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list api management named values: %w", err)
		}
		for _, nv := range page.Value {
			if nv.ID != nil {
				nativeIDs = append(nativeIDs, *nv.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
