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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeCdnSecret = "AZURE::Cdn::Secret"

// cdnSecretsAPI is the narrow slice of *armcdn.SecretsClient used by the
// provisioner. Create/Delete are LRO; Get is synchronous. Update goes through
// BeginCreate (PUT create-or-update).
type cdnSecretsAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, profileName string, secretName string, secret armcdn.Secret, options *armcdn.SecretsClientBeginCreateOptions) (*runtime.Poller[armcdn.SecretsClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, profileName string, secretName string, options *armcdn.SecretsClientGetOptions) (armcdn.SecretsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, profileName string, secretName string, options *armcdn.SecretsClientBeginDeleteOptions) (*runtime.Poller[armcdn.SecretsClientDeleteResponse], error)
	NewListByProfilePager(resourceGroupName string, profileName string, options *armcdn.SecretsClientListByProfileOptions) *runtime.Pager[armcdn.SecretsClientListByProfileResponse]
}

func init() {
	registry.Register(ResourceTypeCdnSecret, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CdnSecret{
			api:      c.CdnSecretsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CdnSecret is the provisioner for a Front Door secret
// (Microsoft.Cdn/profiles/secrets). It models a BYO customer certificate: the
// secret wraps a Key Vault certificate referenced by its secret id.
type CdnSecret struct {
	api      cdnSecretsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func cdnSecretIDParts(resourceID string) (rgName, profileName, secretName string, err error) {
	rgName, names, err := armIDParts(resourceID, "profiles", "secrets")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["profiles"], names["secrets"], nil
}

func buildCdnSecretParams(props map[string]any) armcdn.Secret {
	cc := &armcdn.CustomerCertificateParameters{
		Type: to.Ptr(armcdn.SecretTypeCustomerCertificate),
	}
	// The KV certificate reference (e.g. cert.res.secretId) is passed through as
	// the secret source and round-trips as-is.
	if id, ok := resolvableString(props["secretSource"]); ok {
		cc.SecretSource = &armcdn.ResourceReference{ID: stringPtr(id)}
	}
	if v, ok := props["secretVersion"].(string); ok && v != "" {
		cc.SecretVersion = stringPtr(v)
	}
	if v, ok := props["useLatestVersion"].(bool); ok {
		cc.UseLatestVersion = to.Ptr(v)
	}
	if sans := stringListFromProperties(props["subjectAlternativeNames"]); sans != nil {
		cc.SubjectAlternativeNames = sans
	}
	return armcdn.Secret{Properties: &armcdn.SecretProperties{Parameters: cc}}
}

func serializeCdnSecretProperties(result armcdn.Secret, rgName, profileName, secretName string) (json.RawMessage, error) {
	props := make(map[string]any)
	props["resourceGroupName"] = rgName
	props["profileName"] = profileName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = secretName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	if p := result.Properties; p != nil && p.Parameters != nil {
		if cc, ok := p.Parameters.(*armcdn.CustomerCertificateParameters); ok {
			props["type"] = string(armcdn.SecretTypeCustomerCertificate)
			if cc.SecretSource != nil && cc.SecretSource.ID != nil {
				props["secretSource"] = *cc.SecretSource.ID
			}
			if cc.SecretVersion != nil {
				props["secretVersion"] = *cc.SecretVersion
			}
			if cc.UseLatestVersion != nil {
				props["useLatestVersion"] = *cc.UseLatestVersion
			}
			if len(cc.SubjectAlternativeNames) > 0 {
				sans := make([]string, 0, len(cc.SubjectAlternativeNames))
				for _, s := range cc.SubjectAlternativeNames {
					if s != nil {
						sans = append(sans, *s)
					}
				}
				props["subjectAlternativeNames"] = sans
			}
		}
	}
	return json.Marshal(props)
}

func (s *CdnSecret) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	profileName, ok := props["profileName"].(string)
	if !ok || profileName == "" {
		return nil, fmt.Errorf("profileName is required")
	}
	secretName, ok := props["name"].(string)
	if !ok || secretName == "" {
		secretName = request.Label
	}

	params := buildCdnSecretParams(props)

	poller, err := s.api.BeginCreate(ctx, rgName, profileName, secretName, params, nil)
	if err != nil {
		return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusFailure,
			ErrorCode:       operationErrorCode(err),
		}}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Cdn/profiles/%s/secrets/%s",
		s.config.SubscriptionId, rgName, profileName, secretName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			}}, nil
		}
		propsJSON, err := serializeCdnSecretProperties(result.Secret, rgName, profileName, secretName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Secret properties: %w", err)
		}
		return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		}}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}
	return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationCreate,
		OperationStatus: resource.OperationStatusInProgress,
		RequestID:       reqIDJSON,
		NativeID:        expectedNativeID,
	}}, nil
}

func (s *CdnSecret) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, profileName, secretName, err := cdnSecretIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	result, err := s.api.Get(ctx, rgName, profileName, secretName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeCdnSecretProperties(result.Secret, rgName, profileName, secretName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Secret properties: %w", err)
	}
	return &resource.ReadResult{ResourceType: ResourceTypeCdnSecret, Properties: string(propsJSON)}, nil
}

func (s *CdnSecret) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, profileName, secretName, err := cdnSecretIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := buildCdnSecretParams(props)

	poller, err := s.api.BeginCreate(ctx, rgName, profileName, secretName, params, nil)
	if err != nil {
		return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        request.NativeID,
			ErrorCode:       operationErrorCode(err),
		}}, nil
	}

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			}}, nil
		}
		propsJSON, err := serializeCdnSecretProperties(result.Secret, rgName, profileName, secretName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Secret properties: %w", err)
		}
		return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		}}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}
	return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationUpdate,
		OperationStatus: resource.OperationStatusInProgress,
		RequestID:       reqIDJSON,
		NativeID:        request.NativeID,
	}}, nil
}

func (s *CdnSecret) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, profileName, secretName, err := cdnSecretIDParts(request.NativeID)
	if err != nil {
		return nil, fmt.Errorf("invalid NativeID %s: %w", request.NativeID, err)
	}
	poller, err := s.api.BeginDelete(ctx, rgName, profileName, secretName, nil)
	if err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			}}, nil
		}
		return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusFailure,
			NativeID:        request.NativeID,
			ErrorCode:       operationErrorCode(err),
		}}, fmt.Errorf("failed to start Secret deletion: %w", err)
	}
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}
	return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationDelete,
		OperationStatus: resource.OperationStatusInProgress,
		RequestID:       reqIDJSON,
		NativeID:        request.NativeID,
	}}, nil
}

func (s *CdnSecret) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       request.RequestID,
			ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
		}}, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armcdn.SecretsClientCreateResponse], error) {
				return resumePoller[armcdn.SecretsClientCreateResponse](s.pipeline, token)
			},
			func(_ context.Context, result armcdn.SecretsClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				rgName, profileName, secretName, err := cdnSecretIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := serializeCdnSecretProperties(result.Secret, rgName, profileName, secretName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize Secret properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcdn.SecretsClientDeleteResponse], error) {
				return resumePoller[armcdn.SecretsClientDeleteResponse](s.pipeline, token)
			}, nil)
	default:
		return &resource.StatusResult{ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusFailure,
			RequestID:       request.RequestID,
			ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
		}}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (s *CdnSecret) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	profileName := request.AdditionalProperties["profileName"]
	if rgName == "" || profileName == "" {
		return &resource.ListResult{}, nil
	}
	var nativeIDs []string
	pager := s.api.NewListByProfilePager(rgName, profileName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list afd secrets: %w", err)
		}
		for _, x := range page.Value {
			if x != nil && x.ID != nil {
				nativeIDs = append(nativeIDs, *x.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
