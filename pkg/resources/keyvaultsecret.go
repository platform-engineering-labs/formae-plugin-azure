// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeKeyVaultSecret = "AZURE::KeyVault::Secret"

// secretsAPI is the azsecrets surface used here; all operations are synchronous.
type secretsAPI interface {
	SetSecret(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error)
	GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
	UpdateSecretProperties(ctx context.Context, name string, version string, parameters azsecrets.UpdateSecretPropertiesParameters, options *azsecrets.UpdateSecretPropertiesOptions) (azsecrets.UpdateSecretPropertiesResponse, error)
	DeleteSecret(ctx context.Context, name string, options *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error)
	NewListSecretPropertiesPager(options *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse]
}

func init() {
	registry.Register(ResourceTypeKeyVaultSecret, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &KeyVaultSecret{cred: c.Credential(), config: cfg}
	})
}

// KeyVaultSecret provisions secrets via the per-vault azsecrets data-plane client.
type KeyVaultSecret struct {
	cred   azcore.TokenCredential
	config *config.Config
	// newAPI overrides client construction in tests; nil uses the real azsecrets client.
	newAPI func(vaultURL string) (secretsAPI, error)
}

// keyVaultSecretProps mirrors schema/pkl/keyvault/secret.pkl; value is write-only.
type keyVaultSecretProps struct {
	Name        string `json:"name"`
	VaultURI    string `json:"vaultUri"`
	Value       string `json:"value"`
	ContentType string `json:"contentType"`
}

func (s *KeyVaultSecret) clientFor(vaultURL string) (secretsAPI, error) {
	if s.newAPI != nil {
		return s.newAPI(vaultURL)
	}
	return azsecrets.NewClient(vaultURL, s.cred, nil)
}

// The versionless id is the stable NativeID; each SetSecret mints a new version.
func versionlessSecretID(vaultURI, name string) string {
	return strings.TrimRight(vaultURI, "/") + "/secrets/" + name
}

// The NativeID is a data-plane URL, not an ARM id, so parse with net/url.
func parseSecretID(nativeID string) (vaultURL, name string, err error) {
	u, err := url.Parse(nativeID)
	if err != nil {
		return "", "", fmt.Errorf("invalid secret id %q: %w", nativeID, err)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if u.Scheme == "" || u.Host == "" || len(parts) < 2 || parts[0] != "secrets" {
		return "", "", fmt.Errorf("invalid secret id %q: expected https://<vault>/secrets/<name>", nativeID)
	}
	return u.Scheme + "://" + u.Host, parts[1], nil
}

// value is intentionally omitted: it is write-only and never surfaced in state.
func buildSecretProperties(sec azsecrets.Secret, vaultURI, name, nativeID string) map[string]any {
	props := map[string]any{
		"name":     name,
		"vaultUri": vaultURI,
		"id":       nativeID,
	}
	if sec.ContentType != nil {
		props["contentType"] = *sec.ContentType
	}
	if tags := azureTagsToFormaeTags(sec.Tags); tags != nil {
		props["Tags"] = tags
	}
	return props
}

func (s *KeyVaultSecret) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props keyVaultSecretProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.VaultURI == "" {
		return nil, fmt.Errorf("vaultUri is required")
	}
	if props.Value == "" {
		return nil, fmt.Errorf("value is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}

	api, err := s.clientFor(props.VaultURI)
	if err != nil {
		return nil, err
	}

	params := azsecrets.SetSecretParameters{Value: stringPtr(props.Value)}
	if props.ContentType != "" {
		params.ContentType = stringPtr(props.ContentType)
	}
	if tags := formaeTagsToAzureTags(request.Properties); tags != nil {
		params.Tags = tags
	}

	res, err := api.SetSecret(ctx, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	nativeID := versionlessSecretID(props.VaultURI, name)
	propsJSON, err := json.Marshal(buildSecretProperties(res.Secret, props.VaultURI, name, nativeID))
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

func (s *KeyVaultSecret) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	vaultURL, name, err := parseSecretID(request.NativeID)
	if err != nil {
		return nil, err
	}
	api, err := s.clientFor(vaultURL)
	if err != nil {
		return nil, err
	}

	res, err := api.GetSecret(ctx, name, "", nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(buildSecretProperties(res.Secret, vaultURL+"/", name, request.NativeID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeKeyVaultSecret,
		Properties:   string(propsJSON),
	}, nil
}

func (s *KeyVaultSecret) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	vaultURL, name, err := parseSecretID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props keyVaultSecretProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	api, err := s.clientFor(vaultURL)
	if err != nil {
		return nil, err
	}

	// value is createOnly; Update only touches metadata (contentType, tags).
	params := azsecrets.UpdateSecretPropertiesParameters{}
	if props.ContentType != "" {
		params.ContentType = stringPtr(props.ContentType)
	}
	if tags := formaeTagsToAzureTags(request.DesiredProperties); tags != nil {
		params.Tags = tags
	}

	res, err := api.UpdateSecretProperties(ctx, name, "", params, nil)
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

	propsJSON, err := json.Marshal(buildSecretProperties(res.Secret, vaultURL+"/", name, request.NativeID))
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

func (s *KeyVaultSecret) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	vaultURL, name, err := parseSecretID(request.NativeID)
	if err != nil {
		return nil, err
	}
	api, err := s.clientFor(vaultURL)
	if err != nil {
		return nil, err
	}

	_, err = api.DeleteSecret(ctx, name, nil)
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

// Secret operations are synchronous, so Status is a no-op that satisfies the interface.
func (s *KeyVaultSecret) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List is scoped to one vault via AdditionalProperties["vaultUri"]; the data plane cannot list subscription-wide.
func (s *KeyVaultSecret) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	vaultURI := request.AdditionalProperties["vaultUri"]
	if vaultURI == "" {
		return &resource.ListResult{}, nil
	}
	api, err := s.clientFor(vaultURI)
	if err != nil {
		return nil, err
	}

	var nativeIDs []string
	pager := api.NewListSecretPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list key vault secrets: %w", err)
		}
		for _, sp := range page.Value {
			if sp.ID != nil {
				nativeIDs = append(nativeIDs, versionlessSecretID(vaultURI, sp.ID.Name()))
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
