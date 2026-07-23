// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeKeyVaultCertificate = "AZURE::KeyVault::Certificate"

// certificatesAPI is the azcertificates surface used here; all operations are
// treated synchronously (a self-signed CreateCertificate completes immediately).
type certificatesAPI interface {
	ImportCertificate(ctx context.Context, name string, parameters azcertificates.ImportCertificateParameters, options *azcertificates.ImportCertificateOptions) (azcertificates.ImportCertificateResponse, error)
	CreateCertificate(ctx context.Context, name string, parameters azcertificates.CreateCertificateParameters, options *azcertificates.CreateCertificateOptions) (azcertificates.CreateCertificateResponse, error)
	GetCertificate(ctx context.Context, name string, version string, options *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error)
	UpdateCertificate(ctx context.Context, name string, version string, parameters azcertificates.UpdateCertificateParameters, options *azcertificates.UpdateCertificateOptions) (azcertificates.UpdateCertificateResponse, error)
	DeleteCertificate(ctx context.Context, name string, options *azcertificates.DeleteCertificateOptions) (azcertificates.DeleteCertificateResponse, error)
	NewListCertificatePropertiesPager(options *azcertificates.ListCertificatePropertiesOptions) *runtime.Pager[azcertificates.ListCertificatePropertiesResponse]
}

func init() {
	registry.Register(ResourceTypeKeyVaultCertificate, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &KeyVaultCertificate{cred: c.Credential(), config: cfg}
	})
}

// KeyVaultCertificate provisions certificates via the per-vault azcertificates
// data-plane client, exactly like KeyVaultSecret (credential-based, no ARM client).
type KeyVaultCertificate struct {
	cred   azcore.TokenCredential
	config *config.Config
	// newAPI overrides client construction in tests; nil uses the real azcertificates client.
	newAPI func(vaultURL string) (certificatesAPI, error)
}

// certificatePolicy mirrors the minimal schema Policy class for the issued path.
type certificatePolicy struct {
	IssuerName     string `json:"issuerName"`
	Subject        string `json:"subject"`
	KeyType        string `json:"keyType"`
	ValidityMonths int32  `json:"validityMonths"`
}

// keyVaultCertificateProps mirrors schema/pkl/keyvault/certificate.pkl; data and
// password are write-only and never surfaced back in state.
type keyVaultCertificateProps struct {
	Name     string             `json:"name"`
	VaultURI string             `json:"vaultUri"`
	Policy   *certificatePolicy `json:"policy"`
}

func (c *KeyVaultCertificate) clientFor(vaultURL string) (certificatesAPI, error) {
	if c.newAPI != nil {
		return c.newAPI(vaultURL)
	}
	return azcertificates.NewClient(vaultURL, c.cred, nil)
}

// The versionless id is the stable NativeID; each import/issue mints a new version.
func versionlessCertificateID(vaultURI, name string) string {
	return strings.TrimRight(vaultURI, "/") + "/certificates/" + name
}

// The NativeID is a data-plane URL, not an ARM id, so parse with net/url.
func parseCertificateID(nativeID string) (vaultURL, name string, err error) {
	u, err := url.Parse(nativeID)
	if err != nil {
		return "", "", fmt.Errorf("invalid certificate id %q: %w", nativeID, err)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if u.Scheme == "" || u.Host == "" || len(parts) < 2 || parts[0] != "certificates" {
		return "", "", fmt.Errorf("invalid certificate id %q: expected https://<vault>/certificates/<name>", nativeID)
	}
	return u.Scheme + "://" + u.Host, parts[1], nil
}

// buildCertificateProperties serializes metadata only. data and password are
// write-only and are intentionally never included.
func buildCertificateProperties(cert azcertificates.Certificate, vaultURI, name, nativeID string) map[string]any {
	props := map[string]any{
		"name":     name,
		"vaultUri": vaultURI,
		"id":       nativeID,
	}
	if cert.SID != nil {
		props["secretId"] = string(*cert.SID)
	}
	if cert.KID != nil {
		props["kid"] = string(*cert.KID)
	}
	if len(cert.X509Thumbprint) > 0 {
		props["thumbprint"] = hex.EncodeToString(cert.X509Thumbprint)
	}
	if cert.Attributes != nil && cert.Attributes.Enabled != nil {
		props["enabled"] = *cert.Attributes.Enabled
	}
	if tags := azureTagsToFormaeTags(cert.Tags); tags != nil {
		props["Tags"] = tags
	}
	return props
}

// buildIssuePolicy maps the minimal schema Policy onto an azcertificates policy.
func buildIssuePolicy(p *certificatePolicy) *azcertificates.CertificatePolicy {
	policy := &azcertificates.CertificatePolicy{
		IssuerParameters: &azcertificates.IssuerParameters{Name: stringPtr(p.IssuerName)},
		X509CertificateProperties: &azcertificates.X509CertificateProperties{
			Subject: stringPtr(p.Subject),
		},
	}
	if p.ValidityMonths > 0 {
		v := p.ValidityMonths
		policy.X509CertificateProperties.ValidityInMonths = &v
	}
	if p.KeyType != "" {
		kt := azcertificates.KeyType(p.KeyType)
		policy.KeyProperties = &azcertificates.KeyProperties{KeyType: &kt}
	}
	return policy
}

func (c *KeyVaultCertificate) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props keyVaultCertificateProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.VaultURI == "" {
		return nil, fmt.Errorf("vaultUri is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}

	// A raw map lets opaqueString unwrap the write-only import fields, which core
	// may deliver as a plain string or as an opaque wrapper under $value.
	var raw map[string]any
	if err := json.Unmarshal(request.Properties, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	data, hasData := opaqueString(raw["data"])

	if !hasData && props.Policy == nil {
		return nil, fmt.Errorf("either data (import) or policy (issue) is required")
	}

	api, err := c.clientFor(props.VaultURI)
	if err != nil {
		return nil, err
	}

	nativeID := versionlessCertificateID(props.VaultURI, name)

	var propsMap map[string]any
	if hasData {
		// Import path wins when data is present.
		params := azcertificates.ImportCertificateParameters{
			Base64EncodedCertificate: stringPtr(data),
		}
		if password, ok := opaqueString(raw["password"]); ok {
			params.Password = stringPtr(password)
		}
		if tags := formaeTagsToAzureTags(request.Properties); tags != nil {
			params.Tags = tags
		}
		res, err := api.ImportCertificate(ctx, name, params, nil)
		if err != nil {
			return certificateCreateFailure(err), nil
		}
		propsMap = buildCertificateProperties(res.Certificate, props.VaultURI, name, nativeID)
	} else {
		// Issue path: create via a (self-signed) policy.
		params := azcertificates.CreateCertificateParameters{
			CertificatePolicy: buildIssuePolicy(props.Policy),
		}
		if tags := formaeTagsToAzureTags(request.Properties); tags != nil {
			params.Tags = tags
		}
		if _, err := api.CreateCertificate(ctx, name, params, nil); err != nil {
			return certificateCreateFailure(err), nil
		}
		// The issue response is an async operation without cert metadata; emit the
		// minimal identity and let Read backfill thumbprint/secretId.
		propsMap = map[string]any{"name": name, "vaultUri": props.VaultURI, "id": nativeID}
		if tags := azureTagsToFormaeTags(params.Tags); tags != nil {
			propsMap["Tags"] = tags
		}
	}

	propsJSON, err := json.Marshal(propsMap)
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

func certificateCreateFailure(err error) *resource.CreateResult {
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusFailure,
			ErrorCode:       operationErrorCode(err),
		},
	}
}

func (c *KeyVaultCertificate) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	vaultURL, name, err := parseCertificateID(request.NativeID)
	if err != nil {
		return nil, err
	}
	api, err := c.clientFor(vaultURL)
	if err != nil {
		return nil, err
	}

	res, err := api.GetCertificate(ctx, name, "", nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(buildCertificateProperties(res.Certificate, vaultURL+"/", name, request.NativeID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeKeyVaultCertificate,
		Properties:   string(propsJSON),
	}, nil
}

func (c *KeyVaultCertificate) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	vaultURL, name, err := parseCertificateID(request.NativeID)
	if err != nil {
		return nil, err
	}
	api, err := c.clientFor(vaultURL)
	if err != nil {
		return nil, err
	}

	// Only non-createOnly metadata (tags) is mutable in place; data/password are
	// createOnly and never patched here.
	params := azcertificates.UpdateCertificateParameters{}
	if tags := formaeTagsToAzureTags(request.DesiredProperties); tags != nil {
		params.Tags = tags
	}
	res, err := api.UpdateCertificate(ctx, name, "", params, nil)
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

	propsJSON, err := json.Marshal(buildCertificateProperties(res.Certificate, vaultURL+"/", name, request.NativeID))
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

func (c *KeyVaultCertificate) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	vaultURL, name, err := parseCertificateID(request.NativeID)
	if err != nil {
		return nil, err
	}
	api, err := c.clientFor(vaultURL)
	if err != nil {
		return nil, err
	}

	if _, err := api.DeleteCertificate(ctx, name, nil); err != nil {
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

// Certificate operations are treated synchronously, so Status is a no-op that
// satisfies the interface (mirrors KeyVaultSecret).
func (c *KeyVaultCertificate) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List is scoped to one vault via AdditionalProperties["vaultUri"]; the data plane cannot list subscription-wide.
func (c *KeyVaultCertificate) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	vaultURI := request.AdditionalProperties["vaultUri"]
	if vaultURI == "" {
		return &resource.ListResult{}, nil
	}
	api, err := c.clientFor(vaultURI)
	if err != nil {
		return nil, err
	}

	var nativeIDs []string
	pager := api.NewListCertificatePropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list key vault certificates: %w", err)
		}
		for _, cp := range page.Value {
			if cp.ID != nil {
				nativeIDs = append(nativeIDs, versionlessCertificateID(vaultURI, cp.ID.Name()))
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
