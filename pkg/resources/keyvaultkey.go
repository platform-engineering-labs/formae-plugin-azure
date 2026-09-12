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
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeKeyVaultKey = "AZURE::KeyVault::Key"

// keysAPI is the azkeys surface used here; all operations are synchronous.
//
// This is deliberately the DATA-plane client, not ARM's armkeyvault.KeysClient:
// that one exposes only CreateIfNotExist/Get/GetVersion/List — no Delete and no
// upsert — so it cannot back a full CRUD provisioner. azkeys mirrors azsecrets.
type keysAPI interface {
	CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error)
	GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	UpdateKey(ctx context.Context, name string, version string, parameters azkeys.UpdateKeyParameters, options *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error)
	DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error)
	PurgeDeletedKey(ctx context.Context, name string, options *azkeys.PurgeDeletedKeyOptions) (azkeys.PurgeDeletedKeyResponse, error)
	NewListKeyPropertiesPager(options *azkeys.ListKeyPropertiesOptions) *runtime.Pager[azkeys.ListKeyPropertiesResponse]
}

// Soft delete cannot be turned off on a Key Vault, so a deleted key keeps its
// name reserved for the retention period and re-creating it fails with a 409.
// Purge after delete so the name is immediately reusable; the deleted entity can
// take a moment to become purgeable, hence the short retry.
const keyPurgeAttempts = 3

func init() {
	registry.Register(ResourceTypeKeyVaultKey, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &KeyVaultKey{
			config:     cfg,
			purgeDelay: 2 * time.Second,
			newAPI: func(vaultURL string) (keysAPI, error) {
				return c.KeysClient(vaultURL)
			},
		}
	})
}

// KeyVaultKey provisions keys via the per-vault azkeys data-plane client.
type KeyVaultKey struct {
	config *config.Config
	// newAPI builds the per-vault-endpoint client; tests substitute a fake.
	newAPI func(vaultURL string) (keysAPI, error)
	// purgeDelay is the wait between purge attempts; tests set it to zero.
	purgeDelay time.Duration
}

// keyVaultKeyProps mirrors schema/pkl/keyvault/key.pkl.
type keyVaultKeyProps struct {
	Name      string   `json:"name"`
	VaultURI  string   `json:"vaultUri"`
	KeyType   string   `json:"keyType"`
	KeySize   *int32   `json:"keySize"`
	CurveName string   `json:"curveName"`
	KeyOps    []string `json:"keyOps"`
	Enabled   *bool    `json:"enabled"`
	ExpiresOn string   `json:"expiresOn"`
	NotBefore string   `json:"notBefore"`
}

func (k *KeyVaultKey) clientFor(vaultURL string) (keysAPI, error) {
	return k.newAPI(vaultURL)
}

// The versionless id is the stable NativeID; each CreateKey mints a new version.
func versionlessKeyID(vaultURI, name string) string {
	return strings.TrimRight(vaultURI, "/") + "/keys/" + name
}

// The NativeID is a data-plane URL, not an ARM id, so parse with net/url.
func parseKeyID(nativeID string) (vaultURL, name string, err error) {
	u, err := url.Parse(nativeID)
	if err != nil {
		return "", "", fmt.Errorf("invalid key id %q: %w", nativeID, err)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if u.Scheme == "" || u.Host == "" || len(parts) < 2 || parts[0] != "keys" {
		return "", "", fmt.Errorf("invalid key id %q: expected https://<vault>/keys/<name>", nativeID)
	}
	return u.Scheme + "://" + u.Host, parts[1], nil
}

// rsaKeySizeBits recovers the create-time keySize from the public modulus.
//
// Key Vault never echoes the `key_size` create parameter back on any response,
// so a read that simply omitted it would report drift against the desired state
// on every single reconcile. The modulus length is the same number: an RSA-2048
// key has a 256-byte modulus. Returns 0 for anything that is not an RSA key.
func rsaKeySizeBits(jwk *azkeys.JSONWebKey) int32 {
	if jwk == nil || jwk.Kty == nil || len(jwk.N) == 0 {
		return 0
	}
	switch *jwk.Kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		return int32(len(jwk.N) * 8) //nolint:gosec // modulus length is bounded by the RSA key sizes Key Vault accepts
	default:
		return 0
	}
}

// buildKeyProperties returns the read-back property set shared by Create, Read
// and Update. Key material beyond the public JWK components is never returned by
// the service and is never surfaced here.
func buildKeyProperties(kb azkeys.KeyBundle, vaultURI, name, nativeID string) map[string]any {
	props := map[string]any{
		"name":     name,
		"vaultUri": vaultURI,
		"id":       nativeID,
	}

	if kb.Key != nil {
		if kb.Key.Kty != nil {
			props["keyType"] = string(*kb.Key.Kty)
		}
		if kb.Key.Crv != nil {
			props["curveName"] = string(*kb.Key.Crv)
		}
		if size := rsaKeySizeBits(kb.Key); size > 0 {
			props["keySize"] = size
		}
		if len(kb.Key.KeyOps) > 0 {
			ops := make([]string, 0, len(kb.Key.KeyOps))
			for _, op := range kb.Key.KeyOps {
				if op != nil {
					ops = append(ops, string(*op))
				}
			}
			props["keyOps"] = ops
		}
		if kb.Key.KID != nil {
			props["keyVersion"] = kb.Key.KID.Version()
		}
	}

	if kb.Attributes != nil {
		if kb.Attributes.Enabled != nil {
			props["enabled"] = *kb.Attributes.Enabled
		}
		if kb.Attributes.Expires != nil {
			props["expiresOn"] = kb.Attributes.Expires.UTC().Format(time.RFC3339)
		}
		if kb.Attributes.NotBefore != nil {
			props["notBefore"] = kb.Attributes.NotBefore.UTC().Format(time.RFC3339)
		}
	}

	if tags := azureTagsToFormaeTags(kb.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// keyOpsToAzure maps the schema's key operation names onto the SDK pointer slice.
func keyOpsToAzure(ops []string) []*azkeys.KeyOperation {
	if len(ops) == 0 {
		return nil
	}
	out := make([]*azkeys.KeyOperation, 0, len(ops))
	for _, op := range ops {
		out = append(out, to.Ptr(azkeys.KeyOperation(op)))
	}
	return out
}

// keyAttributes builds the attribute block, or nil when nothing was declared so
// the request body omits it entirely and the service applies its own defaults.
func (p keyVaultKeyProps) keyAttributes() (*azkeys.KeyAttributes, error) {
	attrs := &azkeys.KeyAttributes{Enabled: p.Enabled}
	set := p.Enabled != nil

	if p.ExpiresOn != "" {
		t, err := parseTime(p.ExpiresOn)
		if err != nil {
			return nil, fmt.Errorf("invalid expiresOn: %w", err)
		}
		attrs.Expires = &t
		set = true
	}
	if p.NotBefore != "" {
		t, err := parseTime(p.NotBefore)
		if err != nil {
			return nil, fmt.Errorf("invalid notBefore: %w", err)
		}
		attrs.NotBefore = &t
		set = true
	}
	if !set {
		return nil, nil
	}
	return attrs, nil
}

func (k *KeyVaultKey) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props keyVaultKeyProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.VaultURI == "" {
		return nil, fmt.Errorf("vaultUri is required")
	}
	if props.KeyType == "" {
		return nil, fmt.Errorf("keyType is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	attrs, err := props.keyAttributes()
	if err != nil {
		return nil, err
	}

	api, err := k.clientFor(props.VaultURI)
	if err != nil {
		return nil, err
	}

	params := azkeys.CreateKeyParameters{
		Kty:           to.Ptr(azkeys.KeyType(props.KeyType)),
		KeySize:       props.KeySize,
		KeyOps:        keyOpsToAzure(props.KeyOps),
		KeyAttributes: attrs,
	}
	if props.CurveName != "" {
		params.Curve = to.Ptr(azkeys.CurveName(props.CurveName))
	}
	if tags := formaeTagsToAzureTags(request.Properties); tags != nil {
		params.Tags = tags
	}

	res, err := api.CreateKey(ctx, name, params, nil)
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

	nativeID := versionlessKeyID(props.VaultURI, name)
	propsJSON, err := json.Marshal(buildKeyProperties(res.KeyBundle, props.VaultURI, name, nativeID))
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

func (k *KeyVaultKey) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	vaultURL, name, err := parseKeyID(request.NativeID)
	if err != nil {
		return nil, err
	}
	api, err := k.clientFor(vaultURL)
	if err != nil {
		return nil, err
	}

	res, err := api.GetKey(ctx, name, "", nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(buildKeyProperties(res.KeyBundle, vaultURL+"/", name, request.NativeID))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeKeyVaultKey,
		Properties:   string(propsJSON),
	}, nil
}

// Update patches the latest version in place. keyType, keySize and curveName are
// createOnly in the schema — changing key material means a new key, which core
// handles as a replace rather than an update.
func (k *KeyVaultKey) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	vaultURL, name, err := parseKeyID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props keyVaultKeyProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	attrs, err := props.keyAttributes()
	if err != nil {
		return nil, err
	}

	api, err := k.clientFor(vaultURL)
	if err != nil {
		return nil, err
	}

	params := azkeys.UpdateKeyParameters{
		KeyAttributes: attrs,
		KeyOps:        keyOpsToAzure(props.KeyOps),
	}
	if tags := formaeTagsToAzureTags(request.DesiredProperties); tags != nil {
		params.Tags = tags
	}

	res, err := api.UpdateKey(ctx, name, "", params, nil)
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

	propsJSON, err := json.Marshal(buildKeyProperties(res.KeyBundle, vaultURL+"/", name, request.NativeID))
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

func (k *KeyVaultKey) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	vaultURL, name, err := parseKeyID(request.NativeID)
	if err != nil {
		return nil, err
	}
	api, err := k.clientFor(vaultURL)
	if err != nil {
		return nil, err
	}

	if _, err := api.DeleteKey(ctx, name, nil); err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			k.purgeDeleted(ctx, api, name)
			return keyDeleteSuccess(request.NativeID), nil
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

	k.purgeDeleted(ctx, api, name)
	return keyDeleteSuccess(request.NativeID), nil
}

func keyDeleteSuccess(nativeID string) *resource.DeleteResult {
	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        nativeID,
		},
	}
}

// purgeDeleted frees the key name after a soft delete. It is best effort: a vault
// with purge protection refuses the call, and there the delete has still done
// everything it can, so a failure must not fail the operation.
func (k *KeyVaultKey) purgeDeleted(ctx context.Context, api keysAPI, name string) {
	for attempt := 0; attempt < keyPurgeAttempts; attempt++ {
		_, err := api.PurgeDeletedKey(ctx, name, nil)
		if err == nil || operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return
		}
		if k.purgeDelay <= 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(k.purgeDelay):
		}
	}
}

// Key operations are synchronous, so Status is a no-op that satisfies the interface.
func (k *KeyVaultKey) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List is scoped to one vault via AdditionalProperties["vaultUri"]; the data plane cannot list subscription-wide.
func (k *KeyVaultKey) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	vaultURI := request.AdditionalProperties["vaultUri"]
	if vaultURI == "" {
		return &resource.ListResult{}, nil
	}
	api, err := k.clientFor(vaultURI)
	if err != nil {
		return nil, err
	}

	var nativeIDs []string
	pager := api.NewListKeyPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list key vault keys: %w", err)
		}
		for _, kp := range page.Value {
			if kp.KID != nil {
				nativeIDs = append(nativeIDs, versionlessKeyID(vaultURI, kp.KID.Name()))
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
