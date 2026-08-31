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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeVirtualNetworkGatewayConnection = "AZURE::Network::VirtualNetworkGatewayConnection"

// virtualNetworkGatewayConnectionsAPI is the armnetwork surface used here.
// BeginUpdateTags and BeginSetSharedKey are deliberately absent: neither can change
// the IPsec policies or the routing weight, so every update is a re-PUT.
type virtualNetworkGatewayConnectionsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, virtualNetworkGatewayConnectionName string, parameters armnetwork.VirtualNetworkGatewayConnection, options *armnetwork.VirtualNetworkGatewayConnectionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, virtualNetworkGatewayConnectionName string, options *armnetwork.VirtualNetworkGatewayConnectionsClientGetOptions) (armnetwork.VirtualNetworkGatewayConnectionsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, virtualNetworkGatewayConnectionName string, options *armnetwork.VirtualNetworkGatewayConnectionsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientDeleteResponse], error)
	NewListPager(resourceGroupName string, options *armnetwork.VirtualNetworkGatewayConnectionsClientListOptions) *runtime.Pager[armnetwork.VirtualNetworkGatewayConnectionsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeVirtualNetworkGatewayConnection, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &VirtualNetworkGatewayConnection{
			api:      c.VirtualNetworkGatewayConnectionsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// VirtualNetworkGatewayConnection is the provisioner for the tunnel joining a
// virtual network gateway to its peer (Microsoft.Network/connections).
type VirtualNetworkGatewayConnection struct {
	api      virtualNetworkGatewayConnectionsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// virtualNetworkGatewayConnectionProps mirrors
// schema/pkl/network/virtualnetworkgatewayconnection.pkl.
type virtualNetworkGatewayConnectionProps struct {
	Name                           string                                      `json:"name"`
	ResourceGroupName              string                                      `json:"resourceGroupName"`
	Location                       string                                      `json:"location"`
	ConnectionType                 string                                      `json:"connectionType"`
	VirtualNetworkGateway1ID       string                                      `json:"virtualNetworkGateway1Id"`
	LocalNetworkGateway2ID         *string                                     `json:"localNetworkGateway2Id"`
	VirtualNetworkGateway2ID       *string                                     `json:"virtualNetworkGateway2Id"`
	PeerID                         *string                                     `json:"peerId"`
	SharedKey                      *string                                     `json:"sharedKey"`
	AuthorizationKey               *string                                     `json:"authorizationKey"`
	EnableBgp                      *bool                                       `json:"enableBgp"`
	ConnectionProtocol             *string                                     `json:"connectionProtocol"`
	ConnectionMode                 *string                                     `json:"connectionMode"`
	RoutingWeight                  *int32                                      `json:"routingWeight"`
	DpdTimeoutSeconds              *int32                                      `json:"dpdTimeoutSeconds"`
	UsePolicyBasedTrafficSelectors *bool                                       `json:"usePolicyBasedTrafficSelectors"`
	UseLocalAzureIPAddress         *bool                                       `json:"useLocalAzureIpAddress"`
	ExpressRouteGatewayBypass      *bool                                       `json:"expressRouteGatewayBypass"`
	IpsecPolicies                  []virtualNetworkGatewayConnectionIpsecProps `json:"ipsecPolicies"`
}

type virtualNetworkGatewayConnectionIpsecProps struct {
	SaLifeTimeSeconds   *int32 `json:"saLifeTimeSeconds"`
	SaDataSizeKilobytes *int32 `json:"saDataSizeKilobytes"`
	IpsecEncryption     string `json:"ipsecEncryption"`
	IpsecIntegrity      string `json:"ipsecIntegrity"`
	IkeEncryption       string `json:"ikeEncryption"`
	IkeIntegrity        string `json:"ikeIntegrity"`
	DhGroup             string `json:"dhGroup"`
	PfsGroup            string `json:"pfsGroup"`
}

var (
	// The canonical casing for every enum the connection echoes back, applied on the
	// read path because ARM is inconsistent about it.
	connectionTypes     = []string{"IPsec", "Vnet2Vnet", "ExpressRoute", "VPNClient"}
	connectionProtocols = []string{"IKEv1", "IKEv2"}
	connectionModes     = []string{"Default", "InitiatorOnly", "ResponderOnly"}
	dhGroups            = []string{"None", "DHGroup1", "DHGroup2", "DHGroup14", "DHGroup24", "DHGroup2048", "ECP256", "ECP384"}
	pfsGroups           = []string{"None", "PFS1", "PFS2", "PFS14", "PFS24", "PFS2048", "PFSMM", "ECP256", "ECP384"}
	ipsecEncryptions    = []string{"None", "DES", "DES3", "AES128", "AES192", "AES256", "GCMAES128", "GCMAES192", "GCMAES256"}
	ipsecIntegrities    = []string{"MD5", "SHA1", "SHA256", "GCMAES128", "GCMAES192", "GCMAES256"}
	ikeEncryptions      = []string{"DES", "DES3", "AES128", "AES192", "AES256", "GCMAES128", "GCMAES256"}
	ikeIntegrities      = []string{"MD5", "SHA1", "SHA256", "SHA384", "GCMAES128", "GCMAES256"}
)

func virtualNetworkGatewayConnectionIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "connections")
	if err != nil {
		return "", "", err
	}
	return rgName, names["connections"], nil
}

func (r *VirtualNetworkGatewayConnection) buildPropertiesFromResult(conn *armnetwork.VirtualNetworkGatewayConnection, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if conn.ID != nil {
		props["id"] = *conn.ID
	}
	if conn.Name != nil {
		props["name"] = *conn.Name
	}
	if conn.Location != nil {
		props["location"] = normalizeAzureLocation(*conn.Location)
	}
	if tags := azureTagsToFormaeTags(conn.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	p := conn.Properties
	if p == nil {
		return props
	}

	if p.ConnectionType != nil && *p.ConnectionType != "" {
		props["connectionType"] = canonicalizeEnum(string(*p.ConnectionType), connectionTypes...)
	}
	// ARM echoes the peers back as full gateway objects with their own properties
	// inflated; only the ARM ID is ours.
	if p.VirtualNetworkGateway1 != nil && p.VirtualNetworkGateway1.ID != nil {
		props["virtualNetworkGateway1Id"] = *p.VirtualNetworkGateway1.ID
	}
	if p.LocalNetworkGateway2 != nil && p.LocalNetworkGateway2.ID != nil {
		props["localNetworkGateway2Id"] = *p.LocalNetworkGateway2.ID
	}
	if p.VirtualNetworkGateway2 != nil && p.VirtualNetworkGateway2.ID != nil {
		props["virtualNetworkGateway2Id"] = *p.VirtualNetworkGateway2.ID
	}
	if p.Peer != nil && p.Peer.ID != nil {
		props["peerId"] = *p.Peer.ID
	}
	if p.EnableBgp != nil {
		props["enableBgp"] = *p.EnableBgp
	}
	if p.ConnectionProtocol != nil && *p.ConnectionProtocol != "" {
		props["connectionProtocol"] = canonicalizeEnum(string(*p.ConnectionProtocol), connectionProtocols...)
	}
	if p.ConnectionMode != nil && *p.ConnectionMode != "" {
		props["connectionMode"] = canonicalizeEnum(string(*p.ConnectionMode), connectionModes...)
	}
	if p.RoutingWeight != nil {
		props["routingWeight"] = *p.RoutingWeight
	}
	if p.DpdTimeoutSeconds != nil {
		props["dpdTimeoutSeconds"] = *p.DpdTimeoutSeconds
	}
	if p.UsePolicyBasedTrafficSelectors != nil {
		props["usePolicyBasedTrafficSelectors"] = *p.UsePolicyBasedTrafficSelectors
	}
	if p.UseLocalAzureIPAddress != nil {
		props["useLocalAzureIpAddress"] = *p.UseLocalAzureIPAddress
	}
	if p.ExpressRouteGatewayBypass != nil {
		props["expressRouteGatewayBypass"] = *p.ExpressRouteGatewayBypass
	}
	if policies := ipsecPoliciesToProps(p.IPSecPolicies); len(policies) > 0 {
		props["ipsecPolicies"] = policies
	}
	// sharedKey and authorizationKey are write-only: ARM does hand the shared key
	// back, and surfacing it would put a pre-shared key into stored state.
	// provisioningState, resourceGuid, connectionStatus, the byte counters and
	// tunnelConnectionStatus are service state.

	return props
}

// ipsecPoliciesToProps is the read-path inverse of ipsecPoliciesFromProps.
func ipsecPoliciesToProps(policies []*armnetwork.IPSecPolicy) []map[string]any {
	if len(policies) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(policies))
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		entry := make(map[string]any)
		if policy.SaLifeTimeSeconds != nil {
			entry["saLifeTimeSeconds"] = *policy.SaLifeTimeSeconds
		}
		if policy.SaDataSizeKilobytes != nil {
			entry["saDataSizeKilobytes"] = *policy.SaDataSizeKilobytes
		}
		if policy.IPSecEncryption != nil && *policy.IPSecEncryption != "" {
			entry["ipsecEncryption"] = canonicalizeEnum(string(*policy.IPSecEncryption), ipsecEncryptions...)
		}
		if policy.IPSecIntegrity != nil && *policy.IPSecIntegrity != "" {
			entry["ipsecIntegrity"] = canonicalizeEnum(string(*policy.IPSecIntegrity), ipsecIntegrities...)
		}
		if policy.IkeEncryption != nil && *policy.IkeEncryption != "" {
			entry["ikeEncryption"] = canonicalizeEnum(string(*policy.IkeEncryption), ikeEncryptions...)
		}
		if policy.IkeIntegrity != nil && *policy.IkeIntegrity != "" {
			entry["ikeIntegrity"] = canonicalizeEnum(string(*policy.IkeIntegrity), ikeIntegrities...)
		}
		if policy.DhGroup != nil && *policy.DhGroup != "" {
			entry["dhGroup"] = canonicalizeEnum(string(*policy.DhGroup), dhGroups...)
		}
		if policy.PfsGroup != nil && *policy.PfsGroup != "" {
			entry["pfsGroup"] = canonicalizeEnum(string(*policy.PfsGroup), pfsGroups...)
		}
		out = append(out, entry)
	}
	return out
}

// ipsecPoliciesFromProps builds the request-side policy list.
func ipsecPoliciesFromProps(policies []virtualNetworkGatewayConnectionIpsecProps) []*armnetwork.IPSecPolicy {
	if len(policies) == 0 {
		return nil
	}
	out := make([]*armnetwork.IPSecPolicy, 0, len(policies))
	for i := range policies {
		policy := policies[i]
		out = append(out, &armnetwork.IPSecPolicy{
			SaLifeTimeSeconds:   policy.SaLifeTimeSeconds,
			SaDataSizeKilobytes: policy.SaDataSizeKilobytes,
			IPSecEncryption:     to.Ptr(armnetwork.IPSecEncryption(policy.IpsecEncryption)),
			IPSecIntegrity:      to.Ptr(armnetwork.IPSecIntegrity(policy.IpsecIntegrity)),
			IkeEncryption:       to.Ptr(armnetwork.IkeEncryption(policy.IkeEncryption)),
			IkeIntegrity:        to.Ptr(armnetwork.IkeIntegrity(policy.IkeIntegrity)),
			DhGroup:             to.Ptr(armnetwork.DhGroup(policy.DhGroup)),
			PfsGroup:            to.Ptr(armnetwork.PfsGroup(policy.PfsGroup)),
		})
	}
	return out
}

// virtualNetworkGatewayConnectionParams builds the request body shared by create and
// update.
//
// ARM models the two gateway peers as whole VirtualNetworkGateway /
// LocalNetworkGateway objects rather than SubResources, but accepts a body carrying
// only their `id`, which is what is sent here.
func virtualNetworkGatewayConnectionParams(props virtualNetworkGatewayConnectionProps, payload json.RawMessage) armnetwork.VirtualNetworkGatewayConnection {
	params := armnetwork.VirtualNetworkGatewayConnection{
		Location: to.Ptr(props.Location),
		Properties: &armnetwork.VirtualNetworkGatewayConnectionPropertiesFormat{
			ConnectionType: to.Ptr(armnetwork.VirtualNetworkGatewayConnectionType(props.ConnectionType)),
			VirtualNetworkGateway1: &armnetwork.VirtualNetworkGateway{
				ID: to.Ptr(props.VirtualNetworkGateway1ID),
			},
			SharedKey:                      props.SharedKey,
			AuthorizationKey:               props.AuthorizationKey,
			EnableBgp:                      props.EnableBgp,
			RoutingWeight:                  props.RoutingWeight,
			DpdTimeoutSeconds:              props.DpdTimeoutSeconds,
			UsePolicyBasedTrafficSelectors: props.UsePolicyBasedTrafficSelectors,
			UseLocalAzureIPAddress:         props.UseLocalAzureIPAddress,
			ExpressRouteGatewayBypass:      props.ExpressRouteGatewayBypass,
			IPSecPolicies:                  ipsecPoliciesFromProps(props.IpsecPolicies),
		},
	}
	if props.LocalNetworkGateway2ID != nil && *props.LocalNetworkGateway2ID != "" {
		params.Properties.LocalNetworkGateway2 = &armnetwork.LocalNetworkGateway{ID: props.LocalNetworkGateway2ID}
	}
	if props.VirtualNetworkGateway2ID != nil && *props.VirtualNetworkGateway2ID != "" {
		params.Properties.VirtualNetworkGateway2 = &armnetwork.VirtualNetworkGateway{ID: props.VirtualNetworkGateway2ID}
	}
	if props.PeerID != nil && *props.PeerID != "" {
		params.Properties.Peer = &armnetwork.SubResource{ID: props.PeerID}
	}
	if props.ConnectionProtocol != nil {
		params.Properties.ConnectionProtocol = to.Ptr(armnetwork.VirtualNetworkGatewayConnectionProtocol(*props.ConnectionProtocol))
	}
	if props.ConnectionMode != nil {
		params.Properties.ConnectionMode = to.Ptr(armnetwork.VirtualNetworkGatewayConnectionMode(*props.ConnectionMode))
	}

	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}

	return params
}

// upsert backs both Create and Update: neither BeginUpdateTags nor
// BeginSetSharedKey can change the IPsec policies, so an update is another
// CreateOrUpdate.
func (r *VirtualNetworkGatewayConnection) upsert(ctx context.Context, payload json.RawMessage, label string) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse], virtualNetworkGatewayConnectionProps, string, error) {
	var props virtualNetworkGatewayConnectionProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return nil, props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, props, "", fmt.Errorf("location is required")
	}
	if props.ConnectionType == "" {
		return nil, props, "", fmt.Errorf("connectionType is required")
	}
	if props.VirtualNetworkGateway1ID == "" {
		return nil, props, "", fmt.Errorf("virtualNetworkGateway1Id is required")
	}
	// Each connection type has exactly one peer field, and ARM's rejection for the
	// wrong one is opaque.
	switch props.ConnectionType {
	case "IPsec":
		if props.LocalNetworkGateway2ID == nil || *props.LocalNetworkGateway2ID == "" {
			return nil, props, "", fmt.Errorf("localNetworkGateway2Id is required for an IPsec connection")
		}
	case "Vnet2Vnet":
		if props.VirtualNetworkGateway2ID == nil || *props.VirtualNetworkGateway2ID == "" {
			return nil, props, "", fmt.Errorf("virtualNetworkGateway2Id is required for a Vnet2Vnet connection")
		}
	case "ExpressRoute":
		if props.PeerID == nil || *props.PeerID == "" {
			return nil, props, "", fmt.Errorf("peerId is required for an ExpressRoute connection")
		}
	}
	// Azure accepts at most one custom policy per connection.
	if len(props.IpsecPolicies) > 1 {
		return nil, props, "", fmt.Errorf("ipsecPolicies accepts at most one entry, got %d", len(props.IpsecPolicies))
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return nil, props, "", fmt.Errorf("name is required")
	}

	poller, err := r.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name,
		virtualNetworkGatewayConnectionParams(props, payload), nil)
	return poller, props, name, err
}

func (r *VirtualNetworkGatewayConnection) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	poller, props, name, err := r.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if name == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/connections/%s",
		r.config.SubscriptionId, props.ResourceGroupName, name)

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
		nativeID, propsJSON, err := r.completeFromConnection(&result.VirtualNetworkGatewayConnection)
		if err != nil {
			return nil, err
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

func (r *VirtualNetworkGatewayConnection) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := virtualNetworkGatewayConnectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.VirtualNetworkGatewayConnection, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeVirtualNetworkGatewayConnection,
		Properties:   string(propsJSON),
	}, nil
}

func (r *VirtualNetworkGatewayConnection) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, _, err := virtualNetworkGatewayConnectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, _, name, err := r.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if name == "" {
			return nil, err
		}
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
		propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.VirtualNetworkGatewayConnection, rgName))
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

func (r *VirtualNetworkGatewayConnection) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := virtualNetworkGatewayConnectionIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := r.api.BeginDelete(ctx, rgName, name, nil)
	if err != nil {
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
			},
		}, nil
	}

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
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

func (r *VirtualNetworkGatewayConnection) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		// Both resume as CreateOrUpdate responses: Update re-PUTs, so the poller that
		// issued the token has the same response type in either case.
		operation := resource.OperationCreate
		if reqID.OperationType == lroOpUpdate {
			operation = resource.OperationUpdate
		}
		return statusLRO(ctx, request, &reqID, operation,
			func(token string) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armnetwork.VirtualNetworkGatewayConnectionsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return r.completeFromConnection(&result.VirtualNetworkGatewayConnection)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.VirtualNetworkGatewayConnectionsClientDeleteResponse], error) {
				return resumePoller[armnetwork.VirtualNetworkGatewayConnectionsClientDeleteResponse](r.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (r *VirtualNetworkGatewayConnection) completeFromConnection(conn *armnetwork.VirtualNetworkGatewayConnection) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if conn.ID != nil {
		nativeID = *conn.ID
		if rg, _, err := virtualNetworkGatewayConnectionIDParts(*conn.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(conn, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List is scoped to a resource group: ARM offers no subscription-wide listing for
// connections.
func (r *VirtualNetworkGatewayConnection) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	if rgName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := r.api.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list virtual network gateway connections in resource group %s: %w", rgName, err)
		}
		for _, conn := range page.Value {
			if conn.ID != nil {
				nativeIDs = append(nativeIDs, *conn.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
