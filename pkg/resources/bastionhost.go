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
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeBastionHost = "AZURE::Network::BastionHost"

// bastionHostsAPI is the armnetwork surface used here. BeginUpdateTags is
// deliberately absent: it cannot change the scale units or the feature toggles, so
// every update is a re-PUT.
type bastionHostsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, bastionHostName string, parameters armnetwork.BastionHost, options *armnetwork.BastionHostsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armnetwork.BastionHostsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, bastionHostName string, options *armnetwork.BastionHostsClientGetOptions) (armnetwork.BastionHostsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, bastionHostName string, options *armnetwork.BastionHostsClientBeginDeleteOptions) (*runtime.Poller[armnetwork.BastionHostsClientDeleteResponse], error)
	NewListByResourceGroupPager(resourceGroupName string, options *armnetwork.BastionHostsClientListByResourceGroupOptions) *runtime.Pager[armnetwork.BastionHostsClientListByResourceGroupResponse]
	NewListPager(options *armnetwork.BastionHostsClientListOptions) *runtime.Pager[armnetwork.BastionHostsClientListResponse]
}

func init() {
	registry.Register(ResourceTypeBastionHost, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &BastionHost{
			api:      c.BastionHostsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// BastionHost is the provisioner for the managed jump host
// (Microsoft.Network/bastionHosts).
type BastionHost struct {
	api      bastionHostsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// bastionHostProps mirrors schema/pkl/network/bastionhost.pkl.
type bastionHostProps struct {
	Name                string                     `json:"name"`
	ResourceGroupName   string                     `json:"resourceGroupName"`
	Location            string                     `json:"location"`
	SKU                 *bastionHostSkuProps       `json:"sku"`
	ScaleUnits          *int32                     `json:"scaleUnits"`
	IPConfigurations    []bastionHostIPConfigProps `json:"ipConfigurations"`
	EnableTunneling     *bool                      `json:"enableTunneling"`
	EnableIPConnect     *bool                      `json:"enableIpConnect"`
	EnableFileCopy      *bool                      `json:"enableFileCopy"`
	EnableShareableLink *bool                      `json:"enableShareableLink"`
	EnableKerberos      *bool                      `json:"enableKerberos"`
	DisableCopyPaste    *bool                      `json:"disableCopyPaste"`
}

type bastionHostSkuProps struct {
	Name string `json:"name"`
}

type bastionHostIPConfigProps struct {
	Name                      string  `json:"name"`
	SubnetID                  string  `json:"subnetId"`
	PublicIPAddressID         string  `json:"publicIpAddressId"`
	PrivateIPAllocationMethod *string `json:"privateIpAllocationMethod"`
}

// bastionSubnetName is the only subnet name Azure accepts for a Bastion host. It is
// checked here so the failure names the real problem instead of surfacing ARM's
// generic rejection half an hour later.
const bastionSubnetName = "AzureBastionSubnet"

var (
	// bastionHostSkus and bastionIPAllocationMethods carry the canonical casing for
	// the two enums, applied on the read path because ARM echoes them back
	// inconsistently.
	bastionHostSkus            = []string{"Basic", "Standard"}
	bastionIPAllocationMethods = []string{"Dynamic", "Static"}
)

// lastARMSegment returns the final path segment of an ARM ID. For a subnet ID that
// is the subnet's own name, which is what the two gateway families have to check:
// Azure only accepts "AzureBastionSubnet" for a Bastion host and "GatewaySubnet"
// for a VirtualNetworkGateway. Reported false for an empty or trailing-slash input
// so callers skip the check instead of comparing against "".
func lastARMSegment(resourceID string) (string, bool) {
	trimmed := strings.TrimSpace(resourceID)
	if trimmed == "" {
		return "", false
	}
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 {
		trimmed = trimmed[idx+1:]
	}
	if trimmed == "" {
		return "", false
	}
	return trimmed, true
}

func bastionHostIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "bastionhosts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["bastionhosts"], nil
}

func (r *BastionHost) buildPropertiesFromResult(host *armnetwork.BastionHost, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if host.ID != nil {
		props["id"] = *host.ID
	}
	if host.Name != nil {
		props["name"] = *host.Name
	}
	if host.Location != nil {
		props["location"] = normalizeAzureLocation(*host.Location)
	}
	if tags := azureTagsToFormaeTags(host.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}
	if sku := host.SKU; sku != nil && sku.Name != nil && *sku.Name != "" {
		props["sku"] = map[string]any{
			"name": canonicalizeEnum(string(*sku.Name), bastionHostSkus...),
		}
	}

	if p := host.Properties; p != nil {
		if p.ScaleUnits != nil {
			props["scaleUnits"] = *p.ScaleUnits
		}
		if p.EnableTunneling != nil {
			props["enableTunneling"] = *p.EnableTunneling
		}
		if p.EnableIPConnect != nil {
			props["enableIpConnect"] = *p.EnableIPConnect
		}
		if p.EnableFileCopy != nil {
			props["enableFileCopy"] = *p.EnableFileCopy
		}
		if p.EnableShareableLink != nil {
			props["enableShareableLink"] = *p.EnableShareableLink
		}
		if p.EnableKerberos != nil {
			props["enableKerberos"] = *p.EnableKerberos
		}
		if p.DisableCopyPaste != nil {
			props["disableCopyPaste"] = *p.DisableCopyPaste
		}
		if configs := bastionIPConfigsToProps(p.IPConfigurations); len(configs) > 0 {
			props["ipConfigurations"] = configs
		}
		// dnsName is the FQDN Azure mints for the host, provisioningState is service
		// state, and networkAcls / virtualNetwork are Developer-SKU only and not
		// modelled.
	}

	return props
}

// bastionIPConfigsToProps is the read-path inverse of bastionIPConfigsFromProps. It
// emits only the modelled fields: the per-config ARM ID, etag, type and
// provisioningState are service-assigned.
func bastionIPConfigsToProps(configs []*armnetwork.BastionHostIPConfiguration) []map[string]any {
	if len(configs) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(configs))
	for _, cfg := range configs {
		if cfg == nil {
			continue
		}
		entry := make(map[string]any)
		if cfg.Name != nil {
			entry["name"] = *cfg.Name
		}
		if cp := cfg.Properties; cp != nil {
			if cp.Subnet != nil && cp.Subnet.ID != nil {
				entry["subnetId"] = *cp.Subnet.ID
			}
			if cp.PublicIPAddress != nil && cp.PublicIPAddress.ID != nil {
				entry["publicIpAddressId"] = *cp.PublicIPAddress.ID
			}
			if cp.PrivateIPAllocationMethod != nil && *cp.PrivateIPAllocationMethod != "" {
				entry["privateIpAllocationMethod"] = canonicalizeEnum(string(*cp.PrivateIPAllocationMethod), bastionIPAllocationMethods...)
			}
		}
		out = append(out, entry)
	}
	return out
}

// bastionIPConfigsFromProps builds the request-side IP configuration list.
func bastionIPConfigsFromProps(configs []bastionHostIPConfigProps) []*armnetwork.BastionHostIPConfiguration {
	if len(configs) == 0 {
		return nil
	}
	out := make([]*armnetwork.BastionHostIPConfiguration, 0, len(configs))
	for i := range configs {
		cfg := configs[i]
		armCfg := &armnetwork.BastionHostIPConfiguration{
			Name: to.Ptr(cfg.Name),
			Properties: &armnetwork.BastionHostIPConfigurationPropertiesFormat{
				Subnet:          &armnetwork.SubResource{ID: to.Ptr(cfg.SubnetID)},
				PublicIPAddress: &armnetwork.SubResource{ID: to.Ptr(cfg.PublicIPAddressID)},
			},
		}
		if cfg.PrivateIPAllocationMethod != nil {
			armCfg.Properties.PrivateIPAllocationMethod = to.Ptr(armnetwork.IPAllocationMethod(*cfg.PrivateIPAllocationMethod))
		}
		out = append(out, armCfg)
	}
	return out
}

// bastionHostParams builds the request body shared by create and update.
func bastionHostParams(props bastionHostProps, payload json.RawMessage) armnetwork.BastionHost {
	params := armnetwork.BastionHost{
		Location: to.Ptr(props.Location),
		Properties: &armnetwork.BastionHostPropertiesFormat{
			ScaleUnits:          props.ScaleUnits,
			IPConfigurations:    bastionIPConfigsFromProps(props.IPConfigurations),
			EnableTunneling:     props.EnableTunneling,
			EnableIPConnect:     props.EnableIPConnect,
			EnableFileCopy:      props.EnableFileCopy,
			EnableShareableLink: props.EnableShareableLink,
			EnableKerberos:      props.EnableKerberos,
			DisableCopyPaste:    props.DisableCopyPaste,
		},
	}
	if sku := props.SKU; sku != nil && sku.Name != "" {
		params.SKU = &armnetwork.SKU{Name: to.Ptr(armnetwork.BastionHostSKUName(sku.Name))}
	}

	if tags := formaeTagsToAzureTags(payload); len(tags) > 0 {
		params.Tags = tags
	}

	return params
}

// upsert backs both Create and Update: BeginUpdateTags cannot touch the scale units
// or the feature toggles, so an update is another CreateOrUpdate.
func (r *BastionHost) upsert(ctx context.Context, payload json.RawMessage, label string) (*runtime.Poller[armnetwork.BastionHostsClientCreateOrUpdateResponse], bastionHostProps, string, error) {
	var props bastionHostProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return nil, props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, props, "", fmt.Errorf("location is required")
	}
	if len(props.IPConfigurations) == 0 {
		return nil, props, "", fmt.Errorf("ipConfigurations is required")
	}
	for _, cfg := range props.IPConfigurations {
		if cfg.Name == "" {
			return nil, props, "", fmt.Errorf("every ipConfigurations entry needs a name")
		}
		if cfg.SubnetID == "" {
			return nil, props, "", fmt.Errorf("ipConfigurations entry %q needs a subnetId", cfg.Name)
		}
		if cfg.PublicIPAddressID == "" {
			return nil, props, "", fmt.Errorf("ipConfigurations entry %q needs a publicIpAddressId", cfg.Name)
		}
		// Azure only accepts a subnet literally named AzureBastionSubnet. Catching it
		// here turns a ten-minute ARM rejection into an immediate, specific error.
		if subnet, ok := lastARMSegment(cfg.SubnetID); ok && subnet != bastionSubnetName {
			return nil, props, "", fmt.Errorf("ipConfigurations entry %q references subnet %q: a Bastion host requires a subnet named exactly %s",
				cfg.Name, subnet, bastionSubnetName)
		}
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return nil, props, "", fmt.Errorf("name is required")
	}

	poller, err := r.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name,
		bastionHostParams(props, payload), nil)
	return poller, props, name, err
}

func (r *BastionHost) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/bastionHosts/%s",
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
		nativeID, propsJSON, err := r.completeFromHost(&result.BastionHost)
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

func (r *BastionHost) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := bastionHostIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.BastionHost, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeBastionHost,
		Properties:   string(propsJSON),
	}, nil
}

func (r *BastionHost) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, _, err := bastionHostIDParts(request.NativeID)
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
		propsJSON, err := json.Marshal(r.buildPropertiesFromResult(&result.BastionHost, rgName))
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

func (r *BastionHost) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := bastionHostIDParts(request.NativeID)
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

func (r *BastionHost) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
			func(token string) (*runtime.Poller[armnetwork.BastionHostsClientCreateOrUpdateResponse], error) {
				return resumePoller[armnetwork.BastionHostsClientCreateOrUpdateResponse](r.pipeline, token)
			},
			func(_ context.Context, result armnetwork.BastionHostsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return r.completeFromHost(&result.BastionHost)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armnetwork.BastionHostsClientDeleteResponse], error) {
				return resumePoller[armnetwork.BastionHostsClientDeleteResponse](r.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (r *BastionHost) completeFromHost(host *armnetwork.BastionHost) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if host.ID != nil {
		nativeID = *host.ID
		if rg, _, err := bastionHostIDParts(*host.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(r.buildPropertiesFromResult(host, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

// List narrows to a resource group when one is supplied and otherwise sweeps the
// whole subscription.
func (r *BastionHost) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := r.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list bastion hosts in resource group %s: %w", rgName, err)
			}
			for _, host := range page.Value {
				if host.ID != nil {
					nativeIDs = append(nativeIDs, *host.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := r.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list bastion hosts: %w", err)
		}
		for _, host := range page.Value {
			if host.ID != nil {
				nativeIDs = append(nativeIDs, *host.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
