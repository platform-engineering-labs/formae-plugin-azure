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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeLogAnalyticsCluster = "AZURE::OperationalInsights::Cluster"

// logAnalyticsClustersAPI is the subset of
// *armoperationalinsights.ClustersClient used here. Create, update and delete are
// all LROs, and the update body is a distinct ClusterPatch type that reaches only
// the billing type, the SKU and the tags.
type logAnalyticsClustersAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, clusterName string, parameters armoperationalinsights.Cluster, options *armoperationalinsights.ClustersClientBeginCreateOrUpdateOptions) (*runtime.Poller[armoperationalinsights.ClustersClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, clusterName string, options *armoperationalinsights.ClustersClientGetOptions) (armoperationalinsights.ClustersClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName, clusterName string, parameters armoperationalinsights.ClusterPatch, options *armoperationalinsights.ClustersClientBeginUpdateOptions) (*runtime.Poller[armoperationalinsights.ClustersClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName, clusterName string, options *armoperationalinsights.ClustersClientBeginDeleteOptions) (*runtime.Poller[armoperationalinsights.ClustersClientDeleteResponse], error)
	NewListPager(options *armoperationalinsights.ClustersClientListOptions) *runtime.Pager[armoperationalinsights.ClustersClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armoperationalinsights.ClustersClientListByResourceGroupOptions) *runtime.Pager[armoperationalinsights.ClustersClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeLogAnalyticsCluster, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogAnalyticsCluster{
			api:      c.LogAnalyticsClustersClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// LogAnalyticsCluster is the provisioner for Log Analytics dedicated clusters
// (Microsoft.OperationalInsights/clusters).
//
// A dedicated cluster is a capacity-reservation container that workspaces are
// linked into (see AZURE::OperationalInsights::LinkedService with name
// `Cluster`). Two consequences follow from that and are visible here:
//
//   - It carries a minimum daily capacity commitment (100 GB/day at the time of
//     writing, historically 500 GB/day), billed whether or not the reservation is
//     used, so this is not a resource to create casually.
//   - Provisioning is measured in HOURS, not minutes. Microsoft documents that a
//     cluster takes a while to complete and that no workspace may be linked until
//     it does; the create LRO stays in progress for that whole time.
//
// The customer-managed-key block (keyVaultProperties) and the managed identity
// that would unlock it are deliberately not modelled: a CMK cluster needs a key
// vault with an access policy pointing back at the cluster's own identity, which
// is a two-phase bootstrap this type cannot express on its own.
type LogAnalyticsCluster struct {
	api      logAnalyticsClustersAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// logAnalyticsClusterProps mirrors
// schema/pkl/operationalinsights/loganalyticscluster.pkl.
type logAnalyticsClusterProps struct {
	Name                       string                       `json:"name"`
	ResourceGroupName          string                       `json:"resourceGroupName"`
	Location                   string                       `json:"location"`
	SKU                        *logAnalyticsClusterSKUProps `json:"sku"`
	BillingType                string                       `json:"billingType"`
	IsDoubleEncryptionEnabled  *bool                        `json:"isDoubleEncryptionEnabled"`
	IsAvailabilityZonesEnabled *bool                        `json:"isAvailabilityZonesEnabled"`
}

// logAnalyticsClusterSKUProps is the nested sku block. `CapacityReservation` is
// the only SKU name ARM accepts.
type logAnalyticsClusterSKUProps struct {
	Name     string `json:"name"`
	Capacity int64  `json:"capacity"`
}

func logAnalyticsClusterIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "clusters")
	if err != nil {
		return "", "", err
	}
	return rgName, names["clusters"], nil
}

func (c *LogAnalyticsCluster) buildPropertiesFromResult(cluster *armoperationalinsights.Cluster, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if cluster.ID != nil {
		props["id"] = *cluster.ID
	}
	if cluster.Name != nil {
		props["name"] = *cluster.Name
	}
	if cluster.Location != nil {
		props["location"] = strings.ToLower(strings.ReplaceAll(*cluster.Location, " ", ""))
	}
	if sku := cluster.SKU; sku != nil {
		entry := make(map[string]any)
		if sku.Name != nil {
			entry["name"] = canonicalizeEnum(string(*sku.Name), "CapacityReservation")
		}
		if sku.Capacity != nil {
			entry["capacity"] = int64(*sku.Capacity)
		}
		if len(entry) > 0 {
			props["sku"] = entry
		}
	}
	if p := cluster.Properties; p != nil {
		if p.BillingType != nil {
			props["billingType"] = canonicalizeEnum(string(*p.BillingType), "Cluster", "Workspaces")
		}
		if p.IsDoubleEncryptionEnabled != nil {
			props["isDoubleEncryptionEnabled"] = *p.IsDoubleEncryptionEnabled
		}
		if p.IsAvailabilityZonesEnabled != nil {
			props["isAvailabilityZonesEnabled"] = *p.IsAvailabilityZonesEnabled
		}
		// associatedWorkspaces is ARM's back-reference to workspaces that linked
		// themselves in through a linkedService; capacityReservationProperties,
		// clusterId, createdDate, lastModifiedDate and provisioningState are
		// service state. Neither group is modelled.
	}
	if tags := azureTagsToFormaeTags(cluster.Tags); len(tags) > 0 {
		props["Tags"] = tags
	}

	return props
}

func (c *LogAnalyticsCluster) parseProps(payload json.RawMessage, label string) (logAnalyticsClusterProps, string, error) {
	var props logAnalyticsClusterProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return props, "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return props, "", fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return props, "", fmt.Errorf("location is required")
	}
	if props.SKU == nil || props.SKU.Capacity <= 0 {
		return props, "", fmt.Errorf("sku.capacity is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return props, "", fmt.Errorf("name is required")
	}
	return props, name, nil
}

func logAnalyticsClusterSKU(props logAnalyticsClusterProps) *armoperationalinsights.ClusterSKU {
	if props.SKU == nil {
		return nil
	}
	skuName := props.SKU.Name
	if skuName == "" {
		skuName = string(armoperationalinsights.ClusterSKUNameEnumCapacityReservation)
	}
	return &armoperationalinsights.ClusterSKU{
		Name:     to.Ptr(armoperationalinsights.ClusterSKUNameEnum(skuName)),
		Capacity: to.Ptr(armoperationalinsights.Capacity(props.SKU.Capacity)),
	}
}

// logAnalyticsClusterParams builds the create body.
func logAnalyticsClusterParams(props logAnalyticsClusterProps, payload json.RawMessage) armoperationalinsights.Cluster {
	clusterProps := &armoperationalinsights.ClusterProperties{}
	if props.BillingType != "" {
		clusterProps.BillingType = to.Ptr(armoperationalinsights.BillingType(props.BillingType))
	}
	if props.IsDoubleEncryptionEnabled != nil {
		clusterProps.IsDoubleEncryptionEnabled = props.IsDoubleEncryptionEnabled
	}
	if props.IsAvailabilityZonesEnabled != nil {
		clusterProps.IsAvailabilityZonesEnabled = props.IsAvailabilityZonesEnabled
	}

	params := armoperationalinsights.Cluster{
		Location:   to.Ptr(props.Location),
		SKU:        logAnalyticsClusterSKU(props),
		Properties: clusterProps,
	}
	if azureTags := formaeTagsToAzureTags(payload); azureTags != nil {
		params.Tags = azureTags
	}
	return params
}

// logAnalyticsClusterPatch builds the update body. ClusterPatch reaches only the
// billing type, the SKU capacity and the tags; everything else on this resource is
// createOnly in the schema to match.
func logAnalyticsClusterPatch(props logAnalyticsClusterProps, payload json.RawMessage) armoperationalinsights.ClusterPatch {
	patch := armoperationalinsights.ClusterPatch{
		SKU:  logAnalyticsClusterSKU(props),
		Tags: formaeTagsToAzureTags(payload),
	}
	if props.BillingType != "" {
		patch.Properties = &armoperationalinsights.ClusterPatchProperties{
			BillingType: to.Ptr(armoperationalinsights.BillingType(props.BillingType)),
		}
	}
	return patch
}

func (c *LogAnalyticsCluster) completeFromCluster(cluster *armoperationalinsights.Cluster, rgName string) (string, json.RawMessage, error) {
	nativeID := ""
	if cluster.ID != nil {
		nativeID = *cluster.ID
		if rg, _, err := logAnalyticsClusterIDParts(*cluster.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(cluster, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (c *LogAnalyticsCluster) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	props, name, err := c.parseProps(request.Properties, request.Label)
	if err != nil {
		return nil, err
	}

	poller, err := c.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name,
		logAnalyticsClusterParams(props, request.Properties), nil)
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

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/clusters/%s",
		c.config.SubscriptionId, props.ResourceGroupName, name)

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
		nativeID, propsJSON, err := c.completeFromCluster(&result.Cluster, props.ResourceGroupName)
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
			// Provisioning a dedicated cluster runs for hours; say so rather than
			// leaving an operation that looks stuck without explanation.
			StatusMessage: "provisioning a Log Analytics dedicated cluster takes 1-3 hours",
		},
	}, nil
}

func (c *LogAnalyticsCluster) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := logAnalyticsClusterIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := c.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.Cluster, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogAnalyticsCluster,
		Properties:   string(propsJSON),
	}, nil
}

func (c *LogAnalyticsCluster) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := logAnalyticsClusterIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	props, _, err := c.parseProps(request.DesiredProperties, name)
	if err != nil {
		return nil, err
	}

	poller, err := c.api.BeginUpdate(ctx, rgName, name,
		logAnalyticsClusterPatch(props, request.DesiredProperties), nil)
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
		propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.Cluster, rgName))
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

func (c *LogAnalyticsCluster) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := logAnalyticsClusterIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := c.api.BeginDelete(ctx, rgName, name, nil)
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
				StatusMessage:   err.Error(),
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

func (c *LogAnalyticsCluster) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armoperationalinsights.ClustersClientCreateOrUpdateResponse], error) {
				return resumePoller[armoperationalinsights.ClustersClientCreateOrUpdateResponse](c.pipeline, token)
			},
			func(_ context.Context, result armoperationalinsights.ClustersClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return c.completeFromCluster(&result.Cluster, "")
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armoperationalinsights.ClustersClientUpdateResponse], error) {
				return resumePoller[armoperationalinsights.ClustersClientUpdateResponse](c.pipeline, token)
			},
			func(_ context.Context, result armoperationalinsights.ClustersClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return c.completeFromCluster(&result.Cluster, "")
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armoperationalinsights.ClustersClientDeleteResponse], error) {
				return resumePoller[armoperationalinsights.ClustersClientDeleteResponse](c.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

// List narrows to a resource group when one is given, and otherwise walks the
// whole subscription.
func (c *LogAnalyticsCluster) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	if rgName != "" {
		pager := c.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list log analytics clusters: %w", err)
			}
			for _, cluster := range page.Value {
				if cluster != nil && cluster.ID != nil {
					nativeIDs = append(nativeIDs, *cluster.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := c.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list log analytics clusters: %w", err)
		}
		for _, cluster := range page.Value {
			if cluster != nil && cluster.ID != nil {
				nativeIDs = append(nativeIDs, *cluster.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
