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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeCosmosDatabaseAccount = "AZURE::DocumentDB::DatabaseAccount"

// cosmosDatabaseAccountsAPI is the armcosmos surface used here. Create and Delete
// are LROs; Update is also an LRO but takes a distinct update-parameters type.
type cosmosDatabaseAccountsAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, accountName string, createUpdateParameters armcosmos.DatabaseAccountCreateUpdateParameters, options *armcosmos.DatabaseAccountsClientBeginCreateOrUpdateOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName string, accountName string, options *armcosmos.DatabaseAccountsClientGetOptions) (armcosmos.DatabaseAccountsClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, accountName string, updateParameters armcosmos.DatabaseAccountUpdateParameters, options *armcosmos.DatabaseAccountsClientBeginUpdateOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, accountName string, options *armcosmos.DatabaseAccountsClientBeginDeleteOptions) (*runtime.Poller[armcosmos.DatabaseAccountsClientDeleteResponse], error)
	NewListPager(options *armcosmos.DatabaseAccountsClientListOptions) *runtime.Pager[armcosmos.DatabaseAccountsClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armcosmos.DatabaseAccountsClientListByResourceGroupOptions) *runtime.Pager[armcosmos.DatabaseAccountsClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeCosmosDatabaseAccount, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &CosmosDatabaseAccount{
			api:      c.CosmosDatabaseAccountsClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// CosmosDatabaseAccount is the provisioner for Cosmos DB accounts
// (Microsoft.DocumentDB/databaseAccounts).
//
// Master keys and connection strings are never serialized: ARM returns them only
// from separate ListKeys / ListConnectionStrings calls, so putting them in
// resource state would persist live credentials.
type CosmosDatabaseAccount struct {
	api      cosmosDatabaseAccountsAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

// cosmosDatabaseAccountProps mirrors schema/pkl/documentdb/databaseaccount.pkl.
type cosmosDatabaseAccountProps struct {
	Name                         string                   `json:"name"`
	Location                     string                   `json:"location"`
	ResourceGroupName            string                   `json:"resourceGroupName"`
	Kind                         string                   `json:"kind"`
	Capabilities                 []string                 `json:"capabilities"`
	GeoLocations                 []cosmosGeoLocation      `json:"geoLocations"`
	ConsistencyPolicy            *cosmosConsistencyPolicy `json:"consistencyPolicy"`
	EnableAutomaticFailover      *bool                    `json:"enableAutomaticFailover"`
	EnableMultipleWriteLocations *bool                    `json:"enableMultipleWriteLocations"`
	EnableFreeTier               *bool                    `json:"enableFreeTier"`
	DisableLocalAuth             *bool                    `json:"disableLocalAuth"`
	PublicNetworkAccess          string                   `json:"publicNetworkAccess"`
	MinimalTLSVersion            string                   `json:"minimalTlsVersion"`
}

type cosmosGeoLocation struct {
	LocationName     string `json:"locationName"`
	FailoverPriority int32  `json:"failoverPriority"`
	IsZoneRedundant  *bool  `json:"isZoneRedundant"`
}

type cosmosConsistencyPolicy struct {
	DefaultConsistencyLevel string `json:"defaultConsistencyLevel"`
	MaxStalenessPrefix      *int64 `json:"maxStalenessPrefix"`
	MaxIntervalInSeconds    *int32 `json:"maxIntervalInSeconds"`
}

func cosmosDatabaseAccountIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "databaseaccounts")
	if err != nil {
		return "", "", err
	}
	return rgName, names["databaseaccounts"], nil
}

func (c *CosmosDatabaseAccount) buildPropertiesFromResult(acct *armcosmos.DatabaseAccountGetResults, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if acct.ID != nil {
		props["id"] = *acct.ID
	}
	if acct.Name != nil {
		props["name"] = *acct.Name
	}
	if acct.Location != nil {
		props["location"] = normalizeAzureLocation(*acct.Location)
	}
	if acct.Kind != nil {
		props["kind"] = string(*acct.Kind)
	}

	if p := acct.Properties; p != nil {
		if p.DocumentEndpoint != nil {
			props["documentEndpoint"] = *p.DocumentEndpoint
		}
		if p.EnableAutomaticFailover != nil {
			props["enableAutomaticFailover"] = *p.EnableAutomaticFailover
		}
		if p.EnableMultipleWriteLocations != nil {
			props["enableMultipleWriteLocations"] = *p.EnableMultipleWriteLocations
		}
		if p.EnableFreeTier != nil {
			props["enableFreeTier"] = *p.EnableFreeTier
		}
		if p.DisableLocalAuth != nil {
			props["disableLocalAuth"] = *p.DisableLocalAuth
		}
		if p.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = string(*p.PublicNetworkAccess)
		}
		if p.MinimalTLSVersion != nil {
			props["minimalTlsVersion"] = string(*p.MinimalTLSVersion)
		}
		// Capabilities select the account's API family (Cassandra, Gremlin, Table)
		// and gate which child resources it accepts.
		capabilities := make([]string, 0, len(p.Capabilities))
		for _, capability := range p.Capabilities {
			if capability == nil || capability.Name == nil {
				continue
			}
			capabilities = append(capabilities, *capability.Name)
		}
		if len(capabilities) > 0 {
			props["capabilities"] = capabilities
		}
		if cp := p.ConsistencyPolicy; cp != nil {
			entry := map[string]any{}
			if cp.DefaultConsistencyLevel != nil {
				entry["defaultConsistencyLevel"] = string(*cp.DefaultConsistencyLevel)
			}
			if cp.MaxStalenessPrefix != nil {
				entry["maxStalenessPrefix"] = *cp.MaxStalenessPrefix
			}
			if cp.MaxIntervalInSeconds != nil {
				entry["maxIntervalInSeconds"] = *cp.MaxIntervalInSeconds
			}
			if len(entry) > 0 {
				props["consistencyPolicy"] = entry
			}
		}
		// Locations is the read-back of the requested geoLocations. ARM also
		// returns readLocations/writeLocations/failoverPolicies views of the same
		// data; only this one round-trips against desired state.
		geos := make([]map[string]any, 0, len(p.Locations))
		for _, loc := range p.Locations {
			if loc == nil || loc.LocationName == nil {
				continue
			}
			entry := map[string]any{"locationName": normalizeAzureLocation(*loc.LocationName)}
			if loc.FailoverPriority != nil {
				entry["failoverPriority"] = *loc.FailoverPriority
			}
			if loc.IsZoneRedundant != nil {
				entry["isZoneRedundant"] = *loc.IsZoneRedundant
			}
			geos = append(geos, entry)
		}
		if len(geos) > 0 {
			props["geoLocations"] = geos
		}
	}

	if tags := azureTagsToFormaeTags(acct.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func cosmosLocationsFromProps(props cosmosDatabaseAccountProps) []*armcosmos.Location {
	locations := make([]*armcosmos.Location, 0, len(props.GeoLocations))
	for _, geo := range props.GeoLocations {
		loc := &armcosmos.Location{
			LocationName:     to.Ptr(geo.LocationName),
			FailoverPriority: to.Ptr(geo.FailoverPriority),
		}
		if geo.IsZoneRedundant != nil {
			loc.IsZoneRedundant = geo.IsZoneRedundant
		}
		locations = append(locations, loc)
	}
	return locations
}

func cosmosCapabilitiesFromProps(props cosmosDatabaseAccountProps) []*armcosmos.Capability {
	if len(props.Capabilities) == 0 {
		return nil
	}
	capabilities := make([]*armcosmos.Capability, 0, len(props.Capabilities))
	for _, name := range props.Capabilities {
		if name == "" {
			continue
		}
		capabilities = append(capabilities, &armcosmos.Capability{Name: to.Ptr(name)})
	}
	return capabilities
}

func cosmosConsistencyFromProps(props cosmosDatabaseAccountProps) *armcosmos.ConsistencyPolicy {
	if props.ConsistencyPolicy == nil {
		return nil
	}
	cp := &armcosmos.ConsistencyPolicy{}
	if props.ConsistencyPolicy.DefaultConsistencyLevel != "" {
		cp.DefaultConsistencyLevel = to.Ptr(armcosmos.DefaultConsistencyLevel(props.ConsistencyPolicy.DefaultConsistencyLevel))
	}
	// maxStalenessPrefix / maxIntervalInSeconds are only legal for BoundedStaleness;
	// ARM rejects the request outright when they accompany any other level.
	if props.ConsistencyPolicy.DefaultConsistencyLevel == string(armcosmos.DefaultConsistencyLevelBoundedStaleness) {
		if props.ConsistencyPolicy.MaxStalenessPrefix != nil {
			cp.MaxStalenessPrefix = props.ConsistencyPolicy.MaxStalenessPrefix
		}
		if props.ConsistencyPolicy.MaxIntervalInSeconds != nil {
			cp.MaxIntervalInSeconds = props.ConsistencyPolicy.MaxIntervalInSeconds
		}
	}
	return cp
}

func (c *CosmosDatabaseAccount) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props cosmosDatabaseAccountProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if len(props.GeoLocations) == 0 {
		return nil, fmt.Errorf("at least one geoLocation is required")
	}
	writeRegions := 0
	for _, geo := range props.GeoLocations {
		if geo.FailoverPriority == 0 {
			writeRegions++
		}
	}
	if writeRegions != 1 {
		return nil, fmt.Errorf("exactly one geoLocation must have failoverPriority 0, got %d", writeRegions)
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	kind := props.Kind
	if kind == "" {
		kind = string(armcosmos.DatabaseAccountKindGlobalDocumentDB)
	}

	createProps := &armcosmos.DatabaseAccountCreateUpdateProperties{
		// ARM requires this and rejects anything other than "Standard".
		DatabaseAccountOfferType: to.Ptr("Standard"),
		Locations:                cosmosLocationsFromProps(props),
		Capabilities:             cosmosCapabilitiesFromProps(props),
		ConsistencyPolicy:        cosmosConsistencyFromProps(props),
		EnableAutomaticFailover:  props.EnableAutomaticFailover,
		EnableFreeTier:           props.EnableFreeTier,
		DisableLocalAuth:         props.DisableLocalAuth,
	}
	if props.EnableMultipleWriteLocations != nil {
		createProps.EnableMultipleWriteLocations = props.EnableMultipleWriteLocations
	}
	if props.PublicNetworkAccess != "" {
		createProps.PublicNetworkAccess = to.Ptr(armcosmos.PublicNetworkAccess(props.PublicNetworkAccess))
	}
	if props.MinimalTLSVersion != "" {
		createProps.MinimalTLSVersion = to.Ptr(armcosmos.MinimalTLSVersion(props.MinimalTLSVersion))
	}

	params := armcosmos.DatabaseAccountCreateUpdateParameters{
		Location:   to.Ptr(props.Location),
		Kind:       to.Ptr(armcosmos.DatabaseAccountKind(kind)),
		Properties: createProps,
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := c.api.BeginCreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DocumentDB/databaseAccounts/%s",
		c.config.SubscriptionId, props.ResourceGroupName, name)

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
		propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.DatabaseAccountGetResults, props.ResourceGroupName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (c *CosmosDatabaseAccount) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := cosmosDatabaseAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := c.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.DatabaseAccountGetResults, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeCosmosDatabaseAccount,
		Properties:   string(propsJSON),
	}, nil
}

// Update patches the mutable subset via the dedicated update-parameters type.
// kind, location and enableFreeTier are createOnly in the schema, so they never
// reach here.
func (c *CosmosDatabaseAccount) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := cosmosDatabaseAccountIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props cosmosDatabaseAccountProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	updateProps := &armcosmos.DatabaseAccountUpdateProperties{
		ConsistencyPolicy:       cosmosConsistencyFromProps(props),
		EnableAutomaticFailover: props.EnableAutomaticFailover,
		DisableLocalAuth:        props.DisableLocalAuth,
	}
	// Locations must be echoed back on update: omitting them asks ARM to drop
	// every replica region. Capabilities are createOnly in the schema, but they are
	// echoed for the same reason — the API family must not be dropped mid-update.
	if len(props.GeoLocations) > 0 {
		updateProps.Locations = cosmosLocationsFromProps(props)
	}
	if capabilities := cosmosCapabilitiesFromProps(props); capabilities != nil {
		updateProps.Capabilities = capabilities
	}
	if props.EnableMultipleWriteLocations != nil {
		updateProps.EnableMultipleWriteLocations = props.EnableMultipleWriteLocations
	}
	if props.PublicNetworkAccess != "" {
		updateProps.PublicNetworkAccess = to.Ptr(armcosmos.PublicNetworkAccess(props.PublicNetworkAccess))
	}
	if props.MinimalTLSVersion != "" {
		updateProps.MinimalTLSVersion = to.Ptr(armcosmos.MinimalTLSVersion(props.MinimalTLSVersion))
	}

	params := armcosmos.DatabaseAccountUpdateParameters{Properties: updateProps}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := c.api.BeginUpdate(ctx, rgName, name, params, nil)
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
		propsJSON, err := json.Marshal(c.buildPropertiesFromResult(&result.DatabaseAccountGetResults, rgName))
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

func (c *CosmosDatabaseAccount) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := cosmosDatabaseAccountIDParts(request.NativeID)
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

func (c *CosmosDatabaseAccount) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armcosmos.DatabaseAccountsClientCreateOrUpdateResponse], error) {
				return resumePoller[armcosmos.DatabaseAccountsClientCreateOrUpdateResponse](c.pipeline, token)
			},
			func(_ context.Context, result armcosmos.DatabaseAccountsClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return c.completeFromAccount(&result.DatabaseAccountGetResults)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armcosmos.DatabaseAccountsClientUpdateResponse], error) {
				return resumePoller[armcosmos.DatabaseAccountsClientUpdateResponse](c.pipeline, token)
			},
			func(_ context.Context, result armcosmos.DatabaseAccountsClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return c.completeFromAccount(&result.DatabaseAccountGetResults)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armcosmos.DatabaseAccountsClientDeleteResponse], error) {
				return resumePoller[armcosmos.DatabaseAccountsClientDeleteResponse](c.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (c *CosmosDatabaseAccount) completeFromAccount(acct *armcosmos.DatabaseAccountGetResults) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if acct.ID != nil {
		nativeID = *acct.ID
		if rg, _, err := cosmosDatabaseAccountIDParts(*acct.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(c.buildPropertiesFromResult(acct, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (c *CosmosDatabaseAccount) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := c.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list cosmos database accounts: %w", err)
			}
			for _, acct := range page.Value {
				if acct.ID != nil {
					nativeIDs = append(nativeIDs, *acct.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := c.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list cosmos database accounts: %w", err)
		}
		for _, acct := range page.Value {
			if acct.ID != nil {
				nativeIDs = append(nativeIDs, *acct.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
